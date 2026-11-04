[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("install", "remove", "update-all", "hook", "update-instance", "update-prefix")]
    [string]$Action,

    [Parameter(Position = 1)]
    [AllowEmptyString()]
    [string]$RepositoryUrl,

    [Parameter(Position = 2)]
    [AllowEmptyString()]
    [string]$Prefix,

    [Parameter(Position = 3)]
    [AllowEmptyString()]
    [string]$CandidateRevision,

    [switch]$SetupAutoUpdate,

    [switch]$RemoveAutoUpdate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Team Skills lifecycle utility. Runtime dependencies: Windows PowerShell and Git.
$PrefixWasSupplied = $PSBoundParameters.ContainsKey("Prefix")
$ScriptPath = [System.IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$WorkRoot = $null
$CandidateWorktree = $null
$ManagedRepo = $null
$script:TransactionActive = $false
$script:CreatedExposures = @()
$script:InstallRoot = $null
$script:CurrentTarget = $null
$script:GenerationPath = $null
$script:OwnershipSnapshot = $null
$script:HadPreviousGeneration = $false
$script:PreviousGenerationTarget = $null
$script:PreviousRepoHead = $null
$script:UpdateDiagnostics = [System.Collections.Generic.List[string]]::new()
$script:HookStages = @()
$script:HookChangesCommitted = $false
$script:RemovalActive = $false
$script:RemovedExposures = @()
$script:RemovalStagedPath = $null
$script:RemovalOriginalPath = $null
$script:RemovalOriginRemoved = $false
$script:RemovalOriginIndex = $null
$script:RemovalInstanceKey = $null
$script:RemovalLockRoot = $null
$script:RemovalLockContent = $null
$script:UpdateOutcome = "skipped"
$script:UpdatePrevious = $null
$script:UpdateCandidate = $null

function Fail([string]$Message) {
    throw [System.InvalidOperationException]::new($Message)
}

function Get-Sha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-PortableName([string]$Value, [int]$Maximum = 64) {
    return $Value.Length -le $Maximum -and $Value -cmatch '^[a-z0-9]+(?:-[a-z0-9]+)*$'
}

function Test-ConfiguredOriginIdentity([string]$Repository, [string]$InstanceKey) {
    try {
        $origin = Get-GitValue @('-C', $Repository, 'remote', 'get-url', 'origin') "managed clone has no configured origin"
        if ([string]::IsNullOrEmpty($origin)) { return $false }
        $digest = Get-Sha256 $origin
        $suffix = '-' + $digest
        if (-not $InstanceKey.EndsWith($suffix, [System.StringComparison]::Ordinal)) {
            return $false
        }
        $catalogId = $InstanceKey.Substring(0, $InstanceKey.Length - $suffix.Length)
        return Test-InstanceKey $catalogId
    }
    catch { return $false }
}

function Get-FullSafeRoot([string]$Value, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Fail "$Label must not be blank"
    }
    if ($Value -match '[\x00-\x1f]') {
        Fail "$Label must not contain control characters"
    }
    if (-not [System.IO.Path]::IsPathRooted($Value)) {
        Fail "$Label must be an absolute path"
    }
    $full = [System.IO.Path]::GetFullPath($Value)
    $pathRoot = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\', '/') -eq $pathRoot.TrimEnd('\', '/')) {
        Fail "$Label must not be a filesystem root"
    }
    $normalized = $full.TrimEnd('\', '/')
    if ([System.IO.File]::Exists($normalized) -or [System.IO.Directory]::Exists($normalized)) {
        $item = Get-Item -Force -LiteralPath $normalized
        if ([bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Fail "$Label must not be a reparse point"
        }
    }
    return $normalized
}

function Test-PathEntry([string]$Path) {
    try {
        $null = Get-Item -Force -LiteralPath $Path
        return $true
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        return $false
    }
}

function Test-ReparsePoint([System.IO.FileSystemInfo]$Item) {
    return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Assert-OwnedDirectory([string]$Path, [string]$Label) {
    if (-not (Test-PathEntry $Path)) { return }
    $item = Get-Item -Force -LiteralPath $Path
    if (-not ($item -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $item)) {
        Fail "$Label is not an owned directory"
    }
}

function Assert-InstanceLayout([string]$InstanceRoot) {
    Assert-OwnedDirectory $InstanceRoot "catalog instance state"
    $repo = Join-Path $InstanceRoot "repo"
    Assert-OwnedDirectory $repo "managed catalog clone"
    $gitDirectory = Join-Path $repo ".git"
    if (-not (Test-PathEntry $gitDirectory)) { Fail "managed catalog clone metadata is invalid" }
    $gitItem = Get-Item -Force -LiteralPath $gitDirectory
    if (-not ($gitItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $gitItem)) {
        Fail "managed catalog clone metadata is invalid"
    }
    Assert-OwnedDirectory (Join-Path $InstanceRoot "installs") "catalog installation state"
}

function Invoke-Git([string[]]$Arguments, [ref]$Output) {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = @(& git @Arguments 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    $Output.Value = ($lines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    return $code
}

function Get-GitValue([string[]]$Arguments, [string]$FailureMessage) {
    $captured = ""
    if ((Invoke-Git $Arguments ([ref]$captured)) -ne 0) {
        Fail $FailureMessage
    }
    return $captured.Trim()
}

function Read-Utf8Text([string]$Path) {
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    return [System.IO.File]::ReadAllText($Path, $encoding)
}

function Test-SafeJsonText([string]$Text) {
    if ($Text.Length -gt 1048576) { return $false }
    $stack = [System.Collections.ArrayList]::new()
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($character -ceq '"') {
            $start = $index
            $closed = $false
            for ($index++; $index -lt $Text.Length; $index++) {
                if ($Text[$index] -ceq '\') {
                    $index++
                    continue
                }
                if ($Text[$index] -ceq '"') {
                    $closed = $true
                    break
                }
            }
            if (-not $closed) { return $false }
            $after = $index + 1
            while ($after -lt $Text.Length -and $Text[$after] -match '[\x20\x09\x0a\x0d]') { $after++ }
            if ($after -lt $Text.Length -and $Text[$after] -ceq ':') {
                if ($stack.Count -eq 0 -or $stack[$stack.Count - 1].Kind -cne 'object') {
                    return $false
                }
                $raw = $Text.Substring($start, $index - $start + 1)
                try { $decoded = ConvertFrom-Json -InputObject $raw }
                catch { return $false }
                if ($decoded -isnot [string]) { return $false }
                $context = $stack[$stack.Count - 1]
                if (-not $context.Exact.Add($decoded) -or -not $context.Folded.Add($decoded)) {
                    return $false
                }
            }
            continue
        }
        if ($character -ceq '{' -or $character -ceq '[') {
            if ($stack.Count -ge 64) { return $false }
            if ($character -ceq '{') {
                $context = [PSCustomObject]@{
                    Kind = 'object'
                    Exact = [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::Ordinal
                    )
                    Folded = [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase
                    )
                }
            }
            else {
                $context = [PSCustomObject]@{ Kind = 'array'; Exact = $null; Folded = $null }
            }
            $null = $stack.Add($context)
            continue
        }
        if ($character -ceq '}' -or $character -ceq ']') {
            if ($stack.Count -gt 0) { $stack.RemoveAt($stack.Count - 1) }
        }
    }
    return $true
}

function Get-ExactJsonProperty([object]$Object, [string]$Name) {
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $matches = @($Object.PSObject.Properties | Where-Object { $_.Name -ceq $Name })
    if ($matches.Count -eq 1) { return $matches[0] }
    return $null
}

function Test-ExactJsonShape([object]$Object, [string[]]$Names) {
    if ($Object -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    return ($actual -join "`n") -ceq ($expected -join "`n")
}

function Get-JsonArray([object]$Value) {
    if ($Value -is [System.Array]) { return ,([object[]]$Value) }
    return $null
}

function Test-OwnedLifecycleGroup([object]$Value, [string]$Command) {
    if (-not (Test-ExactJsonShape $Value @('matcher', 'hooks'))) { return $false }
    $matcher = Get-ExactJsonProperty $Value 'matcher'
    $handlers = Get-ExactJsonProperty $Value 'hooks'
    if ($matcher.Value -isnot [string] -or $matcher.Value -cne 'startup|clear') { return $false }
    $handlerArray = Get-JsonArray $handlers.Value
    if ($null -eq $handlerArray -or $handlerArray.Count -ne 1) { return $false }
    $handler = $handlerArray[0]
    if (-not (Test-ExactJsonShape $handler @('type', 'command', 'async'))) { return $false }
    $type = Get-ExactJsonProperty $handler 'type'
    $commandProperty = Get-ExactJsonProperty $handler 'command'
    $async = Get-ExactJsonProperty $handler 'async'
    return $type.Value -is [string] -and $type.Value -ceq 'command' -and
        $commandProperty.Value -is [string] -and $commandProperty.Value -ceq $Command -and
        $async.Value -is [bool] -and $async.Value
}

function Test-OwnedCursorHook([object]$Value, [string]$Command) {
    if (-not (Test-ExactJsonShape $Value @('command'))) { return $false }
    $commandProperty = Get-ExactJsonProperty $Value 'command'
    return $commandProperty.Value -is [string] -and $commandProperty.Value -ceq $Command
}

function Test-CodexHookRoot([object]$Root) {
    foreach ($property in $Root.PSObject.Properties) {
        if ($property.Name -cne 'description' -and $property.Name -cne 'hooks') {
            return $false
        }
    }
    $description = Get-ExactJsonProperty $Root 'description'
    if ($null -ne $description -and $description.Value -isnot [string]) { return $false }
    $hooks = Get-ExactJsonProperty $Root 'hooks'
    if ($null -ne $hooks -and
            $hooks.Value -isnot [System.Management.Automation.PSCustomObject]) {
        return $false
    }
    return $true
}

function Edit-HookJson(
    [string]$Text,
    [string]$Operation,
    [string]$Product,
    [string]$Command,
    [bool]$RemoveCursorVersion = $false
) {
    if (-not (Test-SafeJsonText $Text)) {
        Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
    }
    try {
        $root = $Text | ConvertFrom-Json
    }
    catch {
        Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
    }
    if ($root -isnot [System.Management.Automation.PSCustomObject]) {
        Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
    }
    if ($Product -ceq 'codex' -and -not (Test-CodexHookRoot $root)) {
        Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
    }

    $hooksProperty = Get-ExactJsonProperty $root 'hooks'
    if ($null -eq $hooksProperty) {
        if ($Operation -ceq 'remove') {
            Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
        }
        $hooksValue = [PSCustomObject][ordered]@{}
        Add-Member -InputObject $root -MemberType NoteProperty -Name 'hooks' -Value $hooksValue
    }
    else {
        $hooksValue = $hooksProperty.Value
        if ($hooksValue -isnot [System.Management.Automation.PSCustomObject]) {
            Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
        }
    }

    if ($Product -ceq 'cursor') {
        $versionProperty = Get-ExactJsonProperty $root 'version'
        if ($null -eq $versionProperty) {
            if ($Operation -ceq 'add') {
                Add-Member -InputObject $root -MemberType NoteProperty -Name 'version' -Value 1
            }
        }
        elseif (($versionProperty.Value -isnot [int] -and $versionProperty.Value -isnot [long]) -or
                $versionProperty.Value -ne 1) {
            Fail "cursor hook configuration is malformed, unsupported, or no longer owned"
        }
        $eventName = 'sessionStart'
    }
    else {
        $eventName = 'SessionStart'
    }

    $eventProperty = Get-ExactJsonProperty $hooksValue $eventName
    if ($null -eq $eventProperty) {
        if ($Operation -ceq 'remove') {
            Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
        }
        Add-Member -InputObject $hooksValue -MemberType NoteProperty -Name $eventName -Value @()
        $eventProperty = Get-ExactJsonProperty $hooksValue $eventName
    }
    $event = Get-JsonArray $eventProperty.Value
    if ($null -eq $event) {
        Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
    }

    $matches = @()
    for ($index = 0; $index -lt $event.Count; $index++) {
        $owned = if ($Product -ceq 'cursor') {
            Test-OwnedCursorHook $event[$index] $Command
        } else {
            Test-OwnedLifecycleGroup $event[$index] $Command
        }
        if ($owned) { $matches += $index }
    }

    if ($Operation -ceq 'add') {
        if ($matches.Count -eq 0) {
            $entry = if ($Product -ceq 'cursor') {
                [PSCustomObject][ordered]@{ command = $Command }
            } else {
                [PSCustomObject][ordered]@{
                    matcher = 'startup|clear'
                    hooks = @([PSCustomObject][ordered]@{
                        type = 'command'
                        command = $Command
                        async = $true
                    })
                }
            }
            $eventProperty.Value = @($event) + @($entry)
        }
    }
    elseif ($Operation -ceq 'remove') {
        if ($matches.Count -ne 1) {
            Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
        }
        $remaining = @()
        for ($index = 0; $index -lt $event.Count; $index++) {
            if ($index -ne $matches[0]) { $remaining += $event[$index] }
        }
        $eventProperty.Value = @($remaining)
        if ($remaining.Count -eq 0) {
            $hooksValue.PSObject.Properties.Remove($eventName)
            if (@($hooksValue.PSObject.Properties).Count -eq 0) {
                $root.PSObject.Properties.Remove('hooks')
            }
        }
        if ($Product -ceq 'cursor' -and $RemoveCursorVersion) {
            $versionProperty = Get-ExactJsonProperty $root 'version'
            if ($null -eq $versionProperty -or
                    (($versionProperty.Value -isnot [int] -and $versionProperty.Value -isnot [long]) -or
                    $versionProperty.Value -ne 1)) {
                Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
            }
            $root.PSObject.Properties.Remove('version')
        }
    }
    else {
        Fail "unsupported hook edit operation"
    }
    return ($root | ConvertTo-Json -Depth 100) + [Environment]::NewLine
}

function Get-HookConfigPath([string]$Product) {
    switch ($Product) {
        'claude' { return $ClaudeHooksFile }
        'codex' { return $CodexHooksFile }
        'cursor' { return $CursorHooksFile }
        default { Fail "unsupported hook product" }
    }
}

function Get-HookCommand([string]$RuntimePath, [string]$InstanceKey) {
    $escapedRuntime = $RuntimePath.Replace("'", "''")
    $escapedKey = $InstanceKey.Replace("'", "''")
    $payload = "& '$escapedRuntime' hook '$escapedKey'"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payload))
    return 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
}

function Test-FileBytesEqual([string]$First, [string]$Second) {
    try {
        $left = [System.IO.File]::ReadAllBytes($First)
        $right = [System.IO.File]::ReadAllBytes($Second)
    }
    catch { return $false }
    if ($left.Length -ne $right.Length) { return $false }
    for ($index = 0; $index -lt $left.Length; $index++) {
        if ($left[$index] -ne $right[$index]) { return $false }
    }
    return $true
}

function Set-FileAccessSddl([string]$Path, [string]$Sddl) {
    $sections = [System.Security.AccessControl.AccessControlSections]::Access
    $accessControl = [System.Security.AccessControl.FileSecurity]::new()
    $accessControl.SetSecurityDescriptorSddlForm($Sddl, $sections)
    [System.IO.File]::SetAccessControl($Path, $accessControl)
}

function Prepare-HookEdit(
    [string]$Operation,
    [string]$Product,
    [string]$ConfigPath,
    [string]$Command,
    [bool]$RemoveCursorVersion = $false
) {
    $stageRoot = Join-Path (Join-Path $WorkRoot 'hooks') $Product
    $null = New-Item -ItemType Directory -Force -Path $stageRoot
    $beforePath = Join-Path $stageRoot 'before.json'
    $afterPath = Join-Path $stageRoot 'after.json'
    $existed = Test-PathEntry $ConfigPath
    $accessControlSddl = $null
    if ($existed) {
        $item = Get-Item -Force -LiteralPath $ConfigPath
        if (-not ($item -is [System.IO.FileInfo]) -or (Test-ReparsePoint $item)) {
            Fail "$Product hook configuration is not a regular file"
        }
        try {
            $accessControl = [System.IO.File]::GetAccessControl(
                $ConfigPath,
                [System.Security.AccessControl.AccessControlSections]::Access
            )
            $accessControlSddl = $accessControl.GetSecurityDescriptorSddlForm(
                [System.Security.AccessControl.AccessControlSections]::Access
            )
        }
        catch { Fail "cannot preserve $Product hook configuration access protection" }
        if ($item.Length -gt 1048576) {
            Fail "$Product hook configuration is malformed, unsupported, or no longer owned"
        }
        [System.IO.File]::WriteAllBytes($beforePath, [System.IO.File]::ReadAllBytes($ConfigPath))
        try { $beforeText = Read-Utf8Text $beforePath }
        catch { Fail "$Product hook configuration is malformed, unsupported, or no longer owned" }
    }
    else {
        $beforeText = '{}' + [Environment]::NewLine
        [System.IO.File]::WriteAllText($beforePath, $beforeText, [System.Text.UTF8Encoding]::new($false))
    }
    $afterText = Edit-HookJson $beforeText $Operation $Product $Command $RemoveCursorVersion
    $cursorVersionCreated = $false
    if ($Operation -ceq 'add' -and $Product -ceq 'cursor') {
        $beforeRoot = $beforeText | ConvertFrom-Json
        $cursorVersionCreated = $null -eq (Get-ExactJsonProperty $beforeRoot 'version')
    }
    [System.IO.File]::WriteAllText($afterPath, $afterText, [System.Text.UTF8Encoding]::new($false))
    $script:HookStages += [PSCustomObject]@{
        Product = $Product
        ConfigPath = $ConfigPath
        BeforePath = $beforePath
        AfterPath = $afterPath
        Existed = $existed
        AccessControlSddl = $accessControlSddl
        ConfigCreated = ($Operation -ceq 'add' -and -not $existed)
        CursorVersionCreated = $cursorVersionCreated
        Deleted = $false
        Committed = $false
    }
}

function Get-InheritedHookFlags([string]$Product, [string]$ConfigPath) {
    $configCreated = $false
    $cursorVersionCreated = $false
    $catalogRoot = Join-Path $StateRoot 'catalogs'
    if (Test-PathEntry $catalogRoot) {
        foreach ($catalog in @(Get-ChildItem -Force -Directory -LiteralPath $catalogRoot)) {
            $ownerPath = Join-Path (Join-Path $catalog.FullName 'hooks') ($Product + '.owner')
            if (-not (Test-PathEntry $ownerPath)) { continue }
            $ownerItem = Get-Item -Force -LiteralPath $ownerPath
            if (-not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem)) { continue }
            $ownerLines = [System.IO.File]::ReadAllLines($ownerPath)
            if ($ownerLines.Count -lt 2 -or $ownerLines[0] -cne $ConfigPath) { continue }
            $flags = if ($ownerLines.Count -ge 3) { $ownerLines[2] } else { '' }
            if ($flags -in @('created', 'config-created', 'config-created,cursor-version-created')) {
                $configCreated = $true
            }
            if ($flags -in @('cursor-version-created', 'config-created,cursor-version-created')) {
                $cursorVersionCreated = $true
            }
        }
    }
    return [PSCustomObject]@{
        ConfigCreated = $configCreated
        CursorVersionCreated = $cursorVersionCreated
    }
}

function Test-OtherHookOwner([string]$Product, [string]$ConfigPath, [string]$CurrentOwner) {
    $catalogRoot = Join-Path $StateRoot 'catalogs'
    if (-not (Test-PathEntry $catalogRoot)) { return $false }
    foreach ($catalog in @(Get-ChildItem -Force -Directory -LiteralPath $catalogRoot)) {
        $ownerPath = Join-Path (Join-Path $catalog.FullName 'hooks') ($Product + '.owner')
        if ($ownerPath -ceq $CurrentOwner -or -not (Test-PathEntry $ownerPath)) { continue }
        $ownerItem = Get-Item -Force -LiteralPath $ownerPath
        if (-not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem)) { continue }
        $ownerLines = [System.IO.File]::ReadAllLines($ownerPath)
        if ($ownerLines.Count -ge 2 -and $ownerLines[0] -ceq $ConfigPath) { return $true }
    }
    return $false
}

function Test-RemovableCreatedHookConfig([string]$Path, [string]$Product) {
    try { $root = (Read-Utf8Text $Path) | ConvertFrom-Json }
    catch { return $false }
    if ($root -isnot [System.Management.Automation.PSCustomObject]) { return $false }
    $properties = @($root.PSObject.Properties)
    if ($properties.Count -eq 0) { return $true }
    if ($Product -cne 'cursor' -or $properties.Count -ne 1 -or $properties[0].Name -cne 'version') {
        return $false
    }
    return ($properties[0].Value -is [int] -or $properties[0].Value -is [long]) -and
        $properties[0].Value -eq 1
}

function Test-AutoUpdateEnabled([string]$InstanceRoot) {
    foreach ($product in @('claude', 'codex', 'cursor')) {
        if (Test-PathEntry (Join-Path (Join-Path $InstanceRoot 'hooks') ($product + '.owner'))) {
            return $true
        }
    }
    return $false
}

function Prepare-HookRegistration([string]$SourceRoot, [string]$InstanceRoot, [string]$InstanceKey) {
    $sourceRuntime = Join-Path (Join-Path $SourceRoot 'scripts') 'team-skills.ps1'
    $managedRuntime = Join-Path (Join-Path (Join-Path $InstanceRoot 'repo') 'scripts') 'team-skills.ps1'
    if (-not (Test-PathEntry $sourceRuntime)) { Fail "catalog is missing its PowerShell lifecycle utility" }
    $script:HookCommand = Get-HookCommand $managedRuntime $InstanceKey
    $script:HookOwnershipRoot = Join-Path $InstanceRoot 'hooks'
    foreach ($product in @('claude', 'codex', 'cursor')) {
        $configPath = Get-HookConfigPath $product
        $ownerPath = Join-Path $script:HookOwnershipRoot ($product + '.owner')
        if (Test-PathEntry $ownerPath) {
            $ownerItem = Get-Item -Force -LiteralPath $ownerPath
            if (-not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem)) {
                Fail "$product hook ownership state is invalid"
            }
            $ownerLines = [System.IO.File]::ReadAllLines($ownerPath)
            if ($ownerLines.Count -lt 2 -or $ownerLines.Count -gt 3 -or
                    $ownerLines[0] -cne $configPath -or
                    $ownerLines[1] -cne $script:HookCommand) {
                Fail "$product hook ownership path or command changed"
            }
            if ($ownerLines.Count -eq 3 -and $ownerLines[2] -notin @(
                    'created', 'config-created', 'cursor-version-created',
                    'config-created,cursor-version-created')) {
                Fail "$product hook ownership state is invalid"
            }
        }
        Prepare-HookEdit 'add' $product $configPath $script:HookCommand
        $inherited = Get-InheritedHookFlags $product $configPath
        $stage = $script:HookStages[-1]
        if ($inherited.ConfigCreated) { $stage.ConfigCreated = $true }
        if ($inherited.CursorVersionCreated) { $stage.CursorVersionCreated = $true }
    }
}

function Prepare-HookRemoval([string]$InstanceRoot, [string]$InstanceKey) {
    $script:HookOwnershipRoot = Join-Path $InstanceRoot 'hooks'
    if (-not (Test-PathEntry $script:HookOwnershipRoot)) { return }
    $ownershipItem = Get-Item -Force -LiteralPath $script:HookOwnershipRoot
    if (-not ($ownershipItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $ownershipItem)) {
        Fail "catalog hook ownership root is invalid"
    }
    $expectedCommand = Get-HookCommand (Join-Path (Join-Path (Join-Path $InstanceRoot 'repo') 'scripts') 'team-skills.ps1') $InstanceKey
    foreach ($product in @('claude', 'codex', 'cursor')) {
        $ownerPath = Join-Path $script:HookOwnershipRoot ($product + '.owner')
        if (-not (Test-PathEntry $ownerPath)) { continue }
        $ownerItem = Get-Item -Force -LiteralPath $ownerPath
        if (-not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem)) {
            Fail "$product hook ownership state is invalid"
        }
        $ownerLines = [System.IO.File]::ReadAllLines($ownerPath)
        if ($ownerLines.Count -lt 2 -or $ownerLines.Count -gt 3 -or
                $ownerLines[1] -cne $expectedCommand) {
            Fail "$product hook ownership command no longer matches its target"
        }
        $flags = if ($ownerLines.Count -eq 3) { $ownerLines[2] } else { '' }
        if ($flags -notin @('', 'created', 'config-created', 'cursor-version-created',
                'config-created,cursor-version-created')) {
            Fail "$product hook ownership state is invalid"
        }
        $configPath = Get-FullSafeRoot $ownerLines[0] "$product owned hook configuration path"
        $configCreated = $flags -in @('created', 'config-created', 'config-created,cursor-version-created')
        $cursorVersionCreated = $flags -in @('cursor-version-created', 'config-created,cursor-version-created')
        $removeCursorVersion = $cursorVersionCreated -and
            -not (Test-OtherHookOwner $product $configPath $ownerPath)
        Prepare-HookEdit 'remove' $product $configPath $ownerLines[1] $removeCursorVersion
        $stage = $script:HookStages[-1]
        $stage.ConfigCreated = $configCreated
        $stage.CursorVersionCreated = $cursorVersionCreated
    }
}

function Rollback-HookChanges {
    if (-not $script:HookChangesCommitted) { return $true }
    $rollbackSucceeded = $true
    foreach ($stage in $script:HookStages) {
        if (-not $stage.Committed) { continue }
        if ($stage.Deleted -and -not (Test-PathEntry $stage.ConfigPath)) {
            try {
                $parent = [System.IO.Path]::GetDirectoryName($stage.ConfigPath)
                $temporary = Join-Path $parent ('.team-skills-rollback.' + [guid]::NewGuid().ToString('N'))
                [System.IO.File]::WriteAllBytes($temporary, [System.IO.File]::ReadAllBytes($stage.BeforePath))
                Set-FileAccessSddl $temporary $stage.AccessControlSddl
                Move-Item -Force -LiteralPath $temporary -Destination $stage.ConfigPath
                Set-FileAccessSddl $stage.ConfigPath $stage.AccessControlSddl
            }
            catch { $rollbackSucceeded = $false }
        }
        elseif ((Test-PathEntry $stage.ConfigPath) -and
                (Test-FileBytesEqual $stage.ConfigPath $stage.AfterPath)) {
            try {
                if ($stage.Existed) {
                    $parent = [System.IO.Path]::GetDirectoryName($stage.ConfigPath)
                    $temporary = Join-Path $parent ('.team-skills-rollback.' + [guid]::NewGuid().ToString('N'))
                    [System.IO.File]::WriteAllBytes($temporary, [System.IO.File]::ReadAllBytes($stage.BeforePath))
                    Set-FileAccessSddl $temporary $stage.AccessControlSddl
                    Move-Item -Force -LiteralPath $temporary -Destination $stage.ConfigPath
                    Set-FileAccessSddl $stage.ConfigPath $stage.AccessControlSddl
                }
                else {
                    Remove-Item -Force -LiteralPath $stage.ConfigPath
                }
            }
            catch { $rollbackSucceeded = $false }
        }
        else {
            $rollbackSucceeded = $false
        }
    }
    $script:HookChangesCommitted = $false
    return $rollbackSucceeded
}

function Commit-HookChanges {
    if ($script:HookStages.Count -eq 0) { return }
    $script:HookChangesCommitted = $true
    foreach ($stage in $script:HookStages) {
        if ($stage.Existed) {
            if (-not (Test-PathEntry $stage.ConfigPath) -or
                    -not (Test-FileBytesEqual $stage.ConfigPath $stage.BeforePath)) {
                $null = Rollback-HookChanges
                Fail "$($stage.Product) hook configuration changed during installation"
            }
        }
        elseif (Test-PathEntry $stage.ConfigPath) {
            $null = Rollback-HookChanges
            Fail "$($stage.Product) hook configuration appeared during installation"
        }
        $parent = [System.IO.Path]::GetDirectoryName($stage.ConfigPath)
        $null = New-Item -ItemType Directory -Force -Path $parent
        if (($Action -ceq 'remove' -or $RemoveAutoUpdate) -and $stage.ConfigCreated -and
                (Test-RemovableCreatedHookConfig $stage.AfterPath $stage.Product)) {
            try {
                Remove-Item -Force -LiteralPath $stage.ConfigPath
                $stage.Deleted = $true
                $stage.Committed = $true
                continue
            }
            catch {
                $null = Rollback-HookChanges
                Fail "cannot remove Team Skills-created $($stage.Product) hook configuration"
            }
        }
        $temporary = Join-Path $parent ('.team-skills-hooks.' + [guid]::NewGuid().ToString('N'))
        try {
            [System.IO.File]::WriteAllBytes($temporary, [System.IO.File]::ReadAllBytes($stage.AfterPath))
            if ($stage.Existed) {
                Set-FileAccessSddl $temporary $stage.AccessControlSddl
                Move-Item -Force -LiteralPath $temporary -Destination $stage.ConfigPath
                # Move-Item can re-inherit the parent DACL while replacing a file.
                # Mark the byte replacement committed before restoring the captured
                # DACL so an access-control failure participates in rollback.
                $stage.Committed = $true
                Set-FileAccessSddl $stage.ConfigPath $stage.AccessControlSddl
            }
            else {
                Move-Item -LiteralPath $temporary -Destination $stage.ConfigPath
                $stage.Committed = $true
            }
        }
        catch {
            if (Test-PathEntry $temporary) { Remove-Item -Force -LiteralPath $temporary -ErrorAction SilentlyContinue }
            $null = Rollback-HookChanges
            Fail "cannot atomically update $($stage.Product) hook configuration"
        }
    }
}

function Finalize-HookOwnership([bool]$Removing) {
    if ($script:HookStages.Count -eq 0) { return }
    if ($Removing) {
        Remove-Item -Recurse -Force -LiteralPath $script:HookOwnershipRoot
        $script:HookChangesCommitted = $false
        return
    }
    if (Test-PathEntry $script:HookOwnershipRoot) {
        $item = Get-Item -Force -LiteralPath $script:HookOwnershipRoot
        if (-not ($item -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $item)) {
            Fail "catalog hook ownership root is invalid"
        }
    }
    else {
        $null = New-Item -ItemType Directory -Path $script:HookOwnershipRoot
    }
    foreach ($product in @('claude', 'codex', 'cursor')) {
        $ownerPath = Join-Path $script:HookOwnershipRoot ($product + '.owner')
        $temporary = Join-Path $script:HookOwnershipRoot ('.' + $product + '.owner.' + [guid]::NewGuid().ToString('N'))
        $stage = @($script:HookStages | Where-Object { $_.Product -ceq $product })[-1]
        $flags = if ($stage.ConfigCreated -and $stage.CursorVersionCreated) {
            'config-created,cursor-version-created'
        }
        elseif ($stage.ConfigCreated) { 'config-created' }
        elseif ($stage.CursorVersionCreated) { 'cursor-version-created' }
        else { '' }
        $text = (Get-HookConfigPath $product) + [Environment]::NewLine +
            $script:HookCommand + [Environment]::NewLine
        if ($flags.Length -gt 0) { $text += $flags + [Environment]::NewLine }
        [System.IO.File]::WriteAllText($temporary, $text, [System.Text.UTF8Encoding]::new($false))
        Move-Item -Force -LiteralPath $temporary -Destination $ownerPath
    }
    $script:HookChangesCommitted = $false
}

function Test-Skill([string]$SkillDirectory, [string]$ExpectedName) {
    $skillFile = Join-Path $SkillDirectory "SKILL.md"
    if (-not (Test-PathEntry $skillFile)) { return $false }
    $item = Get-Item -Force -LiteralPath $skillFile
    if (-not ($item -is [System.IO.FileInfo]) -or (Test-ReparsePoint $item)) { return $false }
    try {
        $text = Read-Utf8Text $skillFile
    }
    catch { return $false }
    $lines = [System.Text.RegularExpressions.Regex]::Split($text, "\r?\n")
    if ($lines.Count -eq 0 -or $lines[0] -cne "---") { return $false }
    $closed = $false
    $names = @()
    for ($index = 1; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -ceq "---") {
            $closed = $true
            break
        }
        if ($lines[$index] -cmatch '^name:[ \t]*(.*)$') {
            $names += $Matches[1]
        }
    }
    return $closed -and $names.Count -eq 1 -and $names[0] -ceq $ExpectedName
}

function Test-CatalogRuntime([string]$CatalogRoot) {
    $scriptsRoot = Join-Path $CatalogRoot 'scripts'
    if (-not (Test-PathEntry $scriptsRoot)) { return $false }
    $scriptsItem = Get-Item -Force -LiteralPath $scriptsRoot
    if (-not ($scriptsItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $scriptsItem)) {
        return $false
    }
    foreach ($name in @('team-skills.sh', 'team-skills-json.awk', 'team-skills.ps1')) {
        $path = Join-Path $scriptsRoot $name
        if (-not (Test-PathEntry $path)) { return $false }
        $item = Get-Item -Force -LiteralPath $path
        if (-not ($item -is [System.IO.FileInfo]) -or (Test-ReparsePoint $item)) { return $false }
    }
    try {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $scriptsRoot 'team-skills.ps1'), [ref]$tokens, [ref]$errors
        ) | Out-Null
        return $errors.Count -eq 0
    }
    catch { return $false }
}

function Read-Catalog([string]$CatalogRoot) {
    if (-not (Test-CatalogRuntime $CatalogRoot)) { return $null }
    $manifestPath = Join-Path $CatalogRoot "catalog.json"
    if (-not (Test-PathEntry $manifestPath)) { return $null }
    $manifestItem = Get-Item -Force -LiteralPath $manifestPath
    if (-not ($manifestItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $manifestItem)) {
        return $null
    }
    try {
        if ($manifestItem.Length -gt 1048576) { return $null }
        $manifestText = Read-Utf8Text $manifestPath
        if (-not (Test-SafeJsonText $manifestText)) { return $null }
        $manifest = $manifestText | ConvertFrom-Json
    }
    catch { return $null }
    if ($null -eq $manifest -or $manifest -isnot [System.Management.Automation.PSCustomObject]) {
        return $null
    }
    $expectedKeys = @('$schema', 'catalog_id', 'default_prefix', 'display_name', 'schema_version', 'skills_directory')
    $actualKeys = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($actualKeys -join "`n") -cne (($expectedKeys | Sort-Object) -join "`n")) { return $null }
    if ($manifest.'$schema' -cne './schemas/catalog.schema.json') { return $null }
    if (($manifest.schema_version -isnot [int] -and $manifest.schema_version -isnot [long]) -or $manifest.schema_version -ne 1) { return $null }
    if ($manifest.skills_directory -cne 'skills') { return $null }
    if ($manifest.catalog_id -isnot [string] -or -not (Test-PortableName $manifest.catalog_id)) { return $null }
    if ($manifest.display_name -isnot [string] -or $manifest.display_name.Length -eq 0 -or $manifest.display_name.Length -gt 128) { return $null }
    if ($manifest.default_prefix -isnot [string]) { return $null }
    if ($manifest.default_prefix.Length -gt 0 -and -not (Test-PortableName $manifest.default_prefix 62)) { return $null }

    $skillsRoot = Join-Path $CatalogRoot "skills"
    if (-not (Test-PathEntry $skillsRoot)) { return $null }
    $skillsRootItem = Get-Item -Force -LiteralPath $skillsRoot
    if (-not ($skillsRootItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $skillsRootItem)) { return $null }
    foreach ($descendant in @(Get-ChildItem -Force -Recurse -LiteralPath $skillsRoot)) {
        if (Test-ReparsePoint $descendant) { return $null }
    }
    $skillDirectories = @(Get-ChildItem -Force -LiteralPath $skillsRoot)
    if ($skillDirectories.Count -eq 0) { return $null }
    foreach ($skillDirectory in $skillDirectories) {
        if (-not ($skillDirectory -is [System.IO.DirectoryInfo])) { return $null }
        if (-not (Test-PortableName $skillDirectory.Name)) { return $null }
        if (-not (Test-Skill $skillDirectory.FullName $skillDirectory.Name)) { return $null }
    }
    return $manifest
}

function New-DirectoryExposure([string]$Path, [string]$Target) {
    if ($env:OS -eq "Windows_NT") {
        $null = New-Item -ItemType Junction -Path $Path -Target $Target
    }
    else {
        $null = New-Item -ItemType SymbolicLink -Path $Path -Target $Target
    }
}

function Remove-DirectoryExposure([string]$Path) {
    $item = Get-Item -Force -LiteralPath $Path
    if (-not ($item -is [System.IO.DirectoryInfo]) -or -not (Test-ReparsePoint $item)) {
        Fail "refusing to remove a path that is not a directory link: $Path"
    }
    # Directory.Delete removes the junction/symlink itself and never traverses its target.
    [System.IO.Directory]::Delete($Path)
}

function Get-LinkTarget([string]$Path) {
    try {
        $item = Get-Item -Force -LiteralPath $Path
    }
    catch { return $null }
    if (-not (Test-ReparsePoint $item)) { return $null }
    $target = $item.Target
    if ($target -is [array]) { $target = $target[0] }
    if ([string]::IsNullOrEmpty([string]$target)) { return $null }
    if (-not [System.IO.Path]::IsPathRooted([string]$target)) {
        $target = Join-Path $item.Parent.FullName ([string]$target)
    }
    return [System.IO.Path]::GetFullPath([string]$target).TrimEnd('\', '/')
}

function Test-OwnedExposure([string]$Path, [string]$ExpectedTarget) {
    $actual = Get-LinkTarget $Path
    if ($null -eq $actual) { return $false }
    $expected = [System.IO.Path]::GetFullPath($ExpectedTarget).TrimEnd('\', '/')
    if ($env:OS -eq "Windows_NT") { return $actual -ieq $expected }
    return $actual -ceq $expected
}

function Test-ExactUtf8File([string]$Path, [string]$ExpectedText) {
    if (-not (Test-PathEntry $Path)) { return $false }
    $item = Get-Item -Force -LiteralPath $Path
    if (-not ($item -is [System.IO.FileInfo]) -or (Test-ReparsePoint $item)) { return $false }
    $actual = [System.IO.File]::ReadAllBytes($Path)
    $expected = [System.Text.UTF8Encoding]::new($false).GetBytes($ExpectedText)
    if ($actual.Length -ne $expected.Length) { return $false }
    for ($index = 0; $index -lt $actual.Length; $index++) {
        if ($actual[$index] -ne $expected[$index]) { return $false }
    }
    return $true
}

function Get-RemovalExposurePlan([string]$InstallRoot) {
    $ownershipRoot = Join-Path $InstallRoot 'ownership'
    foreach ($product in @('agents', 'claude')) {
        $owners = Join-Path $ownershipRoot $product
        foreach ($ownerItem in @(Get-ChildItem -Force -LiteralPath $owners)) {
            if (-not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem) -or
                    -not $ownerItem.Name.EndsWith('.owner', [System.StringComparison]::Ordinal)) {
                Fail "$product skill ownership state is invalid"
            }
            $effectiveName = $ownerItem.Name.Substring(0, $ownerItem.Name.Length - '.owner'.Length)
            if (-not (Test-PortableName $effectiveName)) {
                Fail "$product skill ownership state is invalid"
            }
            $expectedTarget = Join-Path (Join-Path $InstallRoot 'current') $effectiveName
            if (-not (Test-ExactUtf8File $ownerItem.FullName ($expectedTarget + [Environment]::NewLine))) {
                Fail "$product skill ownership state is invalid"
            }
            $productRoot = if ($product -ceq 'agents') { $AgentsRoot } else { $ClaudeRoot }
            [PSCustomObject]@{
                Product = $product
                Name = $effectiveName
                Path = Join-Path $productRoot $effectiveName
                ExpectedTarget = $expectedTarget
            }
        }
    }
}

function Activate-Generation([string]$InstallRoot, [string]$GenerationPath) {
    $current = Join-Path $InstallRoot "current"
    $next = Join-Path $InstallRoot (".current." + [guid]::NewGuid().ToString("N"))
    $previous = Join-Path $InstallRoot (".previous." + [guid]::NewGuid().ToString("N"))
    New-DirectoryExposure $next $GenerationPath
    if (-not (Test-PathEntry $current)) {
        Move-Item -LiteralPath $next -Destination $current
        return
    }
    if ($null -eq (Get-LinkTarget $current)) {
        Remove-DirectoryExposure $next
        Fail "catalog current view is not an owned directory link"
    }
    Move-Item -LiteralPath $current -Destination $previous
    try {
        Move-Item -LiteralPath $next -Destination $current
    }
    catch {
        Move-Item -LiteralPath $previous -Destination $current
        if (Test-PathEntry $next) { Remove-DirectoryExposure $next }
        throw
    }
    Remove-DirectoryExposure $previous
}

function Test-InstanceKey([string]$Value) {
    return -not [string]::IsNullOrEmpty($Value) -and $Value -cmatch '^[a-z0-9-]+$'
}

function Write-UpdateDiagnostic([string]$Message) {
    if ($script:UpdateDiagnostics.Count -lt 256) {
        $script:UpdateDiagnostics.Add($Message)
    }
    if ($env:TEAM_SKILLS_INTERNAL_HOOK_LOG -cne "1") {
        [Console]::Error.WriteLine($Message)
    }
}

function Get-UpdateTimingValue([string]$Name, [long]$DefaultValue) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrEmpty($value)) { return $DefaultValue }
    $parsed = 0L
    if ($value -cnotmatch '^[0-9]+$' -or
            -not [long]::TryParse($value, [ref]$parsed)) {
        Fail "update timing override is invalid"
    }
    return $parsed
}

function Test-ProcessActive([int]$ProcessId) {
    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Enter-CatalogUpdateLock([string]$InstanceRoot, [long]$Now, [long]$StaleSeconds) {
    $lockRoot = Join-Path $InstanceRoot "update.lock"
    try {
        $null = New-Item -ItemType Directory -Path $lockRoot -ErrorAction Stop
    }
    catch [System.IO.IOException] {
        if (-not (Test-PathEntry $lockRoot)) { return $null }
        $lockItem = Get-Item -Force -LiteralPath $lockRoot
        if (-not ($lockItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $lockItem)) {
            Write-UpdateDiagnostic "warning: unsafe update lock path; skipping catalog"
            return $null
        }
        $lockEntries = @(Get-ChildItem -Force -LiteralPath $lockRoot)
        $ownerPath = Join-Path $lockRoot "owner"
        if ($lockEntries.Count -ne 1 -or $lockEntries[0].Name -cne "owner" -or
                -not ($lockEntries[0] -is [System.IO.FileInfo]) -or
                (Test-ReparsePoint $lockEntries[0])) {
            return $null
        }
        try {
            $ownerLines = [System.IO.File]::ReadAllLines($ownerPath)
        }
        catch { return $null }
        $ownerPid = 0
        $ownerTime = 0L
        if ($ownerLines.Count -ne 2 -or
                -not [int]::TryParse($ownerLines[0], [ref]$ownerPid) -or $ownerPid -le 0 -or
                -not [long]::TryParse($ownerLines[1], [ref]$ownerTime) -or $ownerTime -lt 0) {
            return $null
        }
        if ((Test-ProcessActive $ownerPid) -or $Now -lt $ownerTime -or
                ($Now - $ownerTime) -lt $StaleSeconds) {
            return $null
        }

        $staleLock = Join-Path $InstanceRoot (".stale-lock." + [guid]::NewGuid().ToString("N"))
        try {
            Move-Item -LiteralPath $lockRoot -Destination $staleLock -ErrorAction Stop
            try {
                $null = New-Item -ItemType Directory -Path $lockRoot -ErrorAction Stop
            }
            catch {
                if (-not (Test-PathEntry $lockRoot)) {
                    Move-Item -LiteralPath $staleLock -Destination $lockRoot -ErrorAction SilentlyContinue
                }
                return $null
            }
            try {
                Remove-Item -Recurse -Force -LiteralPath $staleLock -ErrorAction Stop
            }
            catch {
                Remove-Item -Recurse -Force -LiteralPath $lockRoot -ErrorAction SilentlyContinue
                if (-not (Test-PathEntry $lockRoot)) {
                    Move-Item -LiteralPath $staleLock -Destination $lockRoot -ErrorAction SilentlyContinue
                }
                return $null
            }
        }
        catch {
            return $null
        }
    }

    $ownerPath = Join-Path $lockRoot "owner"
    try {
        [System.IO.File]::WriteAllText(
            $ownerPath,
            ([System.Diagnostics.Process]::GetCurrentProcess().Id.ToString() +
                [Environment]::NewLine + $Now.ToString() + [Environment]::NewLine),
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        Remove-Item -Recurse -Force -LiteralPath $lockRoot -ErrorAction SilentlyContinue
        Fail "cannot record update lock ownership"
    }
    return $lockRoot
}

function Test-OwnedUpdateLock([string]$LockRoot, [long]$Now) {
    try {
        $lockItem = Get-Item -Force -LiteralPath $LockRoot
        $ownerItem = Get-Item -Force -LiteralPath (Join-Path $LockRoot "owner")
        if (-not ($lockItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $lockItem) -or
                -not ($ownerItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $ownerItem)) {
            return $false
        }
        $lines = [System.IO.File]::ReadAllLines($ownerItem.FullName)
        return $lines.Count -eq 2 -and
            $lines[0] -ceq ([System.Diagnostics.Process]::GetCurrentProcess().Id.ToString()) -and
            $lines[1] -ceq $Now.ToString()
    }
    catch { return $false }
}

function Enter-RemovalLock([string]$InstanceRoot) {
    $lockRoot = Join-Path $InstanceRoot "update.lock"
    try {
        $null = New-Item -ItemType Directory -Path $lockRoot -ErrorAction Stop
    }
    catch {
        Fail "catalog update is in progress; retry removal after it completes"
    }
    $lockContent = (
        [System.Diagnostics.Process]::GetCurrentProcess().Id.ToString() +
        [Environment]::NewLine + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() +
        [Environment]::NewLine
    )
    try {
        [System.IO.File]::WriteAllText(
            (Join-Path $lockRoot "owner"), $lockContent, [System.Text.UTF8Encoding]::new($false)
        )
    }
    catch {
        Remove-Item -LiteralPath $lockRoot -ErrorAction SilentlyContinue
        Fail "cannot record catalog removal lock ownership"
    }
    $script:RemovalLockRoot = $lockRoot
    $script:RemovalLockContent = $lockContent
}

function Exit-RemovalLock {
    if ($null -eq $script:RemovalLockRoot -or -not (Test-PathEntry $script:RemovalLockRoot)) {
        return
    }
    try {
        $lockItem = Get-Item -Force -LiteralPath $script:RemovalLockRoot
        $entries = @(Get-ChildItem -Force -LiteralPath $script:RemovalLockRoot)
        if (-not ($lockItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $lockItem) -or
                $entries.Count -ne 1 -or $entries[0].Name -cne "owner" -or
                -not ($entries[0] -is [System.IO.FileInfo]) -or (Test-ReparsePoint $entries[0]) -or
                [System.IO.File]::ReadAllText($entries[0].FullName) -cne $script:RemovalLockContent) {
            return
        }
        Remove-Item -Force -LiteralPath $entries[0].FullName -ErrorAction Stop
        Remove-Item -LiteralPath $script:RemovalLockRoot -ErrorAction Stop
        $script:RemovalLockRoot = $null
    }
    catch { }
}

# A session hook honors the throttle. An explicit update-all is a request to update now, so it
# passes $Manual and skips the throttle while keeping every lock and validation rule.
function Invoke-CatalogUpdate([string]$InstanceKey, [bool]$Manual = $false) {
    $script:UpdateOutcome = "skipped"
    if (-not (Test-InstanceKey $InstanceKey)) {
        Write-UpdateDiagnostic "error: invalid catalog instance key"
        return $false
    }
    $catalogsRoot = Join-Path $StateRoot "catalogs"
    try { Assert-OwnedDirectory $catalogsRoot "catalog state root" }
    catch {
        Write-UpdateDiagnostic "error: catalog state root is invalid"
        return $false
    }
    $instanceRoot = Join-Path $catalogsRoot $InstanceKey
    if (-not (Test-PathEntry $instanceRoot)) {
        Write-UpdateDiagnostic "error: catalog instance state is invalid"
        return $false
    }
    $instanceItem = Get-Item -Force -LiteralPath $instanceRoot
    if (-not ($instanceItem -is [System.IO.DirectoryInfo]) -or
            (Test-ReparsePoint $instanceItem) -or
            -not (Test-PathEntry (Join-Path (Join-Path $instanceRoot "repo") ".git"))) {
        Write-UpdateDiagnostic "error: catalog instance state is invalid"
        return $false
    }

    try {
        $now = Get-UpdateTimingValue "TEAM_SKILLS_NOW" ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        $throttle = Get-UpdateTimingValue "TEAM_SKILLS_THROTTLE_SECONDS" 21600
        $staleSeconds = Get-UpdateTimingValue "TEAM_SKILLS_STALE_LOCK_SECONDS" 3600
        $lockRoot = Enter-CatalogUpdateLock $instanceRoot $now $staleSeconds
    }
    catch {
        Write-UpdateDiagnostic ("error: " + $_.Exception.Message)
        return $false
    }
    if ($null -eq $lockRoot) { return $true }

    try {
        $successStamp = Join-Path $instanceRoot "last-success"
        if (-not $Manual -and (Test-PathEntry $successStamp)) {
            $stampItem = Get-Item -Force -LiteralPath $successStamp
            if ($stampItem -is [System.IO.FileInfo] -and -not (Test-ReparsePoint $stampItem)) {
                $lastSuccess = 0L
                $stampValue = ([System.IO.File]::ReadAllText($successStamp)).Trim()
                if ([long]::TryParse($stampValue, [ref]$lastSuccess) -and
                        $lastSuccess -ge 0 -and $now -ge $lastSuccess -and
                        ($now - $lastSuccess) -lt $throttle) {
                    return $true
                }
            }
        }

        $installsRoot = Join-Path $instanceRoot "installs"
        if (-not (Test-PathEntry $installsRoot)) {
            Write-UpdateDiagnostic "error: catalog installation state is invalid"
            return $false
        }
        $installsItem = Get-Item -Force -LiteralPath $installsRoot
        if (-not ($installsItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $installsItem)) {
            Write-UpdateDiagnostic "error: catalog installation state is invalid"
            return $false
        }

        $installedViews = @(Get-ChildItem -Force -LiteralPath $installsRoot | Where-Object {
            $_ -is [System.IO.DirectoryInfo] -and -not (Test-ReparsePoint $_)
        })
        if ($installedViews.Count -eq 0) {
            Write-UpdateDiagnostic "error: catalog installation state is invalid"
            return $false
        }

        $updateFailed = $false
        $powerShellExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $env:GIT_TERMINAL_PROMPT = "0"
        $managedRepo = Join-Path $instanceRoot 'repo'
        try {
            if (-not (Test-ConfiguredOriginIdentity $managedRepo $InstanceKey)) {
                Fail "managed catalog configured origin identity changed; restore it or remove and reinstall"
            }
            $updatePrevious = Get-GitValue @('-C', $managedRepo, 'rev-parse', 'HEAD') "managed catalog clone has no Git revision"
            $captured = ""
            if ((Invoke-Git @('-C', $managedRepo, 'fetch', '--quiet', 'origin', '+HEAD:refs/team-skills/candidate') ([ref]$captured)) -ne 0) {
                Fail "unable to fetch the managed catalog origin"
            }
            $updateCandidate = Get-GitValue @('-C', $managedRepo, 'rev-parse', '--verify', 'refs/team-skills/candidate') "managed origin HEAD has no commit"
            $updateCandidateType = Get-GitValue @('-C', $managedRepo, 'cat-file', '-t', $updateCandidate) "managed origin HEAD has no commit"
            if ($updateCandidateType -cne 'commit') { Fail "managed origin HEAD has no commit" }
            $captured = ""
            if ((Invoke-Git @('-C', $managedRepo, 'merge-base', '--is-ancestor', $updatePrevious, $updateCandidate) ([ref]$captured)) -ne 0) {
                Fail "fetched catalog history is not a fast-forward; keeping the last known-good installation"
            }
        }
        catch {
            Write-UpdateDiagnostic ("error: " + $_.Exception.Message)
            return $false
        }
        foreach ($installedView in $installedViews) {
            $installedKey = $installedView.Name
            if ($installedKey -cne "_default" -and -not (Test-PortableName $installedKey 62)) {
                Write-UpdateDiagnostic "warning: invalid installed prefix state; skipping catalog"
                $updateFailed = $true
                continue
            }
            $savedPreference = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $childOutput = @(& $powerShellExecutable -NoLogo -NoProfile -NonInteractive `
                    -ExecutionPolicy Bypass -File $ScriptPath update-prefix $InstanceKey $installedKey $updateCandidate 2>&1)
                $childExitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $savedPreference
            }
            foreach ($childLine in $childOutput) {
                Write-UpdateDiagnostic ($childLine.ToString())
            }
            if ($childExitCode -ne 0) { $updateFailed = $true }
        }
        if ($updateFailed) { return $false }

        $stampTemp = Join-Path $instanceRoot (".last-success." + [guid]::NewGuid().ToString("N"))
        [System.IO.File]::WriteAllText(
            $stampTemp, $now.ToString() + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -Force -LiteralPath $stampTemp -Destination $successStamp
        $script:UpdatePrevious = $updatePrevious
        $script:UpdateCandidate = $updateCandidate
        $script:UpdateOutcome = if ($updatePrevious -ceq $updateCandidate) { "current" } else { "updated" }
        return $true
    }
    catch {
        Write-UpdateDiagnostic "error: catalog update failed safely"
        return $false
    }
    finally {
        if ((Test-PathEntry $lockRoot) -and (Test-OwnedUpdateLock $lockRoot $now)) {
            Remove-Item -Recurse -Force -LiteralPath $lockRoot -ErrorAction SilentlyContinue
        }
    }
}

function Get-ShortRevision([string]$Revision) {
    return $Revision.Substring(0, [Math]::Min(12, $Revision.Length))
}

function Write-ManualUpdateResult([string]$InstanceKey) {
    $catalogName = $InstanceKey -replace '-[^-]*$', ''
    if ($script:UpdateOutcome -ceq "updated") {
        [Console]::Out.WriteLine("Catalog ${catalogName}: updated $(Get-ShortRevision $script:UpdatePrevious) to $(Get-ShortRevision $script:UpdateCandidate).")
    }
    elseif ($script:UpdateOutcome -ceq "current") {
        [Console]::Out.WriteLine("Catalog ${catalogName}: already current at $(Get-ShortRevision $script:UpdateCandidate).")
    }
    else {
        [Console]::Out.WriteLine("Catalog ${catalogName}: skipped because its update lock is held.")
    }
}

function Write-AtomicBoundedLog([string]$Path, [string]$Text) {
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $bytes = $encoding.GetBytes($Text)
    if ($bytes.Length -gt 65536) {
        $offset = $bytes.Length - 65536
        while ($offset -lt $bytes.Length -and ($bytes[$offset] -band 0xC0) -eq 0x80) {
            $offset++
        }
        $bounded = [byte[]]::new($bytes.Length - $offset)
        [System.Array]::Copy($bytes, $offset, $bounded, 0, $bounded.Length)
        $bytes = $bounded
    }
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    $null = New-Item -ItemType Directory -Force -Path $parent
    $temporary = Join-Path $parent (".last-update." + [guid]::NewGuid().ToString("N"))
    [System.IO.File]::WriteAllBytes($temporary, $bytes)
    Move-Item -Force -LiteralPath $temporary -Destination $Path
}

function Invoke-HookLaunch([string]$InstanceKey) {
    if (-not (Test-InstanceKey $InstanceKey)) { return }
    $instanceRoot = Join-Path (Join-Path $StateRoot "catalogs") $InstanceKey
    if (-not (Test-PathEntry $instanceRoot)) { return }
    $instanceItem = Get-Item -Force -LiteralPath $instanceRoot
    if (-not ($instanceItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $instanceItem)) {
        return
    }
    $logPath = Join-Path $instanceRoot "last-update.log"

    if ($env:TEAM_SKILLS_TEST_FOREGROUND -ceq "1") {
        try {
            $script:UpdateDiagnostics.Clear()
            $null = Invoke-CatalogUpdate $InstanceKey
            $text = ($script:UpdateDiagnostics -join [Environment]::NewLine)
            if ($text.Length -gt 0) { $text += [Environment]::NewLine }
            Write-AtomicBoundedLog $logPath $text
        }
        catch { }
        return
    }

    try {
        $escapedScript = $ScriptPath.Replace("'", "''")
        $escapedKey = $InstanceKey.Replace("'", "''")
        $command = @"
`$env:TEAM_SKILLS_INTERNAL_HOOK_LOG = '1'
& '$escapedScript' update-instance '$escapedKey' *> `$null
"@
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $start.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + $encoded
        $start.UseShellExecute = $true
        $start.CreateNoWindow = $true
        $start.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $process = [System.Diagnostics.Process]::Start($start)
        $process.Dispose()
    }
    catch { }
}

function Invoke-TransactionRollback {
    $removalRollbackFailed = -not (Rollback-Removal)
    $hookRollbackFailed = -not (Rollback-HookChanges)
    if (-not $script:TransactionActive) {
        if ($removalRollbackFailed -or $hookRollbackFailed) {
            [Console]::Error.WriteLine("warning: removal rollback could not fully restore catalog-owned state")
        }
        return
    }
    $script:TransactionActive = $false
    $rollbackFailed = $hookRollbackFailed

    # Remove newly created links while their candidate targets still exist, so junction
    # ownership remains inspectable before the current generation is restored.
    foreach ($created in $script:CreatedExposures) {
        try {
            if (Test-OwnedExposure $created.Path $created.ExpectedTarget) {
                Remove-DirectoryExposure $created.Path
            }
        }
        catch { $rollbackFailed = $true }
    }

    try {
        if ($script:HadPreviousGeneration) {
            Activate-Generation $script:InstallRoot $script:PreviousGenerationTarget
        }
        elseif ((Test-PathEntry $script:CurrentTarget) -and
                (Test-OwnedExposure $script:CurrentTarget $script:GenerationPath)) {
            Remove-DirectoryExposure $script:CurrentTarget
        }
    }
    catch { $rollbackFailed = $true }

    if ($null -ne $script:OwnershipSnapshot -and (Test-PathEntry $script:OwnershipSnapshot)) {
        try {
            $ownershipRoot = Join-Path $script:InstallRoot "ownership"
            if (Test-PathEntry $ownershipRoot) {
                Remove-Item -Recurse -Force -LiteralPath $ownershipRoot
            }
            $null = New-Item -ItemType Directory -Path $ownershipRoot
            foreach ($snapshotItem in @(Get-ChildItem -Force -LiteralPath $script:OwnershipSnapshot)) {
                Copy-Item -Recurse -LiteralPath $snapshotItem.FullName -Destination $ownershipRoot
            }
            foreach ($product in @('agents', 'claude')) {
                $productRoot = if ($product -ceq 'agents') { $AgentsRoot } else { $ClaudeRoot }
                $owners = Join-Path $ownershipRoot $product
                foreach ($ownerFile in @(Get-ChildItem -File -Filter "*.owner" -LiteralPath $owners)) {
                    $effectiveName = $ownerFile.BaseName
                    $destination = Join-Path $productRoot $effectiveName
                    $expectedTarget = ([System.IO.File]::ReadAllText($ownerFile.FullName)).Trim()
                    if (Test-OwnedExposure $destination $expectedTarget) { continue }
                    if (Test-PathEntry $destination) {
                        Remove-Item -Force -LiteralPath $ownerFile.FullName
                        continue
                    }
                    try {
                        New-DirectoryExposure $destination $expectedTarget
                    }
                    catch {
                        Remove-Item -Force -LiteralPath $ownerFile.FullName
                        $rollbackFailed = $true
                    }
                }
            }
        }
        catch { $rollbackFailed = $true }
    }

    if ($null -ne $script:PreviousRepoHead -and $null -ne $ManagedRepo) {
        $captured = ""
        if ((Invoke-Git @('-C', $ManagedRepo, 'reset', '--quiet', '--hard', $script:PreviousRepoHead) ([ref]$captured)) -ne 0) {
            $rollbackFailed = $true
        }
    }
    if ($rollbackFailed) {
        [Console]::Error.WriteLine("warning: installation rollback could not fully restore catalog-owned state")
    }
}

function Rollback-Removal {
    if (-not $script:RemovalActive) { return $true }
    $script:RemovalActive = $false
    $rollbackSucceeded = $true

    if ($null -ne $script:RemovalStagedPath -and $null -ne $script:RemovalOriginalPath -and
            (Test-PathEntry $script:RemovalStagedPath)) {
        if (-not (Test-PathEntry $script:RemovalOriginalPath)) {
            try {
                Move-Item -LiteralPath $script:RemovalStagedPath -Destination $script:RemovalOriginalPath
            }
            catch { $rollbackSucceeded = $false }
        }
        else {
            $rollbackSucceeded = $false
        }
    }

    if ($script:RemovalOriginRemoved -and -not (Test-PathEntry $script:RemovalOriginIndex)) {
        try {
            $parent = [System.IO.Path]::GetDirectoryName($script:RemovalOriginIndex)
            $temporary = Join-Path $parent ('.removal-rollback.' + [guid]::NewGuid().ToString('N'))
            [System.IO.File]::WriteAllText(
                $temporary,
                $script:RemovalInstanceKey + [Environment]::NewLine,
                [System.Text.UTF8Encoding]::new($false)
            )
            Move-Item -LiteralPath $temporary -Destination $script:RemovalOriginIndex
        }
        catch { $rollbackSucceeded = $false }
    }

    foreach ($removed in $script:RemovedExposures) {
        if (Test-OwnedExposure $removed.Path $removed.ExpectedTarget) { continue }
        if ((Test-PathEntry $removed.Path) -or -not (Test-PathEntry $removed.ExpectedTarget)) {
            $rollbackSucceeded = $false
            continue
        }
        try { New-DirectoryExposure $removed.Path $removed.ExpectedTarget }
        catch { $rollbackSucceeded = $false }
    }
    return $rollbackSucceeded
}

try {
    if (($Action -ceq "install" -or $Action -ceq "remove") -and
            [string]::IsNullOrWhiteSpace($RepositoryUrl)) {
        Fail "repository URL must not be blank"
    }
    if ($SetupAutoUpdate -and $RemoveAutoUpdate) {
        Fail "-SetupAutoUpdate and -RemoveAutoUpdate cannot be combined"
    }
    if (($SetupAutoUpdate -or $RemoveAutoUpdate) -and $Action -cne "install") {
        Fail "-SetupAutoUpdate and -RemoveAutoUpdate require the install action"
    }
    if ($RemoveAutoUpdate -and $PrefixWasSupplied) {
        Fail "-RemoveAutoUpdate applies to the whole catalog; omit -Prefix"
    }
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Fail "USERPROFILE must be set"
    }
    $defaultState = if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Join-Path $env:USERPROFILE ".local\share\team-skills"
    } else {
        Join-Path $env:LOCALAPPDATA "team-skills"
    }
    $stateValue = if ($env:TEAM_SKILLS_STATE_ROOT) { $env:TEAM_SKILLS_STATE_ROOT } else { $defaultState }
    $agentsValue = if ($env:TEAM_SKILLS_AGENTS_ROOT) { $env:TEAM_SKILLS_AGENTS_ROOT } else { Join-Path $env:USERPROFILE ".agents\skills" }
    $claudeValue = if ($env:TEAM_SKILLS_CLAUDE_ROOT) { $env:TEAM_SKILLS_CLAUDE_ROOT } else { Join-Path $env:USERPROFILE ".claude\skills" }
    $claudeHooksValue = if ($env:TEAM_SKILLS_CLAUDE_HOOKS_FILE) { $env:TEAM_SKILLS_CLAUDE_HOOKS_FILE } else { Join-Path $env:USERPROFILE ".claude\settings.json" }
    $codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
    $codexHooksValue = if ($env:TEAM_SKILLS_CODEX_HOOKS_FILE) { $env:TEAM_SKILLS_CODEX_HOOKS_FILE } else { Join-Path $codexHome "hooks.json" }
    $cursorHooksValue = if ($env:TEAM_SKILLS_CURSOR_HOOKS_FILE) { $env:TEAM_SKILLS_CURSOR_HOOKS_FILE } else { Join-Path $env:USERPROFILE ".cursor\hooks.json" }
    $StateRoot = Get-FullSafeRoot $stateValue "TEAM_SKILLS_STATE_ROOT"
    $AgentsRoot = Get-FullSafeRoot $agentsValue "TEAM_SKILLS_AGENTS_ROOT"
    $ClaudeRoot = Get-FullSafeRoot $claudeValue "TEAM_SKILLS_CLAUDE_ROOT"
    $ClaudeHooksFile = Get-FullSafeRoot $claudeHooksValue "TEAM_SKILLS_CLAUDE_HOOKS_FILE"
    $CodexHooksFile = Get-FullSafeRoot $codexHooksValue "TEAM_SKILLS_CODEX_HOOKS_FILE"
    $CursorHooksFile = Get-FullSafeRoot $cursorHooksValue "TEAM_SKILLS_CURSOR_HOOKS_FILE"

    if ($Action -ceq "hook") {
        Invoke-HookLaunch $RepositoryUrl
        exit 0
    }
    if ($Action -ceq "update-instance") {
        $script:UpdateDiagnostics.Clear()
        $updated = Invoke-CatalogUpdate $RepositoryUrl
        if ($env:TEAM_SKILLS_INTERNAL_HOOK_LOG -ceq "1" -and
                (Test-InstanceKey $RepositoryUrl)) {
            $hookInstanceRoot = Join-Path (Join-Path $StateRoot "catalogs") $RepositoryUrl
            if (Test-PathEntry $hookInstanceRoot) {
                $hookLogText = ($script:UpdateDiagnostics -join [Environment]::NewLine)
                if ($hookLogText.Length -gt 0) { $hookLogText += [Environment]::NewLine }
                try {
                    Write-AtomicBoundedLog (Join-Path $hookInstanceRoot "last-update.log") $hookLogText
                }
                catch { }
            }
        }
        if ($updated) { exit 0 }
        exit 1
    }
    if ($Action -ceq "update-all") {
        $catalogsRoot = Join-Path $StateRoot "catalogs"
        if (-not (Test-PathEntry $catalogsRoot)) {
            exit 0
        }
        $catalogsItem = Get-Item -Force -LiteralPath $catalogsRoot
        if (-not ($catalogsItem -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $catalogsItem)) {
            [Console]::Error.WriteLine("error: catalog state root is invalid")
            exit 1
        }
        $overallSuccess = $true
        foreach ($catalog in @(Get-ChildItem -Force -LiteralPath $catalogsRoot)) {
            if (-not ($catalog -is [System.IO.DirectoryInfo]) -or (Test-ReparsePoint $catalog)) {
                continue
            }
            if (Invoke-CatalogUpdate $catalog.Name $true) {
                Write-ManualUpdateResult $catalog.Name
            }
            else {
                $overallSuccess = $false
                $failedCatalog = $catalog.Name -replace '-[^-]*$', ''
                [Console]::Error.WriteLine("Catalog ${failedCatalog}: update failed; keeping the last known-good installation.")
            }
        }
        if ($overallSuccess) { exit 0 }
        exit 1
    }
    if ($Action -ceq "update-prefix" -and
            ([string]::IsNullOrWhiteSpace($RepositoryUrl) -or -not $PrefixWasSupplied)) {
        Fail "update-prefix requires a catalog instance and installed prefix key"
    }

    $null = New-Item -ItemType Directory -Force -Path $StateRoot
    Assert-OwnedDirectory (Join-Path $StateRoot "catalogs") "catalog state root"
    Assert-OwnedDirectory (Join-Path $StateRoot "origins") "catalog origin index root"
    $WorkRoot = Join-Path $StateRoot (".operation." + [guid]::NewGuid().ToString("N"))
    $null = New-Item -ItemType Directory -Path $WorkRoot

    $originIndexRoot = Join-Path $StateRoot "origins"
    $existingInstance = $false
    if ($Action -ceq "update-prefix") {
        $instanceKey = $RepositoryUrl
        if (-not (Test-InstanceKey $instanceKey)) { Fail "invalid catalog instance key" }
        $instanceRoot = Join-Path (Join-Path $StateRoot "catalogs") $instanceKey
        Assert-InstanceLayout $instanceRoot
        $ManagedRepo = Join-Path $instanceRoot "repo"
        $manifest = Read-Catalog $ManagedRepo
        if ($null -eq $manifest) {
            Fail "managed catalog clone is invalid; keeping the last known-good installation"
        }
        $configuredOrigin = Get-GitValue @('-C', $ManagedRepo, 'remote', 'get-url', 'origin') "managed clone has no configured origin"
        if ([string]::IsNullOrEmpty($configuredOrigin)) { Fail "managed clone origin must not be blank" }
        if (-not (Test-ConfiguredOriginIdentity $ManagedRepo $instanceKey)) {
            Fail "managed catalog configured origin identity changed; restore it or remove and reinstall"
        }
        $instanceCatalogId = $manifest.catalog_id
        $existingInstance = $true
        $installKey = $Prefix
        if ($installKey -ceq "_default") {
            $Prefix = ""
        }
        elseif (-not (Test-PortableName $installKey 62)) {
            Fail "installed prefix state is invalid"
        }
        $installRoot = Join-Path (Join-Path $instanceRoot "installs") $installKey
        if (-not (Test-PathEntry $installRoot)) { Fail "installed prefix state is missing" }
    }
    else {
        $suppliedDigest = Get-Sha256 $RepositoryUrl
        $originIndex = Join-Path $originIndexRoot ($suppliedDigest + ".instance")
    }
    if ($Action -cne "update-prefix" -and (Test-PathEntry $originIndex)) {
        $indexItem = Get-Item -Force -LiteralPath $originIndex
        if (-not ($indexItem -is [System.IO.FileInfo]) -or (Test-ReparsePoint $indexItem)) {
            Fail "catalog origin index is invalid"
        }
        $instanceKey = ([System.IO.File]::ReadAllText($originIndex)).Trim()
        if ($instanceKey -cnotmatch '^[a-z0-9-]+$') { Fail "catalog origin index is invalid" }
        $instanceRoot = Join-Path (Join-Path $StateRoot "catalogs") $instanceKey
        $ManagedRepo = Join-Path $instanceRoot "repo"
        Assert-InstanceLayout $instanceRoot
        $manifest = Read-Catalog $ManagedRepo
        if ($null -eq $manifest) {
            Fail "managed catalog clone is invalid; keeping the last known-good installation"
        }
        $configuredOrigin = Get-GitValue @('-C', $ManagedRepo, 'remote', 'get-url', 'origin') "managed clone has no configured origin"
        if ([string]::IsNullOrEmpty($configuredOrigin)) { Fail "managed clone origin must not be blank" }
        $instancePrefix = $manifest.catalog_id + '-'
        if (-not $instanceKey.StartsWith($instancePrefix, [System.StringComparison]::Ordinal)) {
            Fail "catalog origin index identity mismatch"
        }
        $instanceDigest = $instanceKey.Substring($instancePrefix.Length)
        if ($instanceDigest -cnotmatch '^[0-9a-f]{64}$') { Fail "catalog origin index identity mismatch" }
        $instanceCatalogId = $manifest.catalog_id
        $existingInstance = $true
        if ($Action -cne 'remove' -and -not $RemoveAutoUpdate -and
                -not (Test-ConfiguredOriginIdentity $ManagedRepo $instanceKey)) {
            Fail "managed catalog configured origin identity changed; restore it or remove and reinstall"
        }
    }
    elseif ($RemoveAutoUpdate) {
        Fail "catalog instance is not installed"
    }
    elseif ($Action -cne "update-prefix") {
        $bootstrapClone = Join-Path $WorkRoot "bootstrap"
        $captured = ""
        if ((Invoke-Git @('clone', '--quiet', '--no-local', '--', $RepositoryUrl, $bootstrapClone) ([ref]$captured)) -ne 0) {
            Fail "unable to clone the supplied repository"
        }
        $manifest = Read-Catalog $bootstrapClone
        if ($null -eq $manifest) { Fail "supplied repository is not a valid catalog" }
        $configuredOrigin = Get-GitValue @('-C', $bootstrapClone, 'remote', 'get-url', 'origin') "clone has no configured origin"
        if ([string]::IsNullOrEmpty($configuredOrigin)) { Fail "clone origin must not be blank" }
        $originDigest = Get-Sha256 $configuredOrigin
        $instanceKey = $manifest.catalog_id + '-' + $originDigest
        $instanceCatalogId = $manifest.catalog_id
        $instanceRoot = Join-Path (Join-Path $StateRoot "catalogs") $instanceKey
        $ManagedRepo = Join-Path $instanceRoot "repo"
    }

    if (-not $PrefixWasSupplied) { $Prefix = $manifest.default_prefix }
    if ($Prefix.Length -gt 0 -and -not (Test-PortableName $Prefix 62)) { Fail "invalid prefix" }
    if ($Action -cne "update-prefix") {
        $installKey = if ($Prefix.Length -gt 0) { $Prefix } else { "_default" }
    }
    $installRoot = Join-Path (Join-Path $instanceRoot "installs") $installKey

    if ($existingInstance) {
        Assert-InstanceLayout $instanceRoot
        if (Test-PathEntry $installRoot) {
            Assert-OwnedDirectory $installRoot "catalog installation view"
            Assert-OwnedDirectory (Join-Path $installRoot "generations") "catalog generation state"
            $existingOwnership = Join-Path $installRoot "ownership"
            Assert-OwnedDirectory $existingOwnership "catalog ownership state"
            Assert-OwnedDirectory (Join-Path $existingOwnership "agents") "agents ownership state"
            Assert-OwnedDirectory (Join-Path $existingOwnership "claude") "Claude ownership state"
        }
    }

    # Turning automatic updates off must work when the origin is unreachable or no longer trusted,
    # so this path never fetches and leaves the active skills exactly as they are.
    if ($RemoveAutoUpdate) {
        Enter-RemovalLock $instanceRoot
        Assert-InstanceLayout $instanceRoot
        $autoUpdateWasEnabled = Test-AutoUpdateEnabled $instanceRoot
        Prepare-HookRemoval $instanceRoot $instanceKey
        Commit-HookChanges
        Finalize-HookOwnership $true
        if ($autoUpdateWasEnabled) {
            Write-Output "Automatic updates are off for catalog $($manifest.catalog_id). Installed skills were not changed."
        }
        else {
            Write-Output "Automatic updates were already off for catalog $($manifest.catalog_id)."
        }
        exit 0
    }

    if ($Action -ceq "remove") {
        if (-not (Test-PathEntry $ManagedRepo)) { Fail "catalog instance is not installed" }
        if (-not (Test-PathEntry $installRoot)) {
            Write-Output "Catalog $($manifest.catalog_id) prefix '$Prefix' is already absent."
            exit 0
        }
        # Explicit removal and session-start reconciliation mutate the same catalog-owned state.
        # Atomic lock creation makes an existing updater a fail-closed, pre-mutation error.
        Enter-RemovalLock $instanceRoot
        Assert-InstanceLayout $instanceRoot
        if (-not (Test-PathEntry $installRoot)) { Fail "installed prefix state changed during removal" }
        Assert-OwnedDirectory $installRoot "catalog installation view"
        $remainingInstall = @(
            Get-ChildItem -Force -LiteralPath (Join-Path $instanceRoot 'installs') | Where-Object {
                $_ -is [System.IO.DirectoryInfo] -and -not (Test-ReparsePoint $_) -and
                    $_.FullName -cne $installRoot
            }
        ).Count -gt 0
        $removalPlan = @(Get-RemovalExposurePlan $installRoot)
        if (-not $remainingInstall -and -not (Test-ExactUtf8File $originIndex ($instanceKey + [Environment]::NewLine))) {
            Fail "catalog origin index is invalid"
        }
        $script:RemovalActive = $true
        $script:RemovalOriginIndex = $originIndex
        $script:RemovalInstanceKey = $instanceKey
        if (-not $remainingInstall) {
            Prepare-HookRemoval $instanceRoot $instanceKey
            Commit-HookChanges
        }
        foreach ($planned in $removalPlan) {
            if (Test-OwnedExposure $planned.Path $planned.ExpectedTarget) {
                $script:RemovedExposures += $planned
                Remove-DirectoryExposure $planned.Path
            }
            elseif (Test-PathEntry $planned.Path) {
                [Console]::Error.WriteLine("warning: not removing changed path $($planned.Path)")
            }
        }
        if ($remainingInstall) {
            $script:RemovalOriginalPath = $installRoot
            $script:RemovalStagedPath = Join-Path $WorkRoot 'removed-install'
        }
        else {
            $script:RemovalOriginalPath = $instanceRoot
            $script:RemovalStagedPath = Join-Path $WorkRoot 'removed-instance'
        }
        try {
            Move-Item -LiteralPath $script:RemovalOriginalPath -Destination $script:RemovalStagedPath
        }
        catch {
            Fail "cannot atomically stage catalog state removal"
        }
        if (-not $remainingInstall) {
            $script:RemovalOriginRemoved = $true
            Remove-Item -Force -LiteralPath $originIndex
        }
        $script:HookChangesCommitted = $false
        $script:RemovalActive = $false
        Write-Output "Removed catalog $($manifest.catalog_id) prefix '$Prefix'."
        exit 0
    }

    if (-not $existingInstance) {
        if (Test-PathEntry $instanceRoot) { Fail "catalog instance state already exists without an origin index" }
        $null = New-Item -ItemType Directory -Path $instanceRoot
        Move-Item -LiteralPath $bootstrapClone -Destination $ManagedRepo
        $null = New-Item -ItemType Directory -Force -Path $originIndexRoot
        $indexTemp = Join-Path $originIndexRoot ("." + $suppliedDigest + "." + [guid]::NewGuid().ToString("N"))
        [System.IO.File]::WriteAllText($indexTemp, $instanceKey + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $indexTemp -Destination $originIndex
        $sourceRoot = $ManagedRepo
    }
    else {
        $script:PreviousRepoHead = Get-GitValue @('-C', $ManagedRepo, 'rev-parse', 'HEAD') "managed catalog clone has no Git revision"
        if (-not [string]::IsNullOrEmpty($CandidateRevision)) {
            if ($CandidateRevision -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
                Fail "pinned catalog candidate is invalid"
            }
            $candidateRevisionResolved = Get-GitValue @('-C', $ManagedRepo, 'rev-parse', '--verify', $CandidateRevision) "pinned catalog candidate is unavailable"
            $candidateRevisionType = Get-GitValue @('-C', $ManagedRepo, 'cat-file', '-t', $candidateRevisionResolved) "pinned catalog candidate is unavailable"
            if ($candidateRevisionType -cne 'commit') { Fail "pinned catalog candidate is unavailable" }
            if ($candidateRevisionResolved -cne $CandidateRevision) {
                Fail "managed origin candidate changed during catalog update"
            }
            $candidateRevision = $candidateRevisionResolved
        }
        else {
            $captured = ""
            if ((Invoke-Git @('-C', $ManagedRepo, 'fetch', '--quiet', 'origin', '+HEAD:refs/team-skills/candidate') ([ref]$captured)) -ne 0) {
                Fail "unable to fetch the managed catalog origin"
            }
            $candidateRevision = Get-GitValue @('-C', $ManagedRepo, 'rev-parse', '--verify', 'refs/team-skills/candidate') "managed origin HEAD has no commit"
            $candidateRevisionType = Get-GitValue @('-C', $ManagedRepo, 'cat-file', '-t', $candidateRevision) "managed origin HEAD has no commit"
            if ($candidateRevisionType -cne 'commit') { Fail "managed origin HEAD has no commit" }
        }
        $captured = ""
        if ((Invoke-Git @('-C', $ManagedRepo, 'merge-base', '--is-ancestor', $script:PreviousRepoHead, $candidateRevision) ([ref]$captured)) -ne 0) {
            Fail "fetched catalog history is not a fast-forward; keeping the last known-good installation"
        }
        $CandidateWorktree = Join-Path $WorkRoot "candidate"
        if ((Invoke-Git @('-C', $ManagedRepo, 'worktree', 'add', '--quiet', '--detach', $CandidateWorktree, $candidateRevision) ([ref]$captured)) -ne 0) {
            Fail "unable to stage the fetched catalog"
        }
        $sourceRoot = $CandidateWorktree
        $manifest = Read-Catalog $sourceRoot
        if ($null -eq $manifest) { Fail "fetched catalog is invalid; keeping the last known-good installation" }
    }

    $manifest = Read-Catalog $sourceRoot
    if ($null -eq $manifest) { Fail "catalog is invalid; keeping the last known-good installation" }
    if ($manifest.catalog_id -cne $instanceCatalogId) {
        Fail "fetched catalog identity changed; keeping the last known-good installation"
    }
    if ($SetupAutoUpdate) {
        Prepare-HookRegistration $sourceRoot $instanceRoot $instanceKey
    }
    if (-not $PrefixWasSupplied) { $Prefix = $manifest.default_prefix }
    $installKey = if ($Prefix.Length -gt 0) { $Prefix } else { "_default" }
    $installRoot = Join-Path (Join-Path $instanceRoot "installs") $installKey

    $generationId = Get-GitValue @('-C', $sourceRoot, 'rev-parse', 'HEAD') "catalog has no Git revision"
    $stagedGeneration = Join-Path $WorkRoot "generation"
    $null = New-Item -ItemType Directory -Path $stagedGeneration
    foreach ($skillDirectory in @(Get-ChildItem -Directory -LiteralPath (Join-Path $sourceRoot "skills"))) {
        $effectiveName = if ($Prefix.Length -gt 0) { $Prefix + '-' + $skillDirectory.Name } else { $skillDirectory.Name }
        if (-not (Test-PortableName $effectiveName)) { Fail "effective skill name is invalid or exceeds 64 characters: $effectiveName" }
        $stagedSkill = Join-Path $stagedGeneration $effectiveName
        Copy-Item -Recurse -LiteralPath $skillDirectory.FullName -Destination $stagedSkill
        if ($Prefix.Length -gt 0) {
            $skillFile = Join-Path $stagedSkill "SKILL.md"
            $text = Read-Utf8Text $skillFile
            # Leave the original LF or CRLF delimiter byte-for-byte intact.
            $rewritten = [System.Text.RegularExpressions.Regex]::Replace($text, '(?m)^name:[ \t]*[^\r\n]*(?=\r?$)', "name: $effectiveName")
            [System.IO.File]::WriteAllText($skillFile, $rewritten, [System.Text.UTF8Encoding]::new($false))
        }
        if (-not (Test-Skill $stagedSkill $effectiveName)) { Fail "generated skill failed validation: $effectiveName" }
    }

    $generationsRoot = Join-Path $installRoot "generations"
    $ownershipRoot = Join-Path $installRoot "ownership"
    $null = New-Item -ItemType Directory -Force -Path $generationsRoot
    foreach ($product in @('agents', 'claude')) {
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $ownershipRoot $product)
    }
    Assert-OwnedDirectory $installRoot "catalog installation view"
    Assert-OwnedDirectory $generationsRoot "catalog generation state"
    Assert-OwnedDirectory $ownershipRoot "catalog ownership state"
    Assert-OwnedDirectory (Join-Path $ownershipRoot "agents") "agents ownership state"
    Assert-OwnedDirectory (Join-Path $ownershipRoot "claude") "Claude ownership state"
    $generationPath = Join-Path $generationsRoot $generationId
    $currentTarget = Join-Path $installRoot "current"
    $exposurePlan = Join-Path $WorkRoot "exposure-plan"
    $script:OwnershipSnapshot = Join-Path $WorkRoot "ownership.before"
    $null = New-Item -ItemType Directory -Path $exposurePlan
    foreach ($product in @('agents', 'claude')) {
        $null = New-Item -ItemType Directory -Path (Join-Path $exposurePlan $product)
    }
    Copy-Item -Recurse -LiteralPath $ownershipRoot -Destination $script:OwnershipSnapshot

    foreach ($product in @('agents', 'claude')) {
        $productRoot = if ($product -ceq 'agents') { $AgentsRoot } else { $ClaudeRoot }
        if ((Test-PathEntry $productRoot) -and -not ((Get-Item -Force -LiteralPath $productRoot) -is [System.IO.DirectoryInfo])) {
            Fail "product skills root is not a directory: $productRoot"
        }
        foreach ($generatedSkill in @(Get-ChildItem -Directory -LiteralPath $stagedGeneration)) {
            $destination = Join-Path $productRoot $generatedSkill.Name
            $ownerFile = Join-Path (Join-Path $ownershipRoot $product) ($generatedSkill.Name + ".owner")
            $expectedTarget = Join-Path $currentTarget $generatedSkill.Name
            if ((Test-PathEntry $destination) -and -not ((Test-PathEntry $ownerFile) -and (Test-OwnedExposure $destination $expectedTarget))) {
                [Console]::Error.WriteLine("warning: catalog $($manifest.catalog_id) skill $($generatedSkill.Name) skipped; destination exists: $destination")
            }
            elseif (-not (Test-PathEntry $destination)) {
                $planFile = Join-Path (Join-Path $exposurePlan $product) ($generatedSkill.Name + ".create")
                $null = New-Item -ItemType File -Path $planFile
            }
        }
    }

    if (-not (Test-PathEntry $generationPath)) {
        Move-Item -LiteralPath $stagedGeneration -Destination $generationPath
    }
    $script:InstallRoot = $installRoot
    $script:CurrentTarget = $currentTarget
    $script:GenerationPath = $generationPath
    if (Test-PathEntry $currentTarget) {
        $script:PreviousGenerationTarget = Get-LinkTarget $currentTarget
        if ($null -eq $script:PreviousGenerationTarget) {
            Fail "catalog current view is not an owned directory link"
        }
        $script:HadPreviousGeneration = $true
    }
    else {
        $script:HadPreviousGeneration = $false
    }
    $script:TransactionActive = $true
    Activate-Generation $installRoot $generationPath

    foreach ($product in @('agents', 'claude')) {
        $productRoot = if ($product -ceq 'agents') { $AgentsRoot } else { $ClaudeRoot }
        $null = New-Item -ItemType Directory -Force -Path $productRoot
        $owners = Join-Path $ownershipRoot $product
        foreach ($ownerFile in @(Get-ChildItem -File -Filter "*.owner" -LiteralPath $owners)) {
            $ownedName = $ownerFile.BaseName
            if (Test-PathEntry (Join-Path $currentTarget $ownedName)) { continue }
            $destination = Join-Path $productRoot $ownedName
            $expectedTarget = ([System.IO.File]::ReadAllText($ownerFile.FullName)).Trim()
            if (Test-OwnedExposure $destination $expectedTarget) {
                Remove-DirectoryExposure $destination
            }
            elseif (Test-PathEntry $destination) {
                [Console]::Error.WriteLine("warning: not removing changed path $destination")
            }
            Remove-Item -Force -LiteralPath $ownerFile.FullName
        }
        foreach ($generatedSkill in @(Get-ChildItem -Directory -LiteralPath $currentTarget)) {
            $planFile = Join-Path (Join-Path $exposurePlan $product) ($generatedSkill.Name + ".create")
            if (-not (Test-PathEntry $planFile)) { continue }
            $destination = Join-Path $productRoot $generatedSkill.Name
            $ownerFile = Join-Path $owners ($generatedSkill.Name + ".owner")
            $expectedTarget = Join-Path $currentTarget $generatedSkill.Name
            $script:CreatedExposures += [PSCustomObject]@{
                Path = $destination
                ExpectedTarget = $expectedTarget
            }
            try {
                # Creating the final junction/symlink is atomic and fails if a racing path exists.
                New-DirectoryExposure $destination $expectedTarget
            }
            catch {
                Fail "cannot expose skill $($generatedSkill.Name)"
            }
            [System.IO.File]::WriteAllText($ownerFile, $expectedTarget + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        }
    }

    if ($null -ne $CandidateWorktree) {
        $captured = ""
        if ((Invoke-Git @('-C', $ManagedRepo, 'reset', '--quiet', '--hard', $candidateRevision) ([ref]$captured)) -ne 0) {
            Fail "installed view is valid but managed clone could not advance"
        }
    }
    Commit-HookChanges
    Finalize-HookOwnership $false
    $script:TransactionActive = $false
    Write-Output "Installed catalog $($manifest.catalog_id) as instance $instanceKey with prefix '$Prefix'."
    if ($Action -ceq 'install') {
        if (Test-AutoUpdateEnabled $instanceRoot) {
            Write-Output "Automatic updates are on for this catalog. Disable them with -RemoveAutoUpdate."
        }
        else {
            Write-Output "Automatic updates are off. Rerun this install command to update, or add -SetupAutoUpdate to enable them."
        }
    }
}
catch {
    $failureMessage = $_.Exception.Message
    Invoke-TransactionRollback
    [Console]::Error.WriteLine("error: " + $failureMessage)
    exit 1
}
finally {
    if ($null -ne $CandidateWorktree -and $null -ne $ManagedRepo -and (Test-PathEntry $ManagedRepo)) {
        $captured = ""
        $null = Invoke-Git @('-C', $ManagedRepo, 'worktree', 'remove', '--force', $CandidateWorktree) ([ref]$captured)
    }
    Exit-RemovalLock
    if ($null -ne $WorkRoot -and (Test-PathEntry $WorkRoot)) {
        Remove-Item -Recurse -Force -LiteralPath $WorkRoot
    }
}
