# Disposable manual verification

Automated tests exercise configuration merging and updater behavior with disposable homes, Git
origins, state roots, and config roots on Linux, macOS, and native Windows. The checks below are the
remaining human product-verification package. They have not been run or accepted on behalf of any
user.

## Prepare the repeatable fixture

Do not test against a normal user profile. Use a dedicated temporary OS account, VM, or disposable
product profile whose entire home/configuration directory can be discarded. Clone Team Skills at
the commit under test inside that environment. The fixture helper requires Python only to prepare
test data; installation and updating still require only the platform shell and Git.

On macOS, Linux, or WSL:

```sh
TEAM_SKILLS_MANUAL_PARENT=$(mktemp -d "${TMPDIR:-/tmp}/team-skills-manual.XXXXXXXX")
TEAM_SKILLS_MANUAL_ROOT="$TEAM_SKILLS_MANUAL_PARENT/fixture"
export TEAM_SKILLS_MANUAL_PARENT TEAM_SKILLS_MANUAL_ROOT
python3 scripts/prepare-manual-verification.py prepare "$TEAM_SKILLS_MANUAL_ROOT"
. "$TEAM_SKILLS_MANUAL_ROOT/environment.sh"
```

On native Windows PowerShell:

```powershell
$TeamSkillsManualParent = Join-Path ([IO.Path]::GetTempPath()) ("team-skills-manual-" + [guid]::NewGuid())
$TeamSkillsManualRoot = Join-Path $TeamSkillsManualParent "fixture"
python scripts/prepare-manual-verification.py prepare $TeamSkillsManualRoot
. (Join-Path $TeamSkillsManualRoot "environment.ps1")
```

The helper refuses an existing root and never launches a product. It creates two local bare origins
with the same catalog ID and skill name, installs the first twice, installs the second once blank
and once as `second` (each with automatic updates enabled), seeds product-valid unrelated configuration (including a Codex description
and unrelated `Other` hook), and records before/after JSON and the visible collision warning.
Inspect `fixture.json`, `evidence/install-transcript.txt`, both skill roots, and
all three hook files before launching anything. `RESULTS.md` is copied from the
[pending results template](manual-results-template.md) with the tested Team Skills SHA filled in.

Use these commands to make controlled changes during the checklist:

```sh
python3 scripts/prepare-manual-verification.py advance "$TEAM_SKILLS_MANUAL_ROOT" first v2
python3 scripts/prepare-manual-verification.py origin "$TEAM_SKILLS_MANUAL_ROOT" first unreachable
python3 scripts/prepare-manual-verification.py origin "$TEAM_SKILLS_MANUAL_ROOT" first restore
python3 scripts/prepare-manual-verification.py show "$TEAM_SKILLS_MANUAL_ROOT"
```

Use `python` and `$TeamSkillsManualRoot` for the equivalent PowerShell commands. `advance` creates
and pushes one valid local commit. `origin ... unreachable` uses only an absent local file origin
with inert `manual-user` and `manual-secret` strings, so it exercises credential redaction without
network access; `restore` puts back the original local origin.

In the product checklists, “advance with `MARKER`” means exactly one of:

```sh
python3 scripts/prepare-manual-verification.py advance "$TEAM_SKILLS_MANUAL_ROOT" first MARKER
```

```powershell
python scripts/prepare-manual-verification.py advance $TeamSkillsManualRoot first MARKER
```

Likewise, “set the origin `MODE`” means `origin "$TEAM_SKILLS_MANUAL_ROOT" first MODE` on
POSIX or `origin $TeamSkillsManualRoot first MODE` on Windows, using the same helper command shown
above. Replace `MARKER` and `MODE` only with the literal value named in the checklist.

Claude Code, Codex, and Cursor must be launched from the prepared environment in the dedicated
account/VM/profile so their ordinary paths resolve to the fixture's `home`. Merely redirecting the
installer while launching a normal product profile would not test the generated hook files.

## WSL POSIX-path evidence

WSL uses `scripts/team-skills.sh`, not the native PowerShell implementation. From a disposable WSL
checkout, the automated POSIX suite creates all of its own temporary homes and local origins:

```sh
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
sh -n scripts/team-skills.sh
```

For the exact disposable merge/update smoke test, run the preparation commands above inside WSL,
then advance only the first catalog and invoke the POSIX URL-free updater:

```sh
python3 scripts/prepare-manual-verification.py advance "$TEAM_SKILLS_MANUAL_ROOT" first wsl-v2
TEAM_SKILLS_NOW=2000000000 sh scripts/team-skills.sh update-all
grep -q '# Fixture first wsl-v2' "$TEAM_SKILLS_AGENTS_ROOT/common-skill/SKILL.md"
grep -q 'name: second-common-skill' "$TEAM_SKILLS_CLAUDE_ROOT/second-common-skill/SKILL.md"
grep -q '# Fixture second v1' "$TEAM_SKILLS_CLAUDE_ROOT/second-common-skill/SKILL.md"
grep -q 'foreign-workspace' "$TEAM_SKILLS_CURSOR_HOOKS_FILE"
```

This proves validation/tests in WSL, POSIX hook merging, colliding/prefixed exposure, and a local
origin-based update that leaves the second skill content unchanged. It does not prove that a
Windows-hosted Cursor instance consumes WSL user configuration, nor does it count as a native
Windows PowerShell result.

## Product lifecycle checks

Before each product event, copy the three hook files, each instance's `last-success` and
`last-update.log` when present, and the active `SKILL.md` into a new evidence subdirectory. Use an
unmistakable, non-sensitive marker with `advance`. The prepared environment disables throttling;
do not carry that setting outside this disposable profile.

### Claude Code

1. Advance with `claude-startup`, start a fresh local session, and confirm startup is
   prompt and `last-success` eventually changes.
2. Advance with `claude-clear`, use `/clear`, and confirm another completed update.
3. Record `last-success` and `last-update.log`, resume a session, and trigger compaction separately.
   Confirm neither file changes.
4. Set the origin `unreachable`, start a fresh session, and confirm Claude Code remains
   usable, the previous skill stays active, and `last-update.log` contains neither `manual-user` nor
   `manual-secret`. Set the origin `restore`, advance with `claude-retry`, and confirm a clean retry.

Do not require the changed skill in the session that triggered the update. Claude Code normally
scans skills before an asynchronous `SessionStart` update completes, so verify it in the following
session.

### Codex

1. Review the newly discovered non-managed Team Skills hook and explicitly trust its exact
   definition. Record that step; Codex skips it until trusted and requires renewed review if its
   hash changes.
2. Advance with `codex-startup`, start a new local session, and confirm it eventually updates
   without delaying startup.
3. As a version-specific capability check, advance with `codex-clear` and use `/clear`. Record a
   pass only if the updater evidence changes. Codex CLI 0.149.1 and 0.151.0 did not emit the active
   `SessionStart` hook for this event during authenticated macOS verification; classify that result
   as a product-runtime gap and use a fresh process as the reliable update boundary.
4. Capture timestamps, resume and compact separately, and confirm neither starts an update.
5. Set the origin `unreachable` and start fresh. Then set it to `restore`, advance with
   `codex-retry`, and start fresh again. Confirm fail-open behavior, last-known-good retention, a
   log without either inert credential string, and clean retry.

As with Claude Code, allow one additional session before expecting a newly updated skill in the
initial scan.

### Cursor

1. Advance with `cursor-conversation`, create a new local composer/agent conversation, and confirm
   `sessionStart` launches the updater without blocking conversation creation.
2. Capture timestamps, open or change a workspace without creating a conversation, and confirm
   neither updater evidence file changes; Team Skills does not register `workspaceOpen`.
3. Advance with `cursor-following`, create a conversation, allow the fire-and-forget process to
   finish, and verify the marker no later than the following conversation.
4. Set the origin `unreachable` and create a conversation. Then set it to `restore`, advance with
   `cursor-retry`, and create another conversation to confirm clean retry.

This check applies only to local Cursor. User-level `~/.cursor/hooks.json` and `sessionStart` are
not available in Cursor cloud agents, and no cloud synchronization is part of Team Skills.

## Multi-catalog and removal checks

With all three products closed, inspect the disposable JSON files and verify foreign entries plus
one updater entry for each catalog. Rerun both installs and confirm no duplicate entry appears.
Remove one catalog's final prefix and verify its exact entries and state disappear while the other
catalog, its prefixes, and every foreign entry survive. Finally remove the other catalog and verify
only its owned exposures, hook entries, and instance state are removed.

## Cleanup

Close every product launched with the disposable environment. Review `RESULTS.md` and copy only
sanitized evidence that must be retained. Do not retain the managed clone's Git configuration: it
temporarily contains the inert test credential strings while origin mode is `unreachable`. The
helper validates `fixture.json`, rejects redirected/linked owned paths, and removes only the exact
fixture root. It never recursively deletes the temporary parent, a normal home, or a product
configuration directory. No service, scheduled task, cron entry, plugin, wrapper, or machine-wide
artifact was installed.

Use the ownership-validating cleanup command, then remove the now-empty parent non-recursively:

```sh
python3 scripts/prepare-manual-verification.py cleanup "$TEAM_SKILLS_MANUAL_ROOT"
rmdir -- "$TEAM_SKILLS_MANUAL_PARENT"
unset TEAM_SKILLS_MANUAL_PARENT TEAM_SKILLS_MANUAL_ROOT
```

```powershell
python scripts/prepare-manual-verification.py cleanup $TeamSkillsManualRoot
Remove-Item -LiteralPath $TeamSkillsManualParent
Remove-Variable TeamSkillsManualParent, TeamSkillsManualRoot
```

Record product versions, OS and shell versions, the tested Team Skills commit, sanitized
before/after JSON, state timestamps, and any product warnings. Every row remains `PENDING` until a
human performs and reviews it; automated CI does not turn these product/WSL rows into passes.
