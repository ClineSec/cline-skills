# Installation and updates

Skills install per user, once, and are then available in every project on that machine. The tooling
that installs and updates them comes from
[Team Skills](https://github.com/ClineSec/team-skills), which is why the scripts are named
`team-skills`.

## Install

On macOS, Linux, or WSL, using only a POSIX shell and Git:

```sh
curl -fsSL https://raw.githubusercontent.com/ClineSec/cline-skills/main/scripts/team-skills.sh \
  | sh -s -- install https://github.com/ClineSec/cline-skills.git
```

On native Windows, using Windows PowerShell and Git without administrator access:

```powershell
$installer = Invoke-RestMethod https://raw.githubusercontent.com/ClineSec/cline-skills/main/scripts/team-skills.ps1
& ([scriptblock]::Create($installer)) install https://github.com/ClineSec/cline-skills.git
```

The repository URL passed to `install` is the explicit initial bootstrap URL and the stable selector
for that catalog instance on later manual runs.

Review downloaded scripts before executing them when that is required by your security policy.
Private forks may instead clone through their normal authenticated Git workflow and run the local
script:

```sh
sh scripts/team-skills.sh install "$(git remote get-url origin)"
```

```powershell
.\scripts\team-skills.ps1 install (git remote get-url origin)
```

The installer creates a private managed clone and exposes its skills in both user-global discovery
locations:

- `~/.agents/skills` for Codex and Cursor;
- `~/.claude/skills` for Claude Code and Cursor.

POSIX systems use directory symlinks. Native Windows uses directory junctions, which require no
administrator or Developer Mode access.

Installation does not change product hook configuration unless you opt in, so skills stay at the
installed revision until you update them. Choose an update path when you install:
[automatic updates at session start](#automatic-updates-at-session-start) or
[manual updates](#manual-updates).

## Use your own fork

A team can fork this repository, curate `skills/`, and install from the fork. To do that, replace
both `ClineSec/cline-skills` occurrences in the commands above with your fork. Later updates use the
managed clone's configured Git `origin`, and no operational path falls back to this repository.

See [the authoring guide](skill-authoring.md) for curating and validating a fork.

## Managed macOS deployment

Team Skills can be deployed through a macOS mobile device management (MDM) product without
changing its user-global ownership model. The MDM command must identify the logged-in console
user and run the installer in that user's launch context; running the installer directly as the
MDM agent would incorrectly install it for `root`.

Setup guides and a checksum-pinned deployment script are provided for:

- [Iru](mdm/iru.md) (formerly Kandji);
- [Jamf Pro](mdm/jamf-pro.md);
- [Mosyle](mdm/mosyle.md).

Create one MDM item per catalog. Substitute that fork's reviewed installer URL, SHA-256 digest,
repository URL, and optional skill-name prefix. Private catalogs also need noninteractive Git
authentication in the target user's context; never embed a token or password in a URL, script,
parameter, or MDM log. MDM performs the initial user-scoped installation. The guides pass
`--setup-auto-update` so session-start hooks provide later one-shot updates without a service or
scheduled job; remove that argument only if you have another way to keep the catalog current.

## Automatic updates at session start

Automatic updates are opt-in. Enable them for a catalog during installation, or later on an existing
installation, by adding the setup flag:

```sh
sh scripts/team-skills.sh install REPOSITORY-URL --setup-auto-update
```

```powershell
.\scripts\team-skills.ps1 install REPOSITORY-URL -SetupAutoUpdate
```

The setting belongs to the whole catalog, including every prefix. Enabling it registers a session
hook that fetches and activates the origin's current default branch, including the lifecycle script
the hook runs next time. Enable it only for catalogs whose default branch you trust to run on this
machine. Registration preserves unrelated JSON keys, events, handlers, and catalog entries. An
existing malformed or unsupported hook file makes the command fail without overwriting that file or
exposing a partial installation.

Turn automatic updates off with:

```sh
sh scripts/team-skills.sh install REPOSITORY-URL --remove-auto-update
```

```powershell
.\scripts\team-skills.ps1 install REPOSITORY-URL -RemoveAutoUpdate
```

This removes only the catalog's own hook entries. It does not fetch or change the installed skills,
so it still works when the origin is unreachable or no longer trusted. Do not combine it with a
prefix. A plain `install` rerun never adds or removes hooks, so an existing installation keeps its
current setting until one of these flags changes it.

Each enabled catalog has its own hook entry, lock, throttle, and managed clone. The hook command
contains only the catalog instance key and the path to the lifecycle script in that clone; it does
not contain or persist the bootstrap URL. Update work reads installed instances from owned state,
verifies each clone's configured `origin` still matches its installation identity, fetches only
that remote's current `HEAD` with Git prompting disabled, and reconciles every installed prefix
through the same validation and transactional activation used by `install`. One
locked catalog attempt performs one fetch and pins the resulting exact commit for every prefix.
The commit must be a fast-forward from the managed clone's current revision.

| Product | User configuration | Installed event |
| --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | asynchronous `SessionStart`, matcher `startup\|clear` |
| Codex | `~/.codex/hooks.json` (`$CODEX_HOME/hooks.json` when set) | async `SessionStart`, `startup\|clear`; fresh startup is the verified update boundary |
| Cursor | `~/.cursor/hooks.json` | `sessionStart` only |

Claude Code updates run for a new session and after `/clear`, not for resume or compact. Codex
fresh-session startup is verified, but Codex CLI 0.149.1 and 0.151.0 did not emit the active
`SessionStart` hook after `/clear`; start a new Codex process when an update boundary is needed.
The installed Codex matcher retains `clear` for versions that emit it, but Team Skills does not
promise that behavior. Codex requires the user to review and trust a non-managed hook before it
will run; a newly installed or changed Team Skills hook can therefore be skipped until accepted.
Cursor defines `sessionStart` as creation of a new composer conversation and runs it
fire-and-forget. Team Skills does not install Cursor's separate `workspaceOpen` event. Cursor
user-level hooks are local-only and are not available in Cursor cloud agents.

The default throttle is six hours per catalog, measured from the last completely successful update.
An update skipped by that throttle or by an already-held catalog lock does no network fetch and
returns success. The hook launcher returns promptly, masks updater failure from product startup,
and starts at most one detached, one-shot updater attempt per event; there is no resident process,
daemon, cron job, or tool wrapper.

Updates are deliberately not guaranteed to finish before a product's initial skill scan. A newly
fetched skill may first be visible in the next session. This is especially relevant to the
asynchronous Claude Code and Codex hooks and Cursor's fire-and-forget event.

## Manual updates

Both manual paths work with or without automatic updates, ignore the six-hour throttle, and use the
same validation and transactional activation as an automatic update.

Rerun the original install command, including the same prefix, to update that one installed view.
This form also works through the `curl` or `Invoke-RestMethod` bootstrap shown above:

```sh
sh scripts/team-skills.sh install REPOSITORY-URL
```

```powershell
.\scripts\team-skills.ps1 install REPOSITORY-URL
```

Run `update-all` to update every prefix of every installed catalog and report each result. It needs
a lifecycle script on disk rather than a piped download, such as a trusted checkout or a managed
clone's copy under `catalogs/<instance-key>/repo/scripts/`:

```sh
sh scripts/team-skills.sh update-all
```

```powershell
.\scripts\team-skills.ps1 update-all
```

It attempts every catalog even when one fails and returns nonzero if any update fails. A catalog
whose update lock is held is reported as skipped. Start a new product session to load updated
skills.

## Multiple catalogs and prefixes

Run the installer once for each catalog URL. Each exact initial URL receives deterministic,
isolated clone and ownership state. A rerun fetches only the managed clone's instance-bound
configured `origin`, validates a complete candidate, and then reconciles its exposures.

The default prefix is read from `catalog.json` and is blank in this repository. With a blank
prefix, an existing destination wins: the incoming skill is skipped, a warning is printed, the
existing bytes are untouched, and the command succeeds. Use a prefix when colliding catalogs
should coexist:

```sh
sh scripts/team-skills.sh install https://github.com/YOUR-ORG/cline-skills.git --prefix acme
```

```powershell
.\scripts\team-skills.ps1 install https://github.com/YOUR-ORG/cline-skills.git -Prefix acme
```

For example, `skill-creator` becomes `acme-skill-creator`. The installer creates a validated,
catalog-owned copy whose directory and `SKILL.md` name agree, while preserving its body, resources,
and required executable permissions.

An explicit empty prefix overrides a catalog's nonblank default:

```sh
sh scripts/team-skills.sh install REPOSITORY-URL --prefix ''
```

```powershell
.\scripts\team-skills.ps1 install REPOSITORY-URL -Prefix ''
```

## Remove a catalog installation

Pass the same initial repository URL and prefix used to install the view:

```sh
sh scripts/team-skills.sh remove REPOSITORY-URL --prefix acme
```

```powershell
.\scripts\team-skills.ps1 remove REPOSITORY-URL -Prefix acme
```

Removal deletes an exposure only when its ownership record and link target both still match. A
changed or user-replaced path is retained with a warning. Other prefixes, catalogs, user skills,
and foreign product configuration are outside that removal boundary. Removing a non-final prefix
keeps the catalog updater, if one is enabled. Removing the final prefix removes only hook entries
whose recorded configuration path and exact command still prove catalog ownership, then removes
that catalog's managed clone, hook ownership state, and origin index. If a catalog-owned hook was edited, removal
refuses safely so the installation can be inspected and retried. Removal also takes the catalog's
update lock and refuses before mutation when a session-start reconciliation is already in progress.
Empty hook containers are pruned. When Team Skills created a product hook file, removing the last
catalog deletes that file only if no foreign configuration was added; pre-existing files remain.
