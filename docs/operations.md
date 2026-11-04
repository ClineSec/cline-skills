# Operations and troubleshooting

This document describes the installed Team Skills lifecycle. The bootstrap URL is used only to
create or find an instance during explicit `install` and `remove` commands. Automatic updates and
`update-all` discover instances from owned state and use the `origin` configured in each managed
clone.

## Lifecycle architecture

One installation has three layers:

1. An instance represents one configured Git origin. It owns a managed clone, hook records, update
   lock, throttle stamp, and diagnostic log.
2. An installed view represents one blank or nonblank prefix under that instance. An updater
   enumerates all of these views; it does not need the original bootstrap URL.
3. Exposures are catalog-owned links or junctions from product skill directories to the active,
   validated generation for a view.

`install --setup-auto-update` adds one hook per instance to each product, regardless of how many
prefixes that instance exposes. Without that flag, `install` does not read or change product hook
files, and a rerun leaves any existing hooks as they are. `install --remove-auto-update` takes the
catalog lock and removes only that instance's owned hook entries without fetching or changing its
skills. Commands identify the instance without embedding a repository URL. Multiple
catalogs therefore have independent commands and mutable state. The JSON edits are staged,
structural, and atomic: unrelated top-level keys, events, handlers, and their order are retained
where practical. Team Skills writes Codex's supported `hooks.json` representation and does not
rewrite `config.toml` or any inline TOML hooks already present there.

The registered lifecycle choices follow the first-party hook references reviewed on 2026-08-29:

- Claude Code: user-level `SessionStart` with `startup|clear`, and an asynchronous command handler.
  `resume`, `compact`, and `fork` are intentionally excluded.
- Codex: user-level `SessionStart` with `startup|clear`, and an asynchronous command handler.
  Fresh-process startup is the verified update boundary; authenticated Codex CLI 0.149.1 and
  0.151.0 did not emit the active hook after `/clear`, so that event is runtime-dependent rather
  than guaranteed.
  `resume` and `compact` are intentionally excluded. Codex must trust the exact non-managed hook
  definition before it runs.
- Cursor: user-level `sessionStart`, which fires for a new composer conversation and is
  fire-and-forget. `workspaceOpen` is intentionally not installed.

References: [Claude Code hooks](https://code.claude.com/docs/en/hooks),
[Codex hooks](https://learn.chatgpt.com/docs/hooks), and
[Cursor hooks](https://cursor.com/docs/hooks).

An enabled hook entry itself returns promptly. It launches a detached, noninteractive, one-shot
updater and always reports success to the product. The updater then:

1. validates the instance state and acquires that catalog's lock;
2. exits successfully without a fetch when another owner holds the lock or the last complete
   success is younger than the throttle;
3. verifies the managed clone's current `origin` still matches its installation identity, fetches
   that remote's current `HEAD` once with terminal prompting disabled, requires a fast-forward,
   and pins that exact candidate commit for every installed prefix;
4. validates the candidate lifecycle runtime and catalog, then transactionally activates each view
   using the installer rules; and
5. records `last-success` only after all installed views reconcile successfully.

`update-all` follows the same steps synchronously except that it skips the throttle, because it is
an explicit request to update now. It prints one result per catalog, and no catalog failure prevents
it from attempting the remaining catalogs. No update path
uses a fallback upstream. No daemon, service, cron entry, scheduled task, or product wrapper is
installed. The detached process is bounded to one update attempt and the per-catalog lock prevents
simultaneous Claude Code, Codex, and Cursor starts from racing.

## State and configuration paths

The POSIX state root is `${XDG_DATA_HOME:-$HOME/.local/share}/team-skills`. Native Windows uses
`%LOCALAPPDATA%\team-skills`, falling back to `%USERPROFILE%\.local\share\team-skills`. Each catalog
instance has this shape:

```text
catalogs/<catalog-id>-<origin-digest>/
├── repo/                          managed clone; origin is update authority
├── hooks/
│   ├── claude.owner              exact config path and command
│   ├── codex.owner
│   └── cursor.owner
├── installs/
│   └── <prefix-or-_default>/
│       ├── current               active view link or junction
│       ├── generations/          immutable validated views
│       └── ownership/            exact exposure targets
├── last-success                  epoch seconds for the six-hour throttle
├── last-update.log               latest hook-launched diagnostic
└── update.lock/                  PID and start time while updating
```

The `origins/` index maps a digest of the initially supplied URL to an instance key. The supplied
URL itself is not stored there. The clone's configured origin is the only later network authority,
and its installation-time digest is part of the instance key so a later origin edit fails closed.
Do not publish or copy a managed clone's Git configuration when its origin can contain credentials.

Default hook files are `~/.claude/settings.json`, `${CODEX_HOME:-~/.codex}/hooks.json`, and
`~/.cursor/hooks.json` on POSIX, with the equivalent paths below `%USERPROFILE%` on Windows. All
state, exposure, and hook paths have explicit [environment overrides](#environment-overrides). These
are useful for managed environments and tests, but a product reads an override file only if that
product is also launched in the corresponding disposable environment.

Atomic hook replacement preserves an existing file's POSIX mode or Windows access-control list.
New POSIX hook files are created with mode `0600`; new Windows files inherit access control from
their product configuration directory.

### Environment overrides

The environment variables `TEAM_SKILLS_STATE_ROOT`, `TEAM_SKILLS_AGENTS_ROOT`,
`TEAM_SKILLS_CLAUDE_ROOT`, `TEAM_SKILLS_CLAUDE_HOOKS_FILE`,
`TEAM_SKILLS_CODEX_HOOKS_FILE`, and `TEAM_SKILLS_CURSOR_HOOKS_FILE` override these paths for managed
environments and disposable tests. They must be absolute, non-root paths. The default throttle can
be changed with `TEAM_SKILLS_THROTTLE_SECONDS`; `TEAM_SKILLS_NOW` and
`TEAM_SKILLS_STALE_LOCK_SECONDS` exist for deterministic testing and controlled test environments.

## Throttle, lock, and visibility

The default throttle is 21,600 seconds (six hours) per catalog. It starts after a completely
successful reconciliation. A failure does not advance the stamp, so the next session can retry.
`TEAM_SKILLS_THROTTLE_SECONDS=0` disables throttling for deterministic tests; do not set it globally
unless fetching on every matching session is intended.

Locks are directories inside the catalog instance. A live owner is never displaced. Incomplete,
malformed, future-dated, or not-yet-stale ownership is conservatively treated as locked. A dead
owner is recoverable only after the one-hour default stale interval and an atomic rename/reacquire
sequence. Unsafe lock path types are skipped without fetching. Explicit removal atomically takes
the same per-catalog lock before mutation and fails closed if an update already owns it. Retry after
the update completes; for a dead well-formed lock, run `update-all` after the stale interval to
recover it before retrying removal. Do not manually recursively delete a lock directory.

Hook execution does not imply that a product waits for its skill scan. A completed update may be
visible only in the next session. Team Skills does not emit Claude Code's synchronous
`reloadSkills` response because the launcher is intentionally asynchronous and fail-open.

## Failure behavior

Clone and fetch diagnostics are suppressed so credential-bearing URLs are not echoed. Malformed
catalogs, invalid names, failed fetches, and failed generation do not replace the last known-good
view. Candidate activation, exposure reconciliation, ownership records, and managed-clone
advancement form one transaction: a late destination race or other unsuccessful install restores
the prior view and removes only newly created, still-proven catalog exposures. On a first-install
failure, no partial catalog exposure remains. The racing or user-owned path is never overwritten.
Interrupted temporary work is removed during process cleanup; validated generations are immutable
and activation is atomic at the `current` link.

A candidate is rejected before clone advancement unless it contains regular, non-symlinked copies
of all three lifecycle files (`team-skills.sh`, `team-skills-json.awk`, and `team-skills.ps1`) and
the native lifecycle script parses successfully. Rewritten, downgraded, or unrelated default-branch
history is also rejected. A remote may move its default `HEAD` to a descendant branch without
manual local tracking-ref repair. To move an installation to any different origin, including a
same-history mirror, remove each prefix using its original bootstrap selector, then install the new
origin as a new instance. Direct edits to a managed clone's configured origin fail closed; removal
remains available because it does not fetch.

The last hook-launched diagnostic for a catalog is written atomically to
`catalogs/<instance-key>/last-update.log` below the state root. Origin values and Git clone/fetch
diagnostics are suppressed so credential-bearing remotes are not printed. The log retains at most
the final 64 KiB from the latest attempt without splitting a UTF-8 sequence. A failed fetch,
invalid candidate, substituted catalog-owned directory, or future-dated throttle stamp leaves
existing skills active and is retried after the next eligible session start or
[manual update](installation.md#manual-updates).

## Removal

Remove each installed prefix with the same bootstrap URL used to create its origin-index record.
Removing one prefix leaves the instance and its single set of hooks in place while another prefix
remains. On the final prefix, Team Skills stages removal of each exact catalog-owned hook entry,
preflights every skill ownership record, removes proven skill exposures, and only then atomically
stages instance state and removes its origin index. If a late removal step fails, unchanged
exposures and hook files are restored; a path created concurrently is never overwritten.

Removal does not delete foreign entries or another catalog's entries. It refuses malformed hook
configuration, a changed owned command, a changed ownership record, or a changed configuration
path. Skill ownership entries must be ordinary files with the exact canonical target and name;
linked, extra, or malformed entries stop removal before mutation. It also retains a skill
destination whose link/junction target no longer matches its ownership record. Restore the
expected owned entry or path from a trusted backup, then rerun
`remove`; do not delete shared configuration files to force removal.

The hook owner records also retain whether Team Skills created the configuration file and whether
it added Cursor's required version field. That provenance is carried across catalogs sharing the
same hook file. Final removal prunes empty event/container objects, removes only a version field
Team Skills added, and deletes a Team Skills-created file only when no foreign configuration
remains. Late-failure rollback restores a deleted file with its prior access protection.

## Troubleshooting

### No automatic update appears

- Confirm automatic updates are enabled: the instance has a `hooks/` directory. A plain `install`
  does not create one. Add `--setup-auto-update` to enable them, or update manually.
- Allow for the six-hour throttle and the possible one-session visibility lag.
- In Codex, review and trust the exact Team Skills hook. Codex skips untrusted or changed
  non-managed hooks.
- In Cursor, create a new local composer conversation. Opening a workspace alone does not trigger
  Team Skills, and user-level hooks do not run in Cursor cloud agents.
- Check the instance's `last-success` and `last-update.log`. A successful no-output run can leave an
  empty log. Never add the output of `git remote get-url origin` to a support report.
- Run the appropriate lifecycle script with `update-all` from a trusted checkout to attempt every
  installed instance immediately, regardless of the throttle. This action is synchronous, reports
  each catalog's result, and returns nonzero if any catalog fails, unlike the fail-open hook
  launcher. A catalog whose update lock is held is reported as skipped.

### Installation refuses a hook file

This applies when `--setup-auto-update` or `--remove-auto-update` edits hook files. A plain
`install` does not read them. Team Skills accepts a JSON object with supported hook container
shapes. It rejects malformed JSON,
duplicate or case-colliding keys, invalid UTF-8, documents larger than 1 MiB, nesting beyond 64
container levels, wrong hook container types, symlinked configuration files, and owned entries
that no longer exactly match. Codex hook roots are additionally limited to its locally verified
`description` string and `hooks` object fields; unsupported root fields are rejected without
changing the file. These Codex-only root restrictions are not applied to Claude or Cursor.
Case-colliding keys are refused because Windows PowerShell cannot
preserve both properties reliably. The original file is not overwritten and the installation
transaction is rolled back. Correct or restore the file, preserve its unrelated fields, and rerun
`install`.

### Fetch or candidate validation fails

The current generation and exposures remain active. Hook logs use fixed diagnostics, suppress Git
fetch output so credential-bearing origins are not exposed, and atomically retain at most the final
64 KiB from the latest attempt. Correct authentication, network access, the clone's configured
origin, or the remote catalog, then wait for the next eligible session or run `update-all`. A
changed configured origin is rejected even when it offers fast-forward history: restore the exact
original origin value, or remove every prefix with the original bootstrap selector and install the
new origin explicitly. Removal remains available after an origin edit because it performs no
network fetch. Team Skills intentionally has no automatic downgrade, mirror-adoption, or
history-adoption flag. A remote may move its default `HEAD` to a descendant branch; the next fetch
follows that current remote `HEAD` without relying on stale local tracking metadata.

Candidate validation requires regular, non-reparse lifecycle files for POSIX and Windows and a
successful native parser check before managed-clone advancement. Therefore a missing, linked, or
syntactically malformed self-update stays isolated as candidate Git state and is never selected as
the next session's managed runtime.

### A lock remains after interruption

Do not delete it while its recorded process is alive. A dead, well-formed lock becomes eligible for
conservative recovery after the stale interval. Malformed or unsafe lock state is intentionally not
stolen; inspect it and the containing instance before making a manual repair.
