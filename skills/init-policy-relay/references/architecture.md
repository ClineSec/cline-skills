# Architecture and safety invariants

## Installation boundary

`install(consumer_root, upstream, branch)` requires an existing real consumer directory. It rejects
credential-bearing or unsupported transport locations, invalid branch names, instruction-file
symlinks, ambiguous managed markers, and a conflicting `.policyrelay/` layout. Configuration is a
bounded canonical JSON document containing only `schemaVersion`, `upstream`, and `branch`.

The installer builds a fixed local runtime, launcher, and configuration in private staging. It
atomically activates that directory and atomically replaces only the marked PolicyRelay blocks in
`AGENTS.md` and `CLAUDE.md`. Existing bytes outside an unambiguous block are preserved. A transition
failure restores the prior runtime/configuration and both complete instruction files; a first-install
failure removes all installed assets. Reinstallation is byte-idempotent and unknown files under
`.policyrelay/` are rejected rather than deleted.

The managed block contains stable routing only: run `./.policyrelay/session-start`, stop if it fails,
then consult `security/PolicyRelay/index.md` and load only relevant routes. It contains no policy
text, upstream location, credentials, Git output, revision, or other volatile bundle state.

## Session-start acquisition

`session_start(consumer_root)` loads and revalidates the bounded local configuration. Git runs with
no shell, no prompt, no inherited system/global/config-parameter settings, a restricted
`file:https:ssh` protocol set, disabled hooks, and captured output that is never rendered. It makes a
single-branch, depth-one, non-local clone in a mode-0700 temporary directory. Neither the upstream
nor consumer receives a remote, commit, checkout, push, or Git configuration change.

Private upstreams keep that isolation with one narrow exception. For an `https` upstream only, the
operator's `credential.*` settings are read from system and user configuration and passed to the
clone through `GIT_CONFIG_*` environment variables, never argv. They are read from a private empty
directory with no inherited `GIT_*` variables, so a consumer repository cannot supply a credential
helper. Settings that cannot be bounded forward nothing, and the clone then fails closed. No other
user configuration is inherited, including `url.*.insteadOf`, `core.sshCommand`, and
`core.hooksPath`. SSH upstreams, as `ssh://` or `user@host:path`, use the operator's `ssh`
configuration and agent and receive no credential settings. Forwarding requires Git 2.31 or newer.

Only the real `checkout/bundle/` directory is passed to the synchronization core. Checkout wrapper
files and `.git/` metadata remain private acquisition artifacts and are never activated in the
consumer. Missing sources/branches, clone errors, timeouts, missing/non-directory bundles, invalid
configuration, and core rejection all report bounded phase/code errors and preserve the prior tree.

## Synchronization transaction

The public boundary accepts two explicit local directories: a candidate bundle and a consumer
repository root. Content is always treated as inert bytes or parsed JSON/Markdown data. Nothing in
a candidate is executed, imported, fetched, or used as an instruction.

1. Reject a symbolic-link/non-directory consumer root, `security/`, or managed target, then acquire
   the persistent `security/.PolicyRelay.lock`.
2. Copy the complete candidate through no-follow file descriptors into a private staging directory
   beside (never inside) the active target. Only regular files and real directories can be copied.
3. Validate that immutable snapshot against contract 1.0: exact layout/version/routes; duplicate-free
   JSON; index bounds and correspondence; guidance metadata, headings, sections, and provenance;
   UTF-8; and link/path safety.
4. Copy only staged `payload/` contents into a separate next-tree. `manifest.json` and the outer
   `payload/` directory can never enter the managed target.
5. If the next-tree digest equals the active tree, return `unchanged`. Otherwise, atomically rename
   it into an absent target or atomically exchange it with an existing target. The old tree remains
   available under the private next-tree name until the commit is durable. A detected post-commit
   error swaps/renames it back before reporting failure.
6. Remove private staging names. Cleanup occurs after rollback or successful commit and never
   deletes through candidate links.

Atomic directory exchange uses Darwin `renamex_np(RENAME_SWAP)` or Linux
`renameat2(RENAME_EXCHANGE)`. A first activation needs only standard atomic rename. An update fails
closed on an OS/filesystem without exchange support; it does not use a non-atomic remove/rename
fallback.

## Boundaries and limitations

- Supported bundle contract versions are explicitly limited to `1.0`.
- This is a local, single-host core for macOS/Linux. It assumes the consumer filesystem honors the
  platform's atomic rename/exchange and advisory lock operations.
- The lock coordinates PolicyRelay writers. A separate process deliberately mutating the same
  private staging names or managed target outside this protocol is outside the locking boundary.
- Git is required at session start. Remote acquisition is implemented, but the test/evidence suite
  performs no network access and uses only temporary local repositories.
- PolicyRelay installs a session-start command, not an automatic process hook, daemon, scheduler,
  retry service, or deployment integration. Agents run it because the installed instructions say to.
