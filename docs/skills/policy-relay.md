# PolicyRelay

PolicyRelay keeps agents working from your current security guidance. It distills policy documents
into short task-specific guidance, stores that in a Git repository, and syncs it into each consumer
repository at the start of every agent session. Agents read a small index and load only the guidance
their task needs.

```text
Policy documents
   │  policy-relay-distill: interview, preview, confirm, one local commit
   ▼
Policy repository   bundle/manifest.json + bundle/payload/
   │  .policyrelay/session-start: clone, validate, swap in atomically
   ▼
Consumer repository   security/PolicyRelay/index.md + guidance/<task>.md
   │  AGENTS.md and CLAUDE.md tell agents to sync, then read the index
   ▼
Agent loads only the guidance for its task
```

## What lives where

| Piece | Location | Who needs it |
| --- | --- | --- |
| [`policy-relay-distill`](policy-relay-distill.md) | This catalog | Whoever maintains policy |
| [`init-policy-relay`](init-policy-relay.md) | This catalog | Whoever sets up a repository |
| Policy bundle | Your own policy repository, usually private | Consumer repositories read it |
| Session-start runtime | Copied into each consumer's `.policyrelay/` | Anyone working in that repository |

The runtime is copied so a repository keeps working for people who never installed this catalog.
The same copy means catalog updates do not change installed repositories; re-run install to upgrade.

The installed runtime carries its own validator, and the Distiller skill carries the authoritative
contract validator, because a skill must be self-contained. A parity test keeps the two aligned.

## Requirements

Python 3.10 or newer and Git on macOS or Linux, with no third-party packages. Private HTTPS
upstreams need Git 2.31 or newer. Native Windows is not supported, because safe bundle updates rely
on atomic directory exchange in the macOS and Linux kernels. Both skills stop with a clear error
there.

## Security model

PolicyRelay treats bundles as untrusted data. Nothing in a bundle is executed, a bad bundle leaves
the last accepted guidance byte for byte intact, and diagnostics do not echo bundle content, Git
output, or upstream locations.

Session start ignores user Git configuration, so `url.*.insteadOf`, `core.sshCommand`, and hook
settings cannot redirect or run anything. The one exception is `credential.*`, read from user and
system configuration for HTTPS upstreams so private repositories work. Consumer repository
configuration can never supply a credential helper.

### Known limitations

- **Upstream authenticity:** bundles are validated but not signed. Anyone who can write to the
  policy branch, or control its transport, controls the guidance agents receive. Use a private
  repository, branch protection, and HTTPS or SSH.
- **Consumer integrity:** anyone with write access to a consumer repository can change its installed
  runtime and instructions, and a sync will not detect that. Synced guidance itself is repaired.
  Review `.policyrelay/` changes like code.
- **No enforcement:** agents run session start because instructions tell them to. There is no hook,
  and synced guidance is advice rather than a control.
- **Fail-closed availability:** the installed instructions tell agents to stop when a sync fails,
  including when offline, even though the last accepted copy is still on disk.
- **Catalog trust:** this catalog's opt-in auto-update runs code from its default branch on enrolled
  machines. See [the security review](../security-review.md).

## Testing

The suite under `tests/policy_relay/` needs no network or credentials, and runs with the rest of the
catalog's tests:

```sh
python3 -m unittest discover -s tests -v
```

`tests/policy_relay/live_e2e.py` is a separate, manual proof against a real private repository and,
optionally, real agent CLIs. It pushes to the upstream you name, so use a disposable repository:

```sh
python3 tests/policy_relay/live_e2e.py --upstream https://github.com/YOUR-ORG/policy-relay-e2e.git
python3 tests/policy_relay/live_e2e.py --upstream git@github.com:YOUR-ORG/policy-relay-e2e.git \
  --agents claude,codex,cursor
```

With agents, it also checks that a route can be followed with only the bundle: one session distills
a policy whose approved list sits in a second source, and a fresh session answers questions from the
result, including one the policy leaves open. That can't be checked by a script, so this is the only test of it. To run just that stage,
which pushes nothing:

```sh
python3 tests/policy_relay/live_e2e.py --sufficiency-only --agents claude,codex
```
