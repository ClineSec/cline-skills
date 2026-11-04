# init-policy-relay

Connects one repository to a policy repository. Afterward, agents working in that repository sync
your guidance at the start of each session and load only what their task needs.

Use this once per repository, and again to upgrade or repoint it. To write or change the policy
itself, use [`policy-relay-distill`](policy-relay-distill.md). For how the pieces fit together, see
the [PolicyRelay overview](policy-relay.md).

## Before you start

- Python 3.10 or newer and Git, on macOS or Linux.
- A policy repository containing a `bundle/` directory, which `policy-relay-distill` creates.
- Access to that repository from this machine. Anyone working in the connected repository needs
  access too, through their own Git credentials or SSH setup.

## Run it

Ask your agent from the repository you want to connect:

> Init policy relay here, using the policy repository at `git@github.com:your-org/your-policy.git`,
> branch `main`.

These location forms work: `https://host/org/repo.git`, `git@host:org/repo.git`,
`ssh://git@host/org/repo.git`, `file:///absolute/path`, or an absolute local path. Don't use a URL
containing a password or token, because it will be refused.

## What it asks

- Which repository to connect, if that isn't clear.
- The policy repository's location and branch.
- Whether to commit the synced guidance. Ignoring it is recommended, since the policy repository
  remains the record and every session refreshes the copy.

## What it changes

| Path | What it is |
| --- | --- |
| `.policyrelay/` | Configuration, launcher, and a copy of the sync runtime |
| `AGENTS.md`, `CLAUDE.md` | One marked block telling agents to sync and then read the index; everything else is preserved |
| `security/PolicyRelay/` | The synced guidance, replaced as a whole on each sync |
| `security/.PolicyRelay.lock` | A lock file used during sync |

It doesn't commit or push. The agent proposes the Git change and waits for you to confirm it.

Committing `.policyrelay/` gives teammates the same setup when they clone, without needing this
catalog. It also records the policy repository's location, so anyone who can read this repository
can see that location.

## What happens next

Each agent session runs `./.policyrelay/session-start` before doing repository work, then reads
`security/PolicyRelay/index.md` and loads the guidance for its task. You can run the same command
yourself to check that a sync works. It prints one line:

```text
OK status=activated bundleId=your-policy revision=sha256-... routes=5
```

If a sync fails, it prints a phase and code, leaves the last good guidance in place, and agents are
told to stop until it works. The [skill instructions](../../skills/init-policy-relay/SKILL.md) list
what each code means. Read the [known limitations](policy-relay.md#known-limitations) before relying
on this.

## Upgrade, repoint, or remove

- **Upgrade:** ask your agent to run this skill again. Updating the catalog doesn't change repositories
  that are already connected, so each one upgrades only when you do this.
- **Repoint:** run the skill again with the new location or branch.
- **Remove:** there's no uninstall command. Delete `.policyrelay/` and `security/PolicyRelay/`, and
  remove the marked block from `AGENTS.md` and `CLAUDE.md`.
