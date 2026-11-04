# Cline Skills

Open-source [Agent Skills](https://agentskills.io/specification) for Claude Code, Codex, and Cursor,
from Cline Technologies. A skill is a packaged set of instructions and helper scripts that an agent
loads when a task calls for it. Install this catalog once, and its skills are available in every
project on your machine.

## Skills

| Skill | What it does |
| --- | --- |
| [`agent-config-integrity`](docs/skills/agent-config-integrity.md) | Assesses the agent, MCP, hook, and permission config in a repository without executing any of it, and ends in a report a person signs |
| [`ai-inventory`](docs/skills/ai-inventory.md) | Finds the AI in a repository and writes it down as a CycloneDX AI-BOM, with a report a person signs |
| [`init-policy-relay`](docs/skills/init-policy-relay.md) | Connects a repository to a policy repository, so agents sync security guidance at session start and load only what each task needs |
| [`mcp-preflight`](docs/skills/mcp-preflight.md) | Answers whether it's safe for a team to use an MCP server before it connects, from whatever evidence exists, and ends in a verdict with conditions that a person signs |
| [`policy-relay-distill`](docs/skills/policy-relay-distill.md) | Distills policy documents into that guidance and commits it to a policy repository |
| [`security-review`](docs/skills/security-review.md) | Reviews a repository or release for what someone could do to it, from outside the repository and without running it, and ends in a report a person signs |
| [`skill-creator`](docs/skills/skill-creator.md) | Creates or revises portable skills in a catalog |
| [`threat-model`](docs/skills/threat-model.md) | Builds a threat model by discovery instead of an interview, read-only, with a color-coded architecture diagram and a report a person signs |
| [`tprm-review`](docs/skills/tprm-review.md) | Researches a vendor from the documents you downloaded and the public record, reports where its account doesn't hold together, and ends in a report a person signs |

Each skill has its own usage guide. The two PolicyRelay skills work together, so start with the
[PolicyRelay overview](docs/skills/policy-relay.md).

## Install

You need Git. On macOS, Linux, or WSL:

```sh
curl -fsSL https://raw.githubusercontent.com/ClineSec/cline-skills/main/scripts/team-skills.sh \
  | sh -s -- install https://github.com/ClineSec/cline-skills.git
```

On Windows, in PowerShell:

```powershell
$installer = Invoke-RestMethod https://raw.githubusercontent.com/ClineSec/cline-skills/main/scripts/team-skills.ps1
& ([scriptblock]::Create($installer)) install https://github.com/ClineSec/cline-skills.git
```

Review downloaded scripts before running them if your security policy requires it. Then start a new
agent session and ask for what you need, such as "init policy relay". Some skills have their own
requirements, listed in their guides.

Skills stay at the installed version until you update. To update, run the install command again. To
update automatically at session start, add `--setup-auto-update` (`-SetupAutoUpdate` on Windows),
which runs code from this repository's default branch on your machine.

## Documentation

- [Skills](docs/skills/README.md): usage guides for each skill
- [Installation and updates](docs/installation.md): automatic updates, prefixes, removal, forks, and
  managed macOS deployment
- [Operations and troubleshooting](docs/operations.md): how installs work and how to fix them
- [Writing skills](docs/skill-authoring.md): authoring, validating, and curating a catalog
- [Catalog contract](docs/catalog-contract.md) and [security review](docs/security-review.md)

## License

Licensed under the [MIT License](LICENSE). The CycloneDX schemas in
[`tests/fixtures/cyclonedx-1.6/`](tests/fixtures/cyclonedx-1.6/) keep their own Apache-2.0 license.
