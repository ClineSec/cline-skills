# Skills

Usage guides for the skills in this catalog.

| Skill | Use it to |
| --- | --- |
| [`agent-config-integrity`](agent-config-integrity.md) | Assess a repository's agent config without executing it |
| [`ai-inventory`](ai-inventory.md) | Inventory a repository's AI as a CycloneDX AI-BOM |
| [`init-policy-relay`](init-policy-relay.md) | Connect a repository to a policy repository |
| [`mcp-preflight`](mcp-preflight.md) | Decide whether it's safe for a team to use an MCP server, before it connects |
| [`policy-relay-distill`](policy-relay-distill.md) | Turn policy documents into guidance and commit it |
| [`security-review`](security-review.md) | Review a repository or release and produce a report a person signs |
| [`skill-creator`](skill-creator.md) | Create or revise a skill in a catalog |
| [`threat-model`](threat-model.md) | Threat model a system by discovery, and produce a report a person signs |
| [`tprm-review`](tprm-review.md) | Research a vendor from its documents and the public record, and produce a report a person signs |

Skills that work together can share an overview: see [PolicyRelay](policy-relay.md).

## Adding a guide

Every skill needs a guide at `docs/skills/<skill-name>.md`, listed in the table above. A test enforces
both. Write it for the person using the skill:

- what the skill is for, and when to use something else;
- what you need before you start;
- how to run it, with an example request;
- what it will ask you and what it changes;
- what to do next.

The skill's `SKILL.md` remains the agent's instructions. Guides explain the skill to people and link
to `SKILL.md` rather than repeating it.
