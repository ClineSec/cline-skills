# Portable skill authoring

Canonical catalog skills target the common Agent Skills behavior supported by Claude Code, Codex,
and Cursor. Product-native creators can help draft content, but they are neither required nor the
authority for this repository; the bundled `skills/skill-creator` workflow and repository validator
enforce the catalog contract.

## Required layout and frontmatter

Store every skill directly at `skills/<name>/SKILL.md`. The name must be 1-64 ASCII lowercase
letters, digits, and single hyphens; it cannot begin or end with a hyphen. The frontmatter `name`
must exactly equal `<name>`.

Use this conservative portable frontmatter subset:

```yaml
---
name: example-skill
description: State what the skill does and the concrete requests that should activate it.
---
```

The repository validator accepts the standard `license`, `compatibility`, and string-valued
`metadata` fields when needed. Keep `name` and `description` as single-line scalars. Do not add
product-only fields such as Cursor `paths` or `disable-model-invocation`, Codex `agents/openai.yaml`
invocation policy, Claude dynamic command injection, or the experimental `allowed-tools` field to
canonical skills. Those can change semantics or permissions across clients.

Descriptions must be nonempty, at most 1024 characters, and say both what the skill does and when
to use it. Instructions must be nonempty Markdown. Keep `SKILL.md` focused; put conditional detail
in `references/`, repeatable deterministic helpers in `scripts/`, and output material in `assets/`.
Reference bundled files with paths relative to the skill root and avoid deep reference chains.

## Authoring workflow

1. Start from a user request and decide a narrow name, activation description, and useful body.
2. Invoke the bundled `skill-creator`, or run its scaffold helper from the catalog root. The helper
   requires a finished Markdown body and refuses invalid names or existing destinations.
3. Add only supporting resources that materially improve the workflow. Helpers should be
   self-contained, handle errors clearly, and avoid assumptions about a particular shell or agent.
4. Run `python3 scripts/validate.py` and the unit tests from the repository root.
5. Review that the skill preserves user intent and authority and remains useful in all three tools.
6. Add usage instructions at `docs/skills/<name>.md` and list the skill in
   [the skills index](skills/README.md). A test requires both.

Canonical skills may not be symlinks. This keeps clones and forks complete. Installation views are
separate generated state governed by `docs/catalog-contract.md`.

## Validate

Python 3.9 or newer is used for repository validation and tests, not by the installers. The
PolicyRelay tests skip themselves below Python 3.10 and on native Windows:

```sh
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

## Format references

The canonical format follows the primary documentation reviewed on 2026-08-29:

- [Agent Skills specification](https://agentskills.io/specification)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Codex skills](https://developers.openai.com/codex/skills)
- [Cursor Agent Skills](https://cursor.com/docs/skills)
