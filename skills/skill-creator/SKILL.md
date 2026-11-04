---
name: skill-creator
description: Create or revise portable skills in a skills catalog. Use when adding a reusable skill, changing skill instructions or resources, or checking cross-agent compatibility for Claude Code, Codex, and Cursor.
---

# Create portable catalog skills

Work in the skills catalog that the user placed in scope. Find its root by locating
`catalog.json`; do not edit an installed generated view or a different catalog clone.

Before authoring, read `docs/skill-authoring.md` and `docs/catalog-contract.md` from that catalog.
Treat product-native skill creators as optional drafting aids. The catalog contract and its
validator are authoritative.

Choose a narrow kebab-case name and a description that states both capability and activation
conditions. Draft a complete Markdown body before scaffolding. Keep the instructions product
neutral, use relative resource paths, and add only `scripts/`, `references/`, or `assets/` that the
workflow needs.

To create a new skill without relying on a native creator, run this skill's bundled helper with an
absolute path to the catalog and a finished body file:

```text
python3 <this-skill-directory>/scripts/create_skill.py <name> --catalog-root <catalog-root> --description <description> --body-file <draft-markdown> [--resources scripts,references,assets]
```

Replace angle-bracket values with separate command arguments; do not execute the example
literally. The helper validates inputs, refuses to overwrite a skill, writes through a temporary
directory, and creates only the requested resource directories. If revising an existing skill,
edit it in place rather than re-running the scaffold.

If the catalog has a `docs/skills/` directory, add usage instructions for the skill at
`docs/skills/<name>.md` and list it in `docs/skills/README.md`.

Finish by running these commands from the catalog root and resolving every failure:

```text
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

Review the result for actual usefulness as well as format: concise discovery metadata, no
product-only semantics, no hidden expansion of the user's authority, and progressive disclosure
for substantial conditional material.
