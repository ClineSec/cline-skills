# skill-creator

Creates or revises a portable skill in a catalog, using only the features Claude Code, Codex, and
Cursor have in common.

## Before you start

- A local checkout of the catalog you want to change. Don't work in an installed copy.
- Python 3.9 or newer.

## Run it

Ask your agent from the catalog's checkout:

> Use skill-creator to add a skill that reviews database migrations before they run.

## What it does

The agent chooses a name and a description that says when the skill should activate, drafts the
instructions, and scaffolds `skills/<name>/`. It adds `scripts/`, `references/`, or `assets/` only when
the workflow needs them. It then runs the catalog's validator and tests.

## What to do next

Review the skill for usefulness as well as format, then commit it. In this catalog, also add its
[usage guide](README.md#adding-a-guide). See [the authoring guide](../skill-authoring.md) for the
full rules.
