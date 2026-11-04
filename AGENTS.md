# Cline Skills contributor guidance

Cline Skills is a catalog of user-global Agent Skills for Claude Code, Codex, and Cursor, installed
and updated by tooling from Team Skills. Keep canonical skills portable: store each one at
`skills/<name>/SKILL.md`, make the frontmatter `name` exactly match its parent directory, and use
only the common Agent Skills
contract documented in `docs/skill-authoring.md`.

- Keep `README.md` lean: what this is, how to install it, and where the docs are. Put usage for
  a skill in `docs/skills/<name>.md` and list it in `docs/skills/README.md`.
- Preserve independent forks. Never hardcode this repository's host, owner, or URL in operational
  code. A URL may bootstrap the initial clone; every later fetch or update must use that clone's
  configured `origin`.
- Preserve unrelated user skills and configuration. Follow `docs/catalog-contract.md`: the default
  prefix is blank, an unprefixed collision warns and skips successfully, and a nonblank prefix uses
  a generated directory with matching folder and frontmatter names.
- Keep product-specific metadata and behavior out of canonical skills unless all three products
  can safely ignore it. Prefer relative references and standard-library, cross-platform helpers.
- This repository uses direct commits to `main`. Run `python3 scripts/validate.py` and
  `python3 -m unittest discover -s tests -v` before committing, then push to `origin/main`.
- Keep installer, updater, lifecycle-hook, test-fixture, release, and publishing changes within the
  ticket's explicit scope. Never test runtime changes against a real user profile.
