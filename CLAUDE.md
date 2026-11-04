# Claude Code guidance

Follow `AGENTS.md` and the contracts it links. In particular, author canonical skills only under
`skills/<name>/SKILL.md` using the portable Claude Code/Codex/Cursor subset; keep the folder and
frontmatter names identical; preserve fork portability; and derive future operational updates from
the local clone's configured `origin`, never a baked-in upstream URL.

The catalog prefix is blank by default. Existing unprefixed installations win collisions, which
must produce a visible warning, skip the new skill, preserve existing state, and still succeed.
Nonblank prefixes require a generated view with matching directory and rewritten `name`; renaming
a symlink is invalid. Work directly on `main`, validate before committing, and use only disposable
homes, state roots, skill roots, hook files, and local origins for runtime tests.
