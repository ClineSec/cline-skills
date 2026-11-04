# Catalog contract v1

This document is normative for catalog validation, installation, updating, and removal. “Must”
describes behavior that operational code and its tests preserve.

## Canonical repository

A catalog root contains `catalog.json` and the `skills/` directory named by its manifest. Each
immediate child of `skills/` is one canonical Agent Skill. Canonical skill directories and files
must be ordinary in-repository paths, not symlinks, so a fork is self-contained.

`catalog.json` has these v1 fields:

| Field | Contract |
| --- | --- |
| `$schema` | Exactly `./schemas/catalog.schema.json`. |
| `schema_version` | Integer `1`. Unknown versions must fail closed before mutation. |
| `catalog_id` | Portable kebab-case label, at most 64 characters. It is not globally unique. |
| `display_name` | Nonempty human-facing label, at most 128 characters. |
| `skills_directory` | Exactly `skills` in v1. |
| `default_prefix` | Blank by default, or a kebab-case prefix without a trailing separator. |

Unknown manifest fields fail validation in v1. Extensions require a schema-version change rather
than being guessed by older operational code. The lifecycle utilities accept ordinary JSON
formatting and escapes, but reject invalid UTF-8, decoded duplicate or case-colliding keys,
documents larger than 1 MiB, and nesting beyond 64 container levels before interpreting fields.

## Catalog instance identity

Forks may retain the same manifest. Therefore `catalog_id` alone must never identify installed
state. During initial installation, the installer must:

1. clone the explicitly supplied bootstrap URL;
2. read the clone's configured fetch URL with the equivalent of
   `git -C <clone> remote get-url origin`;
3. compute an opaque instance key from `catalog_id` plus a cryptographic digest of that exact
   configured-origin value; and
4. use that key for the clone and catalog-owned state.

Different configured origins are independent catalogs even if their manifests match. The origin
value is untrusted input: do not execute it, interpolate it into shell source, or expose embedded
credentials in logs. Its initial digest remains bound to the instance key. A later `origin` change
must fail closed even when the replacement is a fast-forward mirror; remove the old instance with
its original bootstrap selector and install the new origin explicitly. Each fetch resolves the
remote's current `HEAD` rather than trusting a possibly stale local `origin/HEAD`, and that commit
must remain a fast-forward from the managed revision.

Repository URLs are allowed only at initial bootstrap boundaries and in explanatory documentation.
Every fetch, pull, status check, or recovery operation after cloning must derive its remote from
the clone's currently configured and instance-bound `origin`. Operational code must not contain an
embedded repository owner, hosting service, or other fallback source.

The state-root layout and digest encoding are documented in `docs/operations.md`. They must remain
deterministic, credential-safe, collision-resistant, and work on macOS, Linux, native Windows, and
WSL.

## Effective skill names

The installation prefix is either the caller's explicit choice or `default_prefix`. Blank is the
ordinary default.

- Blank prefix: the effective name of `example-skill` is `example-skill`.
- Prefix `acme`: the effective name is `acme-example-skill`.

The prefix and resulting effective name must satisfy the Agent Skills name grammar and the result
must be at most 64 characters. Invalid or overlong combinations must fail before changing user
state.

## Blank-prefix view and collisions

With a blank prefix, the installer may expose a canonical skill through a direct directory
symlink where a product supports it. It must never replace a pre-existing destination it does not
already own for the same catalog instance.

If an effective name is already occupied by another catalog or an unrelated user skill:

1. the existing installation wins and remains byte-for-byte untouched;
2. the incoming skill is skipped for that destination;
3. a visible warning identifies the incoming catalog, skill name, and conflicting destination
   without leaking credentials; and
4. the overall operation returns success unless a separate fatal error occurred.

A warning-and-skip collision is expected coexistence, not partial failure. Repeated runs must make
the same decision and must not accumulate alternate names or stale temporary paths.

## Nonblank-prefix generated view

Renaming a symlink is not portable because its target still declares the original frontmatter
name. For every nonblank prefix, the installer must materialize a catalog-owned generated view:

```text
generated/<prefix>/acme-example-skill/
├── SKILL.md       # frontmatter contains: name: acme-example-skill
├── scripts/       # copied with relative layout preserved, when present
├── references/    # copied with relative layout preserved, when present
└── assets/        # copied with relative layout preserved, when present
```

The generated directory name and `SKILL.md` `name` must both equal the effective name. Generation
must preserve the canonical `SKILL.md` body, all other portable frontmatter, resource contents,
permissions needed for executable helpers, and relative paths. It must not modify the canonical
source. The complete view must validate before it can replace the previous catalog-owned view;
failed generation retains the last known-good view.

Generated output is state, not authored catalog content, and must not be committed. Its location
and atomic replacement mechanism follow the owned generation layout in `docs/operations.md`.

## Ownership and safe failure

Lifecycle code may mutate only paths recorded as owned by its catalog instance. It must not
delete or overwrite unrelated skills, other catalog clones/views/state, or existing product hook
configuration. It edits product hook files only for an explicit `--setup-auto-update` or
`--remove-auto-update` request, or to remove a catalog's own entries with its final prefix. Unsupported schemas, malformed skills, invalid paths, failed fetches, failed view
generation, and interrupted updates must fail safely while retaining the last known-good installed
skills. Collision warning-and-skip is the sole success-path exception described by this contract.
