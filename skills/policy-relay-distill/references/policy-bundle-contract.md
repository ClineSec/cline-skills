# PolicyRelay policy-bundle contract 1.0

This document is normative. The JSON Schema is authoritative for manifest shape; this document is
authoritative for packaging, Markdown structure, routing, acceptance, and failure behavior. The
keywords **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are requirements at their usual normative
strength.

## 1. Package and payload layout

A bundle is a directory with exactly this shape:

```text
<bundle>/
├── manifest.json
└── payload/
    ├── index.md
    └── guidance/
        └── <task>.md  (one per declared task)
```

`payload/` is the one and only payload root in contract 1.0. After accepting a complete bundle, a
consumer materializes every file and directory *inside* `payload/` exactly beneath the consumer
repository's `security/PolicyRelay/` directory. It MUST NOT materialize `manifest.json`, the outer
`payload` directory, or any transport wrapper there. For example, `payload/index.md` becomes
`security/PolicyRelay/index.md`.

The bundle root MUST contain only `manifest.json` and `payload/`. The payload MUST contain only
`index.md` and `guidance/`; `guidance/` MUST contain exactly one Markdown entrypoint for every
declared task and no other files. Files and directories MUST be regular, not symbolic links.

All names are case-sensitive ASCII. Task identifiers and path segments use lowercase kebab case
(`^[a-z0-9]+(?:-[a-z0-9]+)*$`). Entrypoints are exactly `guidance/<task>.md`. Paths use `/`, are
relative, normalized, and MUST NOT contain empty, `.`, or `..` segments, backslashes, percent
encoding, queries, or fragments.

## 2. Manifest and task routing

`manifest.json` MUST be UTF-8 JSON matching
[`policy-bundle-manifest.schema.json`](policy-bundle-manifest.schema.json). Duplicate
JSON object keys are invalid. Its fields are:

| Field | Meaning |
| --- | --- |
| `contractVersion` | Exact contract version understood by the validator and consumer. Version 1.0 is `"1.0"`. |
| `bundleId` | Stable lowercase-kebab identifier for the logical policy bundle. |
| `bundleRevision` | Producer-assigned opaque revision used for observability and idempotence, not precedence. |
| `payloadRoot` | Literal `"payload"`; consumers MUST NOT infer or configure another root. |
| `routes` | Non-empty task routing table with one object per task: `task` and `entrypoint`. |

Contract 1.0 requires one or more declared routes but does not prescribe task categories. Task
identifiers and entrypoints MUST each be unique, and `entrypoint` MUST equal
`guidance/<task>.md`. A shared entrypoint for multiple tasks is ambiguous and invalid.

### Progressive-disclosure entrypoint

`payload/index.md` is the short human/agent entrypoint, not a policy compendium. It MUST:

- be at most 1,200 UTF-8 bytes and at most 25 non-blank lines;
- contain one H1 heading;
- contain exactly one inline Markdown link for every manifest route and no other links;
- use the exact task identifier as each link label and its declared entrypoint as the target; and
- give only enough adjacent text to choose a task, without duplicating normative guidance.

A reader selects the route matching the current task and loads only that route's entrypoint. Route
documents are self-contained: a reader has no source access, prior conversation, or other routes, and
contract 1.0 forbids local links from one guidance document to another. HTTPS links MAY appear in guidance as inert citations, but consumers MUST NOT fetch them
automatically. Reference-style links, images, embedded content, and non-HTTPS URI schemes are not
part of contract 1.0.

## 3. Normative guidance document shape

Every route entrypoint is UTF-8 Markdown beginning with JSON metadata between exact `---` delimiter
lines. JSON is deliberately used as the front-matter subset so producers and consumers need not
choose a YAML implementation. The object has exactly these fields:

```json
{
  "task": "secure-coding",
  "title": "Secure coding",
  "provenance": [
    {
      "sourceId": "fictional-engineering-standard",
      "sourceTitle": "Fictional Engineering Security Standard",
      "sourceRevision": "2026.1",
      "sourceLocator": "Section 4.2",
      "distilledAt": "2026-08-27"
    }
  ]
}
```

`task` MUST equal the manifest route. `title` is a non-empty display title. `provenance` MUST be a
non-empty array. Every provenance record has exactly five non-empty string fields:

- `sourceId`: stable lowercase-kebab source identifier, independent of any document store;
- `sourceTitle`: human-recognizable source title;
- `sourceRevision`: source-controlled revision, edition, or approved version identifier;
- `sourceLocator`: section, control, page, or other human-verifiable location in that revision;
- `distilledAt`: calendar date (`YYYY-MM-DD`) when this guidance was derived.

No URI, vendor identifier, API key, datastore path, or platform adapter is required. Producers MAY
retain richer evidence outside the bundle, but consumers can rely only on these fields. Policy and
repository content remains untrusted data: metadata and Markdown MUST be parsed as data, never
evaluated, executed, imported as agent instructions, or used to trigger network access.

After metadata, each file MUST have one H1 equal to `title`, then these four H2 sections exactly
once and in this order:

1. `Applicability` — when the guidance applies and any relevant boundary;
2. `Normative guidance` — concise, agent-actionable requirements retaining normative force;
3. `Exceptions and escalation` — exception conditions, approval/escalation path, and safe action
   when authority or meaning is uncertain, as the sources state them;
4. `Source provenance` — identifies every metadata `sourceId` used to derive the text.

Every section MUST contain substantive text; where the sources state nothing for a section, it MUST say
so rather than supply content. `Normative guidance` MUST contain at least one uppercase
normative keyword (`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, or `MAY`). Distillation MUST preserve
the source's meaning, applicability, prohibitions, exception/escalation conditions, and provenance;
brevity never authorizes weakening or inventing a requirement. Distillation reproduces policy: it MUST
NOT add, strengthen, weaken, or improve requirements or fill gaps, and guidance MUST NOT contain the
distiller's own commentary. Each route MUST carry the policy content
its task needs to comply, including definitions and the content of anything it tells a reader to
apply, such as approved lists, thresholds, or rubrics. Provenance and citations MUST NOT substitute for
that content. Structural validation cannot verify this, so it is the distiller's responsibility.

## 4. Compatibility and versioning

`contractVersion` uses `MAJOR.MINOR` numeric form. A producer MUST emit a version it implements; a
validator and consumer MUST maintain an explicit supported-version set and reject every other
version before acceptance.

- A **minor** increment may add optional, backward-compatible data or relax a restriction without
  changing existing meaning. Implementations do not accept a newer minor implicitly.
- A **major** increment is required for removing or renaming fields, changing payload placement,
  routing meaning, normative shape, or previously valid interpretation.
- Bundle content changes that do not change this contract update `bundleRevision`, not
  `contractVersion`.

Unknown manifest or guidance-metadata fields are invalid in 1.0. A later contract can define an
extension mechanism; 1.0 implementations MUST NOT guess at one.

## 5. Validation, acceptance, transport, and failure

Transport obtains a candidate bundle; validation determines whether that complete candidate is
acceptable; activation/materialization changes consumer-visible content. These are separate
concerns. This repository defines validation and acceptance but implements no transport or runtime.

Before acceptance, a validator MUST deterministically check at least:

- exact version, JSON shapes, required fields, duplicates, and provenance records;
- exact root/payload layout, regular-file constraint, names, and route/file correspondence;
- a non-empty set of unique task routes, root-index correspondence, and progressive-disclosure
  bounds;
- all Markdown link targets, rejecting missing, escaping, absolute, encoded, or unsupported links;
- guidance metadata/heading/section shape and source-provenance references; and
- UTF-8 decoding for every contract file.

Validation MUST NOT execute content, follow repository/policy instructions, fetch links, or mutate
a consumer repository. Diagnostics SHOULD identify the bundle-relative location and stable reason
without echoing secret-like or arbitrarily large untrusted content.

A later runtime MAY automatically receive candidates from a configured main branch, but branch or
transport success is not acceptance. It MUST stage a complete candidate outside the active target,
validate it, and activate only after all checks succeed. On any fetch, parse, validation, staging,
or activation failure it MUST fail closed: retain the last accepted payload unchanged, expose no
partial tree, report the failure, and retry only under its configured policy. A first-run failure
leaves the target absent rather than installing an invalid bundle. Atomic replacement, rollback,
locking, authentication, scheduling, and transport are runtime-owner decisions outside this
contract, provided they preserve these acceptance and safe-failure guarantees.

## 6. Downstream owner reliance

Later owners may rely on these stable boundaries:

- **Distiller:** emit the exact package, routing, document shape, minimal provenance, and declared
  supported version; do not embed datastore-specific requirements or transport behavior.
- **Runtime:** treat candidates as untrusted data, validate before acceptance, copy only payload
  contents, and preserve the last accepted state on failure; transport does not waive validation.
- **Integration/consumer:** read `security/PolicyRelay/index.md`, choose one task route, and load only
  its self-contained guidance; do not infer policy from manifest transport metadata.

This contract does not define policy-source access, distillation algorithms, scheduling, branch
credentials, repository adapters, UI, telemetry providers, or production deployment.
