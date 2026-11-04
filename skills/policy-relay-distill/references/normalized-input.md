# Normalized policy input

The engine accepts one UTF-8 JSON object matching
[`normalized-policy-input.schema.json`](normalized-policy-input.schema.json).
Runtime validation is deliberately stricter than JSON Schema where uniqueness, cross-references,
canonical ordering, and ambiguity require whole-document checks.

Each route is a complete unit. `applicability` and `exceptionsAndEscalation` contain plain-text
statements with one or more `sourceIds`. `normativeRequirements` adds a separate `force` field; its
text must not repeat an uppercase normative keyword. `provenance` declares the exact five-field
record for each source referenced by route text. Every declaration must be used, and every
reference must be declared.

Arrays are mathematical sets for transformation purposes. Reordering them never changes output;
exact duplicates are rejected rather than silently collapsed. Incompatible positive and negative
force pairs are contradictory and rejected (`MUST`/`MUST NOT`, `MUST`/`SHOULD NOT`,
`SHOULD`/`MUST NOT`, `SHOULD`/`SHOULD NOT`, and `MAY`/`MUST NOT`). Compatible redundancy remains
explicit rather than being silently collapsed; in particular, permission (`MAY`) can coexist with
a negative recommendation (`SHOULD NOT`). Task IDs and source IDs are lowercase kebab case. Route
titles are restricted to safe single-line display text. All other source strings are normalized to
single-space runs and rendered as inert text or JSON data.

## Adapter responsibilities

The interactive workflow keeps authentication, source retrieval, approval-state interpretation,
source format parsing, and platform identifiers behind its generic `AuthorizedSourceAccess`
boundary. Its mapper accepts only already-authorized inert document envelopes plus separately
confirmed normalization decisions. Before invoking the engine it must:

1. decide task applicability from the authorized source without inventing a route;
2. preserve each requirement's exact normative force and prohibition;
3. carry exception conditions, escalation authority, and any safe uncertain action as the sources state
   them, without supplying what they don't;
4. carry the content each route needs to be followed with only the bundle, including definitions and
   any lists, thresholds, or rubrics it applies;
5. attach every statement to one or more exact provenance records; and
6. reject conflicting source meaning, passages it can't restate with confidence, and references to
   content outside the authorized sources. Vague or silent policy isn't rejected; it carries through.

The adapter then serializes only the normalized model. Untrusted source text cannot select files,
versions, routes, commands, imports, tools, network actions, or output paths. The engine validates
the entire candidate and either returns a complete in-memory file map or raises
`DistillationError`. For the source envelope and mapping, see
[input-boundary.md](input-boundary.md).
