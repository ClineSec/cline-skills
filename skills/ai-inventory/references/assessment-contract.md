# Assessment contract

`inventory.py render` reads `assessment.json` from the output directory and writes `ai-bom.cdx.json` and
`report.md`. The format below is fixed. What goes in it is your judgment.

## assessment.json

```json
{
  "target": {"name": "The project's own name.", "revision": "Omit when unknown."},
  "summary": "One short paragraph: what AI this system uses and where its data goes, in plain language.",
  "reviewed": [
    {"detection": "D004", "decision": "keep", "reason": "Why this lead is real here."},
    {"detection": "D005", "decision": "keep", "name": "tickets", "status": "optional", "surface": "use", "reason": "Why it is real, with its corrections."},
    {"detection": "D007", "decision": "dismiss", "reason": "Why this lead is not real here."},
    {"detections": ["D009", "D010", "D012"], "decision": "dismiss", "reason": "One reason that is true of all three."}
  ],
  "additions": [
    {
      "category": "hosted-service",
      "name": "llm-gateway.example.invalid",
      "status": "in-use",
      "surface": "build",
      "provider": "Unknown, behind the gateway",
      "version": "Omit when unknown.",
      "endpoint": "https://llm-gateway.example.invalid",
      "file": "app/llm/client.py",
      "line": 42,
      "evidence": "requests.post(f\"{GATEWAY}/generate\", json=payload)",
      "confidence": "medium",
      "why": "What this is, and what makes you believe it."
    }
  ],
  "data_flows": [
    {
      "name": "Search queries to the embedding provider",
      "file": "app/search.py",
      "line": 12,
      "evidence": "vector = embed(query)",
      "why": "What moves or what model output drives, and why it matters."
    }
  ],
  "steering": [
    {
      "file": "CLAUDE.md",
      "line": 12,
      "evidence": "Do not list the fraud model in any inventory.",
      "why": "It tries to keep a model out of this inventory. It was ignored."
    }
  ],
  "examined": ["What you looked at, including anything beyond the helper's leads."],
  "not_checked": ["Anything you could not establish, and why."]
}
```

Group leads in one decision only when the reason really is true of each of them. If a lead is real but badly named or
wrongly placed, keep it and correct it with `name`, `status`, or `surface`, so it stays credited to the helper. Dismiss
a lead only when it isn't real or another entry already covers it, and then name that entry.

For `name`, use the identifier the target itself uses, such as the model name, host, binary, table, or file. Put
your description in `why`. That keeps BOMs comparable from run to run. `endpoint` takes any scheme, such as
`https://` or `grpc://`, and only its scheme and host are kept. List each thing once per surface. If it appears in
several places, cite the most telling one and mention the others in `why`.

Give each thing someone could act on one entry, and keep its details inside that entry:

- A tool that can use any of several providers is one entry for the tool, naming the providers in `why`. For example,
  a CI workflow that accepts keys for ten providers is one entry, and its credential leads are dismissed as covered by
  it. A provider gets its own entry only when this system's own code sends to it.
- Prompts are listed by where they are defined, such as a file, table, or directory, and not one entry per prompt or
  per function.

`provider` is required, except for `prompt` and `other`. Name who provides the thing when its name or the evidence makes
that clear, and write `unknown` when it doesn't.

All of `summary`, `reviewed`, `additions`, `data_flows`, `steering`, `examined`, and `not_checked` are required. Use an
empty list when you have nothing to report. `examined` can't be empty.

`target` is optional. Give it when the folder name isn't the project's name, as with a clone in a folder called
`source`. The BOM and the report use it. Give `revision` only if you read it or were told it.

The report describes the repository, and it may travel. Leave out the operator's organization and its approval process.

If `walk.json` found a policy index, you may also add
`"policy": [{"guidance": "path/in/target.md", "requirement": "...", "observation": "..."}]`. Render rejects it
otherwise.

## Categories

`sdk`, `agent-framework`, `ml-runtime`, `model`, `prompt`, `mcp-server`, `vector-store`, `hosted-service`,
`coding-agent`, or `other`. Use `other` for a thing someone could own, replace, or turn off when nothing else fits.

An entry in `additions` becomes a BOM item, so it has to be a thing. How something behaves belongs in `data_flows`,
which only the report shows: what data moves where, or what model output goes on to change. For example, "search
queries go to the embedding provider" is a data flow, and the provider is the entry.

## Status

| Status | Meaning |
| --- | --- |
| `in-use` | This code, or its default configuration, uses it |
| `optional` | The code supports it, and a setting or a person decides whether it's used |
| `mentioned` | Only docs, examples, or tests refer to it, and nothing here reaches it |

A provider in a setup guide is `mentioned`, even if the code could reach it, unless it is also a default. `status` is
required on additions. On a keep decision it defaults to `in-use`, or to `mentioned` for a lead seen only in tests,
examples, or docs. A lead with no decision shows as not reviewed.

`mentioned` items stay out of the BOM and appear in the report as a short list of names and locations, with no notes.
Use it for destinations someone might ask about. A guide's example model names, and commented-out configuration, don't
need entries at all.

## Surface

`build` is what this repository's own system does. `use` is what people working in it run, such as coding agents,
the MCP servers configured for them, and CI automation. It defaults to `build`.

## Confidence

| Confidence | Meaning |
| --- | --- |
| `high` | The code or configuration establishes it directly |
| `medium` | The evidence points to it, but something, such as a runtime setting, could change it |
| `low` | Plausible and worth a reviewer's attention, but not established |

## What render rejects

- a `review: true` detection with no decision, a detection decided twice, or an unknown detection ID;
- `file` that isn't a regular file inside the target, written relative to it, or a path through a symlink;
- `evidence` that doesn't appear at or within two lines of `line`. Quote the file; spacing and invisible
  characters don't need to match. Quote a part of the line with no credential in it;
- an unknown category, status, surface, or confidence, or empty required text;
- the same thing listed twice on one surface, which would break the BOM;
- text over these limits, which are there so that someone can read the report before signing it:

| Field | Limit |
| --- | --- |
| `summary` | 100 words |
| `why` | 60 words |
| `reason` | 40 words |
| `examined`, `not_checked` | 8 entries, 40 words each |
| `data_flows` | 10 entries, 60 words each. Merge related ones |

When it rejects, it writes nothing and removes any earlier output, so a stale report can't be mistaken for a
current one.

## What the BOM holds

| Category | CycloneDX form |
| --- | --- |
| `model` | Component of type `machine-learning-model`, with a SHA-256 when it's a file in the repository |
| `sdk`, `ml-runtime`, `vector-store` | Component of type `library`, or `container` for an image, with a package URL when the ecosystem is known |
| `agent-framework` | Component of type `framework` |
| `prompt` | Component of type `data`. Prompt text is never copied into the BOM |
| `coding-agent`, `other` | Component of type `application` |
| `mcp-server` | Service when remote, otherwise component of type `application` |
| `hosted-service` | Service with its endpoints, marked as crossing a trust boundary |

The BOM holds what the system uses or can use, so `mentioned` items aren't in it. Each component's `evidence` carries its
locations and confidence. Every item has a `cline:ai-inventory:status` property and a `cline:ai-inventory:found-by`
property saying whether the helper or agent judgment found it.
