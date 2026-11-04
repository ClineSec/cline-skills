# Model contract

`threat-model.json` lives in the working folder and grows during the run. `diagram` needs only `zones`, `components`, and `flows`,
and uses `threats` if present, so you can draw from the first draft. `render` needs every top-level field below. The sections,
their order, the rating scale, and the threat numbers come from the helper, so only the content changes from run to run.

Ids are your own short names, such as `C1`. The report renumbers threats and unknowns by rank. A list may be empty unless
noted here.

```json
{
  "target": "The system's name.",
  "intake": {
    "started_from": "What you were pointed at.",
    "stage": "existing",
    "gaps": "best-effort",
    "unattended": false
  },
  "system": {
    "what_it_does": "What this system is, in a sentence or two.",
    "worth_protecting": "The data, money, access, or trust at stake."
  },
  "summary": "One short paragraph: what could realistically go wrong, in plain language.",
  "sources": [
    {"id": "S1", "name": "orders-api repository", "kind": "repo", "status": "used", "repo": "orders-api", "read": "Service code and deployment definitions.", "link": "https://code.example/orders-api/blob/COMMIT/{file}#L{line}"},
    {"id": "S2", "name": "Production account", "kind": "live", "status": "used", "observed": "2026-11-03", "read": "Network and identity configuration for this service."},
    {"id": "S3", "name": "Payments provider console", "kind": "other", "status": "not-reachable", "note": "This session has no access to it."}
  ],
  "confirmations": [
    {"action": "Read one row from the orders table to see its shape.", "why_risky": "It holds customer data.", "decision": "declined"}
  ],
  "zones": [
    {"id": "Z1", "name": "Internet", "trust": "Anyone. Nothing here is authenticated.", "trust_level": "low"},
    {"id": "Z2", "name": "Production network", "trust": "Only deployed services, behind the load balancer.", "trust_level": "high"}
  ],
  "components": [
    {"id": "C1", "name": "Customer", "type": "actor", "zone": "Z1", "basis": "inferred", "reasoning": "The API serves public clients."},
    {
      "id": "C2",
      "name": "Orders API",
      "type": "process",
      "zone": "Z2",
      "basis": "observed",
      "sources": ["S1", "S2"],
      "metadata": {"runs on": "Container service", "auth": "Session token"}
    },
    {
      "id": "C3",
      "name": "Refund worker",
      "type": "process",
      "zone": "Z2",
      "basis": "assumed",
      "unknown": "U1",
      "not_assessed": "No code or running instance could be found."
    }
  ],
  "flows": [
    {"id": "F1", "from": "C1", "to": "C2", "label": "Order requests", "channel": "HTTPS", "guarantees": "Session token, no schema check", "basis": "observed", "sources": ["S1"]}
  ],
  "assets": [
    {"id": "A1", "name": "Customer payment history", "why": "Regulated personal data.", "objectives": ["confidentiality"], "where": ["C2"], "basis": "observed", "sources": ["S1"]}
  ],
  "actors": [
    {"name": "Another customer", "can": "Hold a valid session and call every public endpoint.", "cannot": "Reach the production network, or act as staff."}
  ],
  "calibration": {
    "critical": "What this rating means for this system, with an example.",
    "high": "Someone could read another customer's payment history.",
    "medium": "...",
    "low": "..."
  },
  "threats": [
    {
      "id": "T1",
      "title": "One customer can read another's orders",
      "stride": ["information-disclosure"],
      "components": ["C2"],
      "flows": ["F1"],
      "assets": ["A1"],
      "source": "A signed-in customer",
      "prerequisites": "another customer's order number",
      "action": "request that order directly",
      "consequence": "reading its contents",
      "likelihood": "high",
      "impact": "high",
      "rating_reason": "Why those two, given the controls you verified.",
      "status": "open",
      "evidence": [
        {"source": "S1", "file": "src/orders.py", "line": 42, "quote": "The exact text."},
        {"source": "S2", "locator": "Where to find this again.", "quote": "Optional, what it showed.", "observed": "2026-11-03"}
      ],
      "mitigations": [
        {"control": "Ownership check on order reads", "status": "not-found", "looked_in": ["S1"]},
        {"control": "Web application firewall", "status": "could-not-check", "tried": "Listed the firewall rules, and the call was denied.", "note": "Why that leaves it open."},
        {"control": "Client grants", "status": "not-attempted", "note": "That read also returns a secret, and this run was unattended."}
      ],
      "response": "mitigate",
      "recommendation": "The specific control to add, and where.",
      "detection": "Optional: what would show this happening.",
      "references": ["CWE-862"],
      "depends_on": ["U1"]
    }
  ],
  "boundary_reviews": [
    {"flow": "F2", "conclusion": "Why this boundary crossing has no threat listed."}
  ],
  "llm_questions": {
    "has_ai": true,
    "untrusted_text_into_prompts": {"answer": "Where, and from whom.", "evidence": []},
    "where_model_output_goes": {"answer": "Could not be determined.", "determined": false},
    "what_tools_can_do": {"answer": "Each tool and its reach.", "evidence": []},
    "additional": [{"question": "Your own, or the operator's.", "answer": "The answer.", "evidence": []}]
  },
  "conflicts": [
    {
      "about": "Whether the storage bucket is public",
      "sides": [
        {"source": "S1", "says": "The definition sets it private.", "evidence": {"source": "S1", "file": "deploy/storage.yaml", "line": 9, "quote": "The exact text."}},
        {"source": "S2", "says": "It allows public reads today."}
      ],
      "believed": "The live configuration, because it is what's running.",
      "why_it_matters": "Exports in that bucket hold customer data.",
      "threats": ["T1"]
    }
  ],
  "unknowns": [
    {
      "id": "U1",
      "question": "Does the refund worker still run?",
      "assumed": "It runs, with the same access as the API.",
      "who_can_answer": "Whoever owns payments operations.",
      "status": "open",
      "affects": "Optional, for anything that isn't linked another way."
    }
  ],
  "steering": [
    {
      "evidence": {"source": "S1", "file": "AGENTS.md", "line": 12, "quote": "The exact text."},
      "effect": "What it would change about the threat model.",
      "handled": "What you did about the area it points away from, and what you found.",
      "leads": ["orders-api/L001"]
    }
  ],
  "dismissed_leads": [{"leads": ["orders-api/L002", "orders-api/L003"], "reason": "Why these aren't steering."}],
  "stride_coverage": {
    "spoofing": {"result": "none-found", "note": "What you considered, and why it came to that."},
    "tampering": {"result": "not-assessed", "note": "Why it wasn't."},
    "repudiation": {"result": "none-found", "note": "..."},
    "information-disclosure": {"result": "threats-listed", "note": "..."},
    "denial-of-service": {"result": "none-found", "note": "..."},
    "elevation-of-privilege": {"result": "none-found", "note": "..."}
  },
  "backtest": {"checked": "The security fixes in the history, and the two advisories.", "result": "The model anticipates both. One fix prompted T1."},
  "architecture_check": "A fresh agent rebuilt the architecture from the sources. It added one flow. Or: not done, and why.",
  "not_checked": ["Anything else you could not assess, and why."]
}
```

With no AI in the system, `llm_questions` is `{"has_ai": false, "why": "What you looked at to conclude that."}`.

## Values

| Field | Values |
| --- | --- |
| `intake.stage` | `existing`, `planned`, `change` |
| `intake.gaps` | `interview`, `best-effort` |
| source `kind` | `repo` (has a snapshot), `live` (a running system or its control plane), `document`, `person`, `other` |
| source `status` | `used`, `not-reachable`, `declined`, `not-needed` |
| `intake.unattended` | Optional: `true` when nobody can be asked during the run, which needs `gaps` of `best-effort` |
| `confirmations.decision` | `approved`, `declined`, or `not-asked` in an unattended run |
| component `type` | `actor`, `process`, `data`, `model`, `external` |
| `basis` | `observed`, `documented`, `inferred`, `assumed` |
| `threats.stride` | `spoofing`, `tampering`, `repudiation`, `information-disclosure`, `denial-of-service`, `elevation-of-privilege` |
| threat `impact` | `critical`, `high`, `medium`, `low` |
| threat `likelihood` | `high`, `medium`, `low` |
| threat `status` | `open`, `partly-mitigated`, `mitigated` |
| threat `response` | `mitigate`, `eliminate`, `transfer`. Accepting a risk is the signer's decision |
| asset `objectives` | `confidentiality`, `integrity`, `availability` |
| zone `trust_level` | `low`, `medium`, `high` |
| mitigation `status` | `running`, `in-code`, `documented`, `not-found`, `could-not-check`, `not-attempted` |
| unknown `status` | `open`, `answered`, with `answer` when answered |
| `stride_coverage.result` | `threats-listed`, `none-found`, `not-assessed` |

A repository you read some other way, without a snapshot, is `other`, not `repo`.

The helper derives each threat's rating from its impact and likelihood:

| Impact | High likelihood | Medium likelihood | Low likelihood |
| --- | --- | --- | --- |
| critical | critical | critical | high |
| high | high | high | medium |
| medium | medium | medium | low |
| low | low | low | low |

A threat's fields make one sentence, so write them to read that way: "{source} with {prerequisites} can {action}, which leads to
{consequence}, negatively impacting {assets}." `prerequisites` is optional, and is a short phrase following the word "with".

Refer to another item in text by its id, such as `T1`, `U2`, or `C3`. The report replaces each one with its final number or name, so write each id out, not a range such as `T2-T4`.

A threat worth signing is specific, and it names what was checked:

> **Weak:** "An attacker could exploit missing input validation, compromising the system."
>
> **Strong:** "A signed-in customer with another customer's order number can request that order directly, which leads to reading its
> contents, negatively impacting customer payment history." Its evidence is the route that reads an order by number alone, and its
> mitigation entry records that an ownership check was looked for and not found.

## Length

Each text field has a limit of 300 characters, `summary` 800, a threat `title` 120, a source's `name` 40, `source` 100, `prerequisites` 120, and `action` and
`consequence` 200 each. Each list of evidence holds at most 3 items, and a model holds at most 30 threats. These cap words and not facts, so
say it once, merge what shares a root cause, and cite what proves the point.

Write each fact in one place. `not_checked` is for what isn't already recorded on a source, component, or control, because the report
lists those for you. The report shows evidence for `llm_questions`, `conflicts`, and mitigations by location, so state what it shows in words.

## Evidence

From a `repo` source, give `file`, `line`, and `quote`. The helper checks the quote against the snapshot, which shows that the text is there and
not that it proves the point, so cite the text that does. For a credential, set `"credential": true` and leave out `quote`, which makes the helper
check only that the location exists.

If a `repo` source has a permanent web address for its commit, set `link` on the source, with `{file}` and `{line}` where they go. The report then
links each location.

From any other source, give `locator`, specific enough for someone to find it again, with `quote` and `observed` if useful.
`observed` defaults to the source's date. The helper can't check these, and the report says so, so be exact.

## How a claim backs itself up

| `basis` | Needs |
| --- | --- |
| `observed` | `sources`, including one of kind `repo`, `live`, or `other` |
| `documented` | `sources` |
| `inferred` | `reasoning` |
| `assumed` | `unknown`, naming the entry that would settle it |

## What the helper rejects

- A field that's missing, unknown, or empty where text is required.
- A quote that isn't at or just after the cited line, or a path or line that isn't in the snapshot.
- Text anywhere in the file that's shaped like a credential. This covers the whole file, because the file is a deliverable.
- A citation of a source that isn't marked `used`, or a snapshot that isn't listed in `sources`.
- `running` with no evidence from a `live` source, `in-code` with no evidence from a `repo` or `other` source, `documented` with no
  evidence, `not-found` without `looked_in`, `could-not-check` without `tried` and `note`, or `not-attempted` without `note`.
- A threat marked `mitigated` with no mitigation that's `running` or `in-code`, or a threat that isn't `mitigated` with no
  `recommendation` and `response`.
- Text mentioning a threat or unknown id that doesn't exist, or a range of ids.
- A field over its length limit, more than 3 pieces of evidence on one item, or more than 30 threats.
- `not-asked` in a run that isn't unattended, or an unattended run with `gaps` of `interview`.
- A threat with neither `evidence` nor `depends_on`.
- A component other than an `actor` with no threat, `no_open_threats`, or `not_assessed`.
- A flow between zones with no threat and no `boundary_reviews` entry.
- Nothing in `sources` marked `used`, or an empty `zones`, `components`, `assets`, or `actors`.
- An unknown that nothing depends on, with no `affects`.
- A lead that's used twice, isn't used, or is attached to an item citing a different file.
- A `stride_coverage.result` that disagrees with the threats: `threats-listed` exactly when a threat lists that category.
- `policy_route` when no policy guidance was found.
- More than 80 components, or a diagram too large for most viewers to draw.
- A snapshot that changed after `prepare`. This is exit code 2. Run `prepare` again.
