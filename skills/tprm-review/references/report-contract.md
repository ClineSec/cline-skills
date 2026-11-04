# Report contract

`tprm.py render` reads `assessment.json` from the output directory and writes `report.md` and `vendor-questions.md`. The
sections, their order, the scales, the risk ratings, and the subprocessor comparison come from the helper, so only the content
changes from run to run.

## Citations

A citation is `{"source": "D001", "quote": "The exact words."}`. Sources are documents (`D001`), public sources (`S001`),
and policy documents (`P001`). You give the words; the helper finds them and puts the page and line in the report. It ignores
spacing, line breaks, and typographic quote marks, so PDF layout won't trip you up. The words must otherwise be the
source's own, from 12 to 600 characters: enough to prove the point, and no more.

For a credential in a document, use `{"source": "D001", "quote": "", "credential": true}`.

## assessment.json

Every top-level field is required. A list may be empty unless noted here.

```json
{
  "engagement": {
    "product": "The product or service under review.",
    "use": "What the organization would use it for, and who would.",
    "connection": "What it would connect to or be given access to.",
    "data_in_scope": "What data would reach it. Say so if this is your assumption.",
    "data_sensitivity": "restricted",
    "access": "read",
    "business_impact": "high",
    "risk_reason": "Why, in a sentence, from the data and access involved."
  },
  "summary": "One short paragraph: what this vendor is, how well its account holds up, and what it means for this engagement.",
  "verdict": {
    "recommendation": "approve-with-conditions",
    "reasons": [
      {"text": "One line of reasoning.", "refs": ["X1", "G1", "data-use"], "cites": []}
    ],
    "conditions": [
      {"action": "Something the operator can require and check.", "addresses": ["X1", "G1"], "owner": "Vendor", "due": "Before connecting"}
    ],
    "reassess": {"by": "2027-11-01", "triggers": "What should bring the review forward, such as an acquisition or a new model provider."}
  },
  "steering": [
    {
      "cite": {"source": "D002", "quote": "The exact text."},
      "effect": "What it tries to change about the review.",
      "handled": "What you did about what it pointed away from, and what you found.",
      "leads": ["D002:14"]
    }
  ],
  "dismissed_leads": [{"leads": ["D001:220"], "reason": "Why this isn't steering."}],
  "documents": [
    {
      "source": "D001",
      "kind": "SOC 2 Type II report",
      "issued": "2026-03-01, or 'Not stated'",
      "covers": "The entity, product, and period it covers.",
      "note": "Optional. Anything a reader should know, such as a watermark or a draft marking."
    }
  ],
  "data_classification": [
    {"data": "Employee records", "class": "Restricted", "basis": "The organization's scheme, or the default below."}
  ],
  "vendor_profile": [
    {"topic": "legal-entity", "finding": "What you established, or that you couldn't.", "cites": []}
  ],
  "posture": [
    {
      "id": "data-use",
      "status": "contradicted",
      "answer": "What the sources commit to, and how firmly.",
      "cites": [{"source": "D003", "quote": "The exact words."}],
      "looked_in": ["D001", "D002", "S003"]
    }
  ],
  "assurance": [
    {
      "kind": "SOC 2 Type II",
      "issuer": "The auditor or certifying body.",
      "subject_entity": "The entity the report names.",
      "scope": "What's in scope, and what isn't that matters here.",
      "covers_product": "partly",
      "categories": "Security, Availability. Or 'Not stated'.",
      "period_start": "2025-01-01",
      "period_end": "2025-12-31",
      "opinion": "qualified",
      "exceptions": [
        {"control": "CC6.2", "finding": "What the auditor found, with the sample if stated.", "relevance": "What it means here.", "response": "Management's response, or 'None stated'."}
      ],
      "subservice_method": "carve-out",
      "carve_outs": "Optional. Who is carved out, and whether they handle our data.",
      "user_controls": [{"control": "What the report expects the customer to operate.", "owner": "Identity team"}],
      "bridge_letter": "Optional. What it covers and who signed it. Only if you have one.",
      "auditor_check": "What you established about the firm, or that you couldn't.",
      "cites": [{"source": "D001", "quote": "The exact words."}]
    }
  ],
  "subprocessors": [
    {
      "name": "Example Models Inc.",
      "function": "What they do.",
      "data": "What data they see, or 'Not stated'.",
      "location": "Where, or 'Not stated'.",
      "model_provider": true,
      "cites": [{"source": "D004", "quote": "Example Models Inc."}]
    }
  ],
  "subprocessor_note": "How current and complete the list is, and where it came from.",
  "public_sources": [
    {
      "id": "S001",
      "url": "https://example.com/page",
      "title": "The page's title.",
      "publisher": "Who published it.",
      "published": "2026-02 (YYYY, YYYY-MM, YYYY-MM-DD, or empty if unknown)",
      "retrieved": "2026-11-02",
      "kind": "independent-press",
      "captured": true
    }
  ],
  "research": {
    "status": "full",
    "note": "How far the research went, and what limited it.",
    "log": [{"question": "What you looked for.", "where_looked": "Where.", "result": "What came back, including nothing."}]
  },
  "claims": [
    {
      "claim": "A vendor claim this engagement relies on.",
      "cites": [{"source": "D002", "quote": "The exact words."}],
      "tested_against": "What you checked it against.",
      "result": "contradicted",
      "evidence_cites": [{"source": "S002", "quote": "The exact words."}],
      "discrepancy": "X1"
    }
  ],
  "public_record": [
    {
      "event": "What happened.",
      "date": "2026-03",
      "kind": "security-incident",
      "standing": "reported",
      "relevance": "What it means for this engagement.",
      "cites": [{"source": "S002", "quote": "The exact words."}]
    }
  ],
  "discrepancies": [
    {
      "id": "X1",
      "title": "The conflict, as a short sentence",
      "kind": "document-vs-public",
      "severity": "high",
      "confidence": "confirmed",
      "side_a": {"says": "Who says it, and the point in short. The quote carries the rest.", "cite": {"source": "D002", "quote": "The exact words."}},
      "side_b": {"says": "What the second source says.", "cite": {"source": "S002", "quote": "The exact words."}},
      "why": "What this means for this engagement.",
      "ask": "The specific question or document that would settle it."
    }
  ],
  "gaps": [
    {
      "id": "G1",
      "topic": "What's unsaid.",
      "severity": "medium",
      "looked_in": ["D001", "D003", "S004"],
      "why": "Why this engagement needs it.",
      "ask": "What to ask the vendor for."
    }
  ],
  "policy": [
    {
      "requirement": "The organization's requirement, in short.",
      "policy_cite": {"source": "P001", "quote": "The exact words."},
      "status": "not-met",
      "basis": "How the vendor measures against it.",
      "cites": [{"source": "D002", "quote": "The exact words."}]
    }
  ],
  "questions_for_vendor": ["Optional extras. Each finding's ask is already included, so don't repeat them."],
  "not_checked": ["Anything you could not read or assess, and why."]
}
```

## What the report must answer

**`vendor_profile`** has one entry for each topic: `legal-entity`, `jurisdiction`, `ownership`, `history`, `scale`,
`financial-condition`, `leadership`, `foreign-influence`, `regulatory-standing`, `insurance`. If you couldn't establish one, say
so, with no citations; the report marks it not verified.

**`posture`** has one entry for each question below, and a status for each. Add others with `"id": "other"` and a `"question"`.

| `id` | Question |
| --- | --- |
| `data-use` | What may the vendor do with our data, including training models? |
| `data-location` | Where is our data stored and processed, for how long, and how is it deleted? |
| `ai-use` | What AI does the product use, who sees or keeps our data because of it, and how are its actions and inputs contained? |
| `access` | Who can reach our data, on our side and the vendor's, and is that visible to us? |
| `protection` | How is our data protected from compromise, and how is the product built and tested? |
| `assurance` | Who independently checked these claims, for what scope and period, and what did they find? |
| `incidents` | What happens when something goes wrong, and how soon would we know? |
| `resilience` | Can the service keep running or recover, and what does it commit to? |
| `exit-and-recourse` | What rights do we have over changes, audits, liability, and leaving? |

**`data_classification`** uses the organization's scheme when you have it. Otherwise use `restricted` (serious harm if
exposed: special-category or regulated personal data, bulk personal records, financial or health data, credentials, core
secrets), `confidential` (real but limited harm: business data, and ordinary personal details such as names and work contacts),
`internal`, or `public`, and say that this is the default in `basis`. Rate the data, not how alarming the word "personal" sounds.

## Closed values

| Field | Values |
| --- | --- |
| `recommendation` | `approve`, `approve-with-conditions`, `reject`, `insufficient-evidence` |
| `data_sensitivity` | `restricted`, `confidential`, `internal`, `public`: the most sensitive data that would reach the vendor |
| `access` | `privileged`, `write`, `read`, `none`: what the vendor or product could do to your systems |
| `business_impact` | `critical`, `high`, `medium`, `low`: what its failure or breach would do to you, whatever the vendor's size |
| `covers_product` | `yes`, `partly`, `no`, `not-stated`: whether the report covers the product under review |
| `subservice_method` | `carve-out`, `inclusive`, `none`, `not-stated`, `not-applicable` |
| posture `status` | `committed`: firm, binding, and specific. `partial`: stated, but limited, conditional, or only marketing. `silent`: nothing found; list `looked_in`. `contradicted`: sources conflict. `not-applicable`: say why |
| `opinion` | `unqualified`, `qualified`, `adverse`, `disclaimer`, `certificate-issued`, `self-attested`, `not-stated` |
| discrepancy `kind` | `document-vs-document`, `within-document`, `document-vs-public`, `public-vs-public` |
| discrepancy `confidence` | `confirmed`: both statements plainly conflict. `probable`: it depends on something you can't see, which `why` names |
| claim `result` | `corroborated`: another source supports it, in `evidence_cites`. `contradicted`: name the `discrepancy`. `unverifiable`: nothing independent either way |
| source `kind` | `regulator-or-court`, `official-register`, `vendor-published`, `independent-press`, `research-or-analyst`, `community`, `other` |
| record `kind` | `security-incident`, `regulatory`, `litigation`, `corporate-change`, `service-change`, `other` |
| record `standing` | `established`: a regulator, court, or official register you read at its source, or two independent publishers. `reported`: one credible source, or a copy you couldn't open at its address. `alleged`: a claim not yet resolved. `vendor-stated`: only the vendor says so |
| research `status` | `full`, `partial`, `none` |
| policy `status` | `met`, `not-met`, `unknown` |

## Severity

Rate what the discrepancy means for this engagement, not how alarming it sounds.

| Severity | Meaning |
| --- | --- |
| `critical` | Decides the verdict alone: data at this engagement's level would be exposed or misused, or the vendor's account can't be relied on at all |
| `high` | A commitment this engagement relies on may not hold, and it must be resolved before connecting |
| `medium` | A real conflict or gap with limited effect here, or one a condition can contain |
| `low` | Worth correcting, but it doesn't change the risk much |
| `info` | Worth a reviewer's attention, with no demonstrated effect |

## Risk ratings

The helper works these out, so the same facts give the same rating.

- **Inherent risk** comes from the engagement alone, never the vendor's documents. Score sensitivity (restricted 3, confidential 2,
  internal 1, public 0), access (privileged 3, write 2, read 1, none 0), and impact (critical 3, high 2, medium 1, low 0). 7 or more is
  critical, 5 or 6 is high, 3 or 4 is medium, and less is low. Restricted data, privileged access, or critical impact is at least high.
- **Residual risk** is the worst open finding, one level lower if a condition lists it in `addresses`, and never above the inherent
  risk. With no findings, it is low. With `insufficient-evidence`, it is not determined.

## Word limits

These apply to each entry, so split a long point into more entries rather than dropping facts. The helper rejects anything longer.

| Words | Fields |
| --- | --- |
| 90 | `summary` |
| 45 | discrepancy `why`, posture `answer` |
| 40 | assurance `scope`, research `note`, `questions_for_vendor` |
| 35 | profile `finding`, verdict reason `text` |
| 30 | engagement fields and `risk_reason`, condition `action`, discrepancy and gap `ask`, gap `why`, steering `effect` and `handled`, `auditor_check`, `carve_outs`, exception `finding`, policy `basis`, `not_checked`, `subprocessor_note` |
| 25 | document `covers`, record `event` and `relevance`, log `result`, policy `requirement`, `triggers` |
| 20 | claim `claim` and `tested_against`, exception `relevance` and `response`, customer control, dismissal `reason`, document `note`, `bridge_letter`, posture `question` |
| 15 | discrepancy `title` and side `says`, data `basis`, log `question` and `where_looked`, `subject_entity` |
| 12 | gap `topic`, subprocessor `function` and `data`, data `data`, assurance `issuer` and `categories` |
| 10 or fewer | condition `owner` (5) and `due` (6), `location` (8), control id (8), `issued` (8), document and assurance `kind` (10), subprocessor `name` (10), `class` (3), customer control `owner` (5) |

## What the helper rejects

- a field that is missing, unknown, or empty where text is required, or a value outside the closed lists;
- a quote it can't find in the source's text, transcript, or saved copy, or one too short to prove anything;
- a document, lead, posture question, or profile topic left unaccounted for;
- a lead used twice, or one not from this review. Leads are `<source>:<line>`, and leads from a transcript are `<source>T:<line>`;
- a field over its word limit, or more than 6 verdict `reasons`;
- a `silent` answer or a gap without `looked_in`, or a corroborated claim without other evidence;
- a discrepancy whose two sides don't match its `kind`, or that quotes one statement twice;
- a public record entry marked `established` without a regulator, court, or official register, or two independent publishers;
- reasoning with neither references nor citations, `approve-with-conditions` with no conditions, or with a critical or high finding
  no condition addresses;
- a reassessment date that isn't after this assessment;
- a public source marked `captured` with no saved copy, a retrieval date in the future, or an address that isn't http or https;
- policy entries when no policy was supplied, or none when one was;
- a document with no text and no transcript that `not_checked` doesn't name;
- documents that changed after `prepare`. Run `prepare` again; this is exit code 2, not a correction to make.

`approve` is rejected while there are conditions, a critical or high finding, a contradicted posture answer, an unmet policy
requirement, or no public research.

## Report sections

Always these, in this order: Executive summary, Scope and inherent risk, Steering instructions, Findings, Independent assurance,
Control posture, Subprocessors, Vendor profile, Public record, Policy fit, Questions for the vendor, Not checked, Sign-off, then
appendices for Claims tested, Documents reviewed, Research log and sources, Dismissed leads, and Quoted evidence.

Findings and steering show their quotes in place. Tables show a short locator, and the words go in the last appendix.

The helper works out how old each attestation is and whether it needs a bridge letter, compares subprocessors with `--previous`,
and says in the header how many quotes it could check against the helper's own text, and how many rest on your transcripts or
saved copies, or on nothing. Nothing in the report approves a vendor. The person who signs it does.
