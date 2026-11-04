# Report contract

`preflight.py render` reads `assessment.json` from the output directory and writes `report.md` and `report.sarif`. The sections,
their order, and the scales come from the helper, so only the content changes from run to run.

Contents: writing it, citations, assessment.json, what the report must answer, closed values, severity, classification, what the
helper rejects, report sections.

## Writing it

Someone will decide from this, so say each thing once, in the fewest words that keep it true. Lead with the conclusion. Don't
explain what the reader can see, restate a finding in an answer, or hedge in the summary. Point to an item by its id instead of
repeating it. Word limits apply to each field, and they're ceilings, not targets: most entries need less. More entries are always
allowed, so a second point goes in its own entry and nothing has to be cut. Write sentences, not shorthand: `reads/updates` counts as
two words, and a reader still has to unpack it.

Rambling: "It's worth noting that the code returns the high field without checking that it is a number, which could potentially
mean that whoever controls that service might be able to return text addressed to the agent."

Tight: "The service's response reaches the agent unchecked, so whoever controls that service can address the agent."

## Citations

A citation is `{"source": "D001", "quote": "The exact words."}`. Code sources also need the file:
`{"source": "R001", "file": "src/tools.py", "quote": "The exact code."}`. You give the words; the helper finds them and puts
the line in the report. It ignores spacing, line breaks, invisible characters, and typographic quote marks, so a quote can run
across lines. The words must otherwise be the source's own.

A quote has to show the claim by itself. `return true;` shows nothing, so quote the line that does the thing with enough around
it to identify it. The helper rejects anything under 20 characters, or that appears more than once in the source, though it can't
judge whether a longer quote proves the point. A tool's own citation may be as short as 8 characters, like `Tool: delete_record`.
In a listing, quote hidden characters the way `live/<id>.txt` spells them, such as `[U+200B]`.

Sources are documentation (`D001`, including a vendor review), code (`R001`), configuration (`C001`), listings from a server
(`O001`), and policy (`P001`). The report labels each by what it rests on: Documented, Read in code, Configured, Observed, or
Listing supplied.

For a credential, use `{"source": "C001", "quote": "", "credential": true, "line": 12}`, adding `file` for a code source.

## assessment.json

Every top-level field is required. A list may be empty unless noted here. Numbers in brackets are word limits, which the helper
enforces.

```json
{
  "engagement": {
    "server": "The server, as a person would name it. [15]",
    "instance": "The exact version, package, commit, or hosted address this assessment applies to. [25]",
    "team": "Who would use it. [15]",
    "agent": "Which agent or agents. [15]",
    "data": "What data would reach it. [15]",
    "alongside": "What else would be connected in the same session, or that nobody said. [25]",
    "assumptions": ["Anything above that you assumed rather than were told. [25]"]
  },
  "summary": "Exactly what was assessed, then what this use would mean, in plain language. If the name also covers something else or something retired, say so. [50]",
  "verdict": {
    "recommendation": "yes-with-conditions",
    "as_proposed": "not-cleared",
    "reasons": [
      {"text": "One line of reasoning. [20]", "refs": ["F1", "X1", "S1", "identity"], "cites": []}
    ],
    "conditions": [
      {
        "condition": "Something the operator can require. [25]",
        "verify": "How someone would check that it's in place. [15]",
        "addresses": ["F1", "identity"]
      }
    ],
    "review_by": "2027-05-01",
    "reassess_when": ["What would make this answer stale. [12]"]
  },
  "needed_to_decide": ["A fact that's missing, who could supply it, and how it could change the answer. Not a step the operator could take. [25]"],
  "vendor_review": {
    "status": "not-requested",
    "note": "What the operator chose, or why there's no vendor. [25]",
    "source": "D004, only when a review was included or relied on."
  },
  "steering": [
    {
      "id": "S1",
      "title": "The attempt, as a short sentence [15]",
      "severity": "high",
      "cite": {"source": "O001", "quote": "The exact text."},
      "aimed_at": "agent-in-use",
      "effect": "What it would change. [20]",
      "handled": "What you did about what it pointed away from, and what you found. [25]",
      "leads": ["L001"],
      "classification": ["MCP03:2025"]
    }
  ],
  "dismissed_leads": [{"leads": ["L002", "L003"], "reason": "Why these aren't steering. [20]"}],
  "findings": [
    {
      "id": "F1",
      "title": "The weakness and its outcome, as a short sentence [15]",
      "severity": "high",
      "confidence": "confirmed",
      "question": "identity",
      "cites": [{"source": "R001", "file": "src/auth.py", "quote": "The exact code."}],
      "why": "What this means for this use: who could do what, and what they'd gain. [40]",
      "recommendation": "The specific change or condition. [25]",
      "classification": ["MCP07:2025", "CWE-862"]
    }
  ],
  "conflicts": [
    {
      "id": "X1",
      "title": "The disagreement, as a short sentence [15]",
      "severity": "high",
      "side_a": {"says": "What the first source says. [20]", "cite": {"source": "D001", "quote": "The exact words."}},
      "side_b": {"says": "What the second source says. [20]", "cite": {"source": "O001", "quote": "The exact words."}},
      "why": "What this means for this use. [40]",
      "settle": "The question or evidence that would settle it. [25]"
    }
  ],
  "questions": [
    {
      "id": "identity",
      "status": "partly-established",
      "answer": "The answer for this use, or that it couldn't be established. Refer to findings by id instead of restating them. [25]",
      "cites": [{"source": "D001", "quote": "The exact words."}],
      "looked_in": ["D001", "R001"]
    }
  ],
  "tools": [
    {
      "name": "delete_record",
      "effects": ["delete"],
      "touches": "What it reads, changes, or reaches. [12]",
      "decision": "disable",
      "cites": [{"source": "O001", "quote": "Tool: delete_record"}]
    }
  ],
  "tools_note": "How complete this list is and where it comes from. [25]",
  "policy": [
    {
      "id": "G1",
      "requirement": "The organization's requirement, in short. [20]",
      "policy_cite": {"source": "P001", "quote": "The exact words."},
      "status": "not-met",
      "basis": "How this use measures against it. [25]",
      "cites": []
    }
  ],
  "not_checked": ["What you couldn't read or establish that the helper won't already say, and why. [25]"]
}
```

The report's first line asks whether it's safe for `team` to use `server`, with `data`, in `agent`, so write those four to read
mid-sentence: `the support team`, `the Brightdesk CRM server`, `customer contact records`, `their coding agent`.

`as_proposed` is required for `yes-with-conditions` and belongs nowhere else. `fits` means the setup the operator described stands
once the conditions are met, as with pinning a version or narrowing a token. `not-cleared` means the conditions take away something
they planned to connect, share, or do, so the yes is for a narrower use. The headline shows it either way.

`review_by` and `reassess_when` are required for `yes` and `yes-with-conditions`. Suggest about six months, or sooner when the
server changes often. It has to be within a year. `reassess_when` names this server's real triggers, such as a new version, a
changed tool definition, another server joining the session, or more sensitive data. The person who signs sets the final date.

`classification` is optional, on findings, conflicts, and steering. Use it only when a label fits plainly.

`needed_to_decide` belongs to `not-yet`, and elsewhere only for something a condition doesn't already cover, so don't repeat a
condition there. In a `not-yet` or `no`, `conditions` are what the operator should do before asking again, and the report titles them
that way.

`not_checked` holds only what the helper can't say. It already adds every limit in `manifest.json`, that no tool was called, and
whether a listing or source code was available, so don't restate those.

## What the report must answer

**`questions`** has one entry for each question below. Add others with `"id": "other"` and a `"question"`.

| `id` | Question |
| --- | --- |
| `capabilities` | What can it do, including anything its tools don't show? |
| `identity` | Who does it act as, and how far does that reach? |
| `data` | Where does the data go, and who else sees it? |
| `runtime` | Where does it run, and what can it reach from there? |
| `untrusted-content` | Can what comes through it steer the agent? |
| `combination` | What does it become alongside everything else in the session? |
| `ownership-and-change` | Who owns it, and how could it change after this decision? |
| `oversight` | Could anyone tell what it did, stop it, and remove it? |

**`tools`** accounts for every tool in every listing, and every tool you established any other way that this use would get. A
tool from an older version or a different product doesn't belong here; say so in `tools_note`. If you can't establish the full
list, say that there too.

## Closed values

| Field | Values |
| --- | --- |
| `as_proposed` | `fits`, `not-cleared` |
| `recommendation` | `yes`: nothing needs containing. `yes-with-conditions`: what's open can be contained by what the operator can require and check. `not-yet`: a missing fact could change the answer, and no condition can stand in for it. `no`: no condition contains the risk |
| question `status` | `established`: evidence supports the answer. `partly-established`: some of it does. `not-established`: nothing does; list `looked_in`. `conflicting`: sources disagree; list the conflict. `not-applicable`: say why |
| `aimed_at` | `assessor`: tries to change this assessment. `agent-in-use`: would act on an agent using the server |
| `confidence` | `confirmed`: the evidence shows it. `probable`: it depends on something you can't see, which `why` names |
| `effects` | `read`, `write`, `delete`, `execute`, `network`, or `unknown`. List all that apply. `unknown` stands alone: if you can't verify what a tool does, say only that, and put what you know in `touches` |
| tool `decision` | `allow`, `allow-with-condition`, `disable`, or `undecided`, for this use |
| vendor review `status` | `included`, `existing`, `not-requested`, `not-applicable` |
| policy `status` | `met`, `not-met`, `unknown` |

## Severity

Rate what the issue means for this use, not how alarming its class sounds. A path to harm in a session with little to lose isn't
high, however real the path is. Steering is rated by what it would do if it worked.

| Severity | Meaning |
| --- | --- |
| `critical` | Decides the answer alone: this use would expose or hand over what it touches, and no condition contains that |
| `high` | Serious harm to this use's data, accounts, or systems, which must be fixed or contained before connecting |
| `medium` | The same harm with limited reach here, or an uncommon condition |
| `low` | Weakens a safeguard without reaching that harm by itself |
| `info` | Worth a reviewer's attention, with no demonstrated effect |

## Classification

Labels are `CWE-<number>`, or a risk from the OWASP MCP Top 10:

| Label | Risk |
| --- | --- |
| `MCP01:2025` | Token mismanagement and secret exposure |
| `MCP02:2025` | Privilege escalation via scope creep |
| `MCP03:2025` | Tool poisoning |
| `MCP04:2025` | Software supply chain attacks and dependency tampering |
| `MCP05:2025` | Command injection and execution |
| `MCP06:2025` | Prompt injection via contextual payloads |
| `MCP07:2025` | Insufficient authentication and authorization |
| `MCP08:2025` | Lack of audit and telemetry |
| `MCP09:2025` | Shadow MCP servers |
| `MCP10:2025` | Context injection and over-sharing |

## What the helper rejects

- a field that is missing, unknown, over its word limit, or empty where text is required, or a value outside the closed lists;
- a quote it can't find in the source, one too short to prove anything, or one that appears more than once;
- a code citation without a file from that source;
- a fixed question left out, or an `established` answer with no citation;
- a tool in a listing that `tools` doesn't account for, or a tool with no citation;
- a lead used twice, not used at all, or attached to a different source than it came from, or a dismissal that names no lead;
- `unknown` listed alongside other effects;
- a conflict that quotes one statement twice;
- a document with no text and no transcript that `not_checked` doesn't name;
- policy entries when no policy was supplied, or none when one was;
- reasoning with neither references nor citations, or a reference to something that doesn't exist;
- evidence that changed after it was stored. Run `prepare` again; this is exit code 2, not a correction to make.

**`yes`** is rejected while there are conditions, a critical or high item, a fixed question that isn't settled, steering, an
unmet policy requirement, assumptions about the use, a session that already had the server connected, code that couldn't be
read, listings that differ by client, or nothing beyond documentation showing how the server behaves.

**`yes-with-conditions`** is rejected with no conditions, without `as_proposed`, with a critical item, or when a high item, an unsettled question, or
an unmet policy requirement has no condition whose `addresses` names it.

**`not-yet`** needs `needed_to_decide`. It's rejected when nothing is critical or high, no fixed question is unsettled, and code or a
listing was read, because the evidence has then settled it. With no evidence at all, it's the only recommendation available.

## Report sections

Always these, in this order: Executive summary, Scope, Findings summary, Steering instructions, Findings, Tools, Questions, Not
checked, Sign-off, and appendices for Evidence, Method and severity, and Dismissed leads. Policy guidance appears after Questions
only when a policy was supplied, and Changes since the previous assessment follows it only with `--previous`.

The executive summary stands alone: the recommendation, why, the conditions, and when to review it again. Findings holds issues
and conflicts between sources together, most severe first. Questions answers in a table that points to its evidence; the quotes
behind it stay in `assessment.json`.

The header says what the assessment applies to and whether it contacted the server, and records the digest of a listing's tool
definitions, which a later assessment or an admission check can compare against. `report.sarif` holds the same items in SARIF
2.1.0 for tools that track findings. Nothing in either file approves a server. The person who signs decides.
