# Report contract

`review.py render` reads `findings.json` from the output directory and writes `report.md`, `report.sarif`, and, when
there are low or info findings, `report-lower-severity.md`. The
sections, their order, the severity scale, and the finding numbers come from the helper, so only the content changes
from run to run.

## surface.json

The work list. `render` refuses to run while any unit has no result in `units/<id>.json` and isn't marked `not_reviewed`.

```json
{
  "units": [
    {
      "id": "password-reset",
      "what": "Requesting and redeeming a password reset.",
      "entry_points": ["src/routes/auth.py:40", "src/routes/auth.py:58"],
      "affected_by": "Incremental only: how the changes reach this unit.",
      "changes": ["Incremental only: the changed files that put it in scope."],
      "not_reviewed": "Only if it wasn't reviewed: why."
    }
  ],
  "changes_out_of_scope": [{"path": "docs/notes.md", "reason": "Incremental only: why this change can't affect security."}]
}
```

`id` uses lowercase letters, digits, and hyphens. With `--base`, every changed file has to appear in a unit's `changes`
or in `changes_out_of_scope`, and `units` may be empty only when nothing changed. Unit results follow
[unit-review.md](unit-review.md).

## findings.json

Every top-level field is required, except that `suppressions_reviewed` belongs only in a review where the manifest
counts suppression comments. A list may be empty unless noted here.

```json
{
  "system": {
    "what_it_does": "What this system is, in a sentence or two.",
    "worth_protecting": "The data, money, access, or trust at stake.",
    "who_could_abuse": "The realistic actors for this system."
  },
  "summary": "One short paragraph: what someone could do to this system, in plain language.",
  "steering": [
    {
      "file": "docs/agents/review-notes.md",
      "line": 12,
      "evidence": "The exact text.",
      "effect": "What it tries to change about the review.",
      "examined_anyway": "What you did about the area it points away from, and what you found.",
      "leads": ["L001"]
    }
  ],
  "suppressions_reviewed": "Which suppression comments you checked, why those, and what that showed.",
  "findings": [
    {
      "title": "The claim, as a short sentence",
      "severity": "high",
      "confidence": "confirmed",
      "cwe": "CWE-639",
      "file": "src/orders/service.py",
      "line": 42,
      "also_at": ["src/orders/refunds.py:18"],
      "evidence": "The exact code that proves it.",
      "requires": "What an attacker needs: the access, the conditions, and anyone else's action.",
      "why": "The path from attacker to outcome: who can do it, how, and what they gain.",
      "recommendation": "The specific change to make.",
      "origin": "judgment",
      "scanner_hits": [],
      "candidates": ["password-reset#1"],
      "severity_reason": "Required only when rating below a scanner result.",
      "policy_route": "The route's name from the PolicyRelay index, only when this finding breaks that guidance."
    }
  ],
  "examined": [
    {
      "area": "The question you examined, in your own words.",
      "looked_at": ["src/orders/", "src/auth/session.py"],
      "result": "no-issue-found",
      "conclusion": "What you concluded, and the evidence for it.",
      "beyond_examples": true
    }
  ],
  "scanner_territory": [
    {
      "class": "Known-vulnerable dependencies",
      "status": "not-run",
      "note": "No results were supplied. This review didn't assess dependency advisories."
    }
  ],
  "dismissed_leads": [{"leads": ["L002", "L003"], "reason": "Why these aren't steering."}],
  "dismissed_hits": [{"hits": ["H001"], "reason": "Why this isn't real in this system."}],
  "dismissed_candidates": [{"candidates": ["orders#2"], "reason": "The code that disproves it."}],
  "not_checked": ["Anything you could not assess, and why."]
}
```

The helper rejects the file when:

- a field is missing, unknown, or empty where text is required;
- `file` isn't a file in the snapshot, or `line` is outside it;
- `evidence` is too short to prove anything, or doesn't appear on `line` or the two lines after it. Runs of
  whitespace and invisible characters don't need to match, but every word break does, so quote the file;
- a path in `looked_at` isn't in the snapshot. Name `.` only if you truly read the whole snapshot;
- `examined` or `scanner_territory` is empty, because a report has to say what it covered;
- `suppressions_reviewed` is empty or missing when the manifest counts suppression comments, or present when it
  counts none;
- a lead or scanner hit is used twice, isn't used at all, or is attached to an item in a different file;
- a candidate from `units/`, named `<unit id>#<its position>`, is used twice or isn't in a finding or
  `dismissed_candidates`;
- a unit is pending, its result is malformed, or a changed file isn't accounted for;
- the snapshot changed after `prepare`. Run `prepare --restart`; this is exit code 2, not a correction to make;
- an `also_at` entry isn't `path:line` for a file in the snapshot;
- a field runs past its length limit below;
- `cwe` isn't written like `CWE-639`;
- `severity` is below a scanner result's severity with no `severity_reason`;
- `origin` is `scanner-hit` without `scanner_hits`, or the reverse.

For a credential, set `"credential": true`, leave `evidence` as an empty string, and let `file` and `line` point
to it. The report says the helper couldn't check that location. The report also masks anything shaped like a credential, but that is a backstop, not permission to quote
one.

## Length

The report has to be quick to review, so the helper rejects these when they run long. The limits apply to each entry,
never to how many there are, so nothing has to be left out to fit. Cut repetition, not facts, and split an entry that
holds two things. Reasoning that doesn't fit stays in `units/`, and the report points to it.

| Field | Words | What belongs there |
| --- | --- | --- |
| `summary` | 100 | What someone could do to this system, in plain language. Not the method or the findings restated |
| `system` fields | 40 each | |
| `title` | 20 | The claim |
| `requires` | 30 | The access, conditions, and other people's actions an attack needs |
| `why` | 60 | The path from attacker to outcome. Leave out confidence, line references, and rating reasons |
| `recommendation` | 50 | The specific change to make |
| `severity_reason` | 25 | Only when rating below a scanner result |
| `effect` | 50 | What the steering text would change |
| `examined_anyway` | 75 | What you did, and what you found |
| `suppressions_reviewed` | 60 | |
| `area` | 20 | |
| `conclusion` | 40 | The answer and its main evidence |
| `note`, `reason`, `not_checked` entry, `not_reviewed` | 30 each | |

## Closed values

| Field | Values |
| --- | --- |
| `confidence` | `confirmed`: you traced the whole path in the code. `probable`: part of it depends on something you can't see, which `why` names |
| `origin` | `judgment`: you found it by reasoning about the system. `scanner-hit`: a supplied scanner result you confirmed. `scanner-territory`: you saw it, but a deterministic tool should catch this class |
| `result` | `issue-found`, `no-issue-found`, or `inconclusive` |
| `status` | `results-reviewed` or `not-run` |

## Severity

Rate what the issue allows in this system, not how alarming its class sounds.

| Severity | Meaning |
| --- | --- |
| `critical` | An outsider or ordinary user reaches system-wide compromise, or data or money at scale, with no further human step |
| `high` | Serious compromise of data, money, accounts, or integrity, reachable with ordinary access or one realistic condition |
| `medium` | The same outcomes, but limited in reach or needing an uncommon condition, or a privileged actor exceeding their role |
| `low` | Weakens a safeguard or widens access without reaching those outcomes by itself |
| `info` | Worth a reviewer's attention, with no demonstrated risk |

## Report sections

Always these, in this order: Executive summary, System under review, Steering instructions, Findings summary, Finding
details, Not checked, Sign-off, Appendix A: Coverage, Appendix B: Severity scale, Appendix C: Scanner territory, Appendix
D: Dismissed leads, scanner hits, and candidates. A Policy guidance section appears before Not checked only when the
target has PolicyRelay guidance.

No single standard mandates the format of a security review report, so the shape follows the reporting structure the
OWASP Web Security Testing Guide suggests: an executive summary, a findings summary table, finding details that cover
what it takes and what it allows, then appendices that include the severity scale. Findings name a CWE, and
`report.sarif` carries them in SARIF 2.1.0, the OASIS standard for such results. Severity uses the usual names with the
definitions above and no CVSS score, because a score needs facts about the deployment that a code review doesn't have.
SARIF has fewer levels: critical and high are `error`, medium is `warning`, and low and info are `note`, with the
severity kept in each result's properties.

The report gives full detail for critical, high, and medium findings. Every finding has a row in the summary table, with
the evidence and recommendation for low and info findings in `report-lower-severity.md`.

The Executive summary's release position comes from the counts, not from you: any critical or high finding means there are
issues to resolve or accept in writing before release. Nothing in the report approves a release. The person who
signs it does.
