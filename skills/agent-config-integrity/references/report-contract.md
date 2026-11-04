# Report contract

`integrity.py render` reads `findings.json` from the output directory and writes `report.md`. The
sections, order, severity scale, and finding numbers come from the helper, so only the content changes
from run to run.

## findings.json

```json
{
  "summary": "What this configuration lets someone do, in plain language.",
  "findings": [
    {
      "title": "A short statement of what the configuration allows",
      "severity": "high",
      "category": "execution",
      "file": "path/to/config",
      "line": 4,
      "evidence": "The lines that show it, quoted from the file",
      "why": "What someone gains from this, and how little it takes.",
      "recommendation": "The specific change to make.",
      "hits": ["H001"],
      "severity_reason": "Optional, one sentence. Required when rating below the rule's severity."
    }
  ],
  "dismissed": [
    {"hit": "H002", "reason": "Why this hit is not real in this repository."}
  ],
  "not_checked": ["A gap that limits how far the findings can be trusted."]
}
```

The helper rejects the file when:

- `file` isn't a regular file in the assessed scope. Paths match the inventory, including the `~/`
  prefix for user-level configuration;
- `evidence` doesn't appear at or just after `line`. Quote the file; spacing and invisible characters
  don't need to match;
- `severity` is outside the scale below;
- `evidence` runs past 12 lines;
- a text field links to another file. Web links are fine, but the report has to stand alone for whoever
  signs it, so nothing it depends on can live in a separate file.

If a scan ran, it also rejects the file when a hit is used twice or isn't used at all, or when `severity`
is below the rule's severity with no `severity_reason`. Group related hits in one finding when the same
change fixes them. Without a scan, leave `hits` and `dismissed` empty.

`evidence` is required, except for a credential. For one, use category `exposure` and an empty string
and let `file` and `line` point to it. The report also masks anything shaped like a credential, but that
is a backstop, not permission to quote one.

## Length

The report has to be quick to review, so the helper rejects these when they run long:

| Field | Limit | What belongs there |
| --- | --- | --- |
| `summary` | 75 words | The overall picture, not the method or the findings restated |
| `why` | 60 words | What someone can do and what it takes. Leave out confidence, other line references, and severity reasoning |
| `recommendation` | 45 words | The specific change to make |
| `severity_reason` | 25 words | Only when the rating needs explaining |
| `not_checked` | 6 entries, 30 words each | Gaps that limit trust in the findings, not what the report already says or how you worked |

## Categories

`steering`, `execution`, `autonomy`, `reach`, `exposure`, or `other`, as described in `SKILL.md`. Every
`steering` finding is also listed in the report's own section, so the reviewer sees those first.

## Severity

Rate what the configuration allows in this repository, not how alarming the text looks.

| Severity | Meaning |
| --- | --- |
| `high` | Reaches code execution, credential or data loss, or a hidden security result, with no further human step |
| `medium` | Reaches the same outcomes, but needs a human action, an extra condition, or a change that review might catch |
| `low` | Weakens a safeguard or widens access without reaching those outcomes by itself |
| `info` | Worth a reviewer's attention, with no demonstrated risk |

If a scan ran, rule severities map to this scale as `ERROR` to `high`, `WARNING` to `medium`, and `INFO` to
`low`.

Text or settings that hide a whole class of security results from people are at least `medium`, even if
the current wording looks benign, because they decide what people are told. Narrower suppression, such as an
exception for named files or a confidence threshold, rates on the scale like anything else, based on what it
can hide.
