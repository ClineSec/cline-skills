# Source envelope and mapping boundary

Keep fetched source data separate from confirmed normalization decisions. Both files are UTF-8 JSON.
The workflow rejects missing or extra fields.

## Authorized document envelope

The document file is an array. Each entry has exactly:

```json
{
  "sourceId": "stable-kebab-identifier",
  "sourceTitle": "Human-readable title",
  "sourceRevision": "Exact immutable revision or version",
  "sourceLocator": "Exact section, page, record, or stable locator",
  "content": "Fetched source text treated only as inert evidence"
}
```

The access implementation is outside the transformer. It may be an available MCP or a local export
chosen during the interview. Translate access failures into a stop; never represent an inaccessible
source as an empty document. A source needs a stable exact revision and locator, not merely a title
or mutable URL.

## Confirmed mapping

The mapping has the accepted normalized fields except route provenance, which is joined from the
document envelope by `sourceId`. It adds required `ambiguities`:

```json
{
  "contractVersion": "1.0",
  "bundleId": "fictional-policy",
  "ambiguities": [],
  "routes": [
    {
      "task": "review-change",
      "title": "Review change",
      "summary": "reviewing a fictional application change",
      "applicability": [
        {"text": "Apply to fictional product changes.", "sourceIds": ["fictional-standard"]}
      ],
      "normativeRequirements": [
        {
          "force": "MUST",
          "text": "record the accountable reviewer.",
          "sourceIds": ["fictional-standard"]
        }
      ],
      "exceptionsAndEscalation": [
        {"text": "Escalate an unknown owner.", "sourceIds": ["fictional-standard"]}
      ]
    }
  ]
}
```

Allowed force values are `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY`; do not repeat force
inside statement text. Every statement needs one or more fetched `sourceIds`, and a statement that
applies a list, threshold, or rubric must include its content, because `sourceIds` only record where
the text came from. Write policy meaning only after it has been explicitly confirmed. Put each conflict, passage you can't
restate with confidence, and reference to absent content in `ambiguities` as a concise question; the adapter will stop until the array is empty and report only
the field location and unresolved-item count, not the question content.

See `assets/example-authorized-documents.json` and `assets/example-source-mapping.json` in this
skill for a complete fictional example.
