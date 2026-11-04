---
{
  "task": "secure-coding",
  "title": "Secure coding",
  "provenance": [
    {
      "sourceId": "fictional-engineering-security-standard",
      "sourceTitle": "Fictional Engineering Security Standard",
      "sourceRevision": "2026.1",
      "sourceLocator": "Section 4.2, Change safety",
      "distilledAt": "2026-08-27"
    },
    {
      "sourceId": "fictional-review-handbook",
      "sourceTitle": "Fictional Engineering Review Handbook",
      "sourceRevision": "rev-17",
      "sourceLocator": "Chapter 6, Security exceptions",
      "distilledAt": "2026-08-27"
    }
  ]
}
---

# Secure coding

## Applicability

- Apply when code accepts untrusted input, handles credentials, or changes authorization behavior. Sources: `fictional-engineering-security-standard`.

## Normative guidance

- MUST NOT embed secrets in source, fixtures, logs, or error messages. Sources: `fictional-engineering-security-standard`.
- MUST include a negative authorization test for security-sensitive changes. Sources: `fictional-engineering-security-standard`, `fictional-review-handbook`.
- MUST validate untrusted values before using them at a trust boundary. Sources: `fictional-engineering-security-standard`.

## Exceptions and escalation

- An exception requires a named owner, rationale, compensating control, approving authority, and expiry. Sources: `fictional-engineering-security-standard`, `fictional-review-handbook`.
- If authority or policy meaning is uncertain, stop the affected change and escalate to the fictional security owner. Sources: `fictional-review-handbook`.

## Source provenance

- `fictional-engineering-security-standard` is identified by its exact revision and locator in the metadata provenance record.
- `fictional-review-handbook` is identified by its exact revision and locator in the metadata provenance record.
