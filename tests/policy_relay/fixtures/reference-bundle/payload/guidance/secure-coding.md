---
{
  "task": "secure-coding",
  "title": "Secure coding",
  "provenance": [
    {
      "sourceId": "fictional-engineering-security-standard",
      "sourceTitle": "Fictional Engineering Security Standard",
      "sourceRevision": "2026.1",
      "sourceLocator": "Section 4.2, Change Safety",
      "distilledAt": "2026-08-27"
    }
  ]
}
---

# Secure coding

## Applicability

Apply this guidance when adding, changing, or reviewing code that accepts input, crosses a trust
boundary, handles credentials, or changes authorization-sensitive behavior.

## Normative guidance

- The change MUST identify untrusted inputs and validate them at the boundary before use.
- Data access MUST use the platform's parameterized interface; code MUST NOT construct executable
  queries or commands by concatenating untrusted text.
- Secrets MUST NOT be embedded in source, fixtures, logs, or error messages.
- Authorization-sensitive changes MUST include a negative test proving a disallowed actor or input
  is rejected without exposing protected data.
- Reviewers SHOULD prefer the smallest change that preserves existing security boundaries.

## Exceptions and escalation

An exception requires a named owner, rationale, compensating control, approving authority, and
expiry before the change is accepted. If the required authority or policy meaning is unclear, stop
the affected change and escalate to the designated security owner; do not silently weaken a guard.

## Source provenance

Distilled from `fictional-engineering-security-standard`, revision 2026.1, Section 4.2. This is a
fictional reference source used only to demonstrate the contract.
