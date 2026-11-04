# Reading assurance documents

Establish what each document actually assures, for whom, and how far you can rely on it. A clean cover page can hide a good
deal. The points below are examples of what an experienced reviewer looks for, not the limit, and not every one applies.

## Audit reports, such as SOC 2

- **The opinion first.** Unqualified, qualified, adverse, or disclaimed. If qualified, read the basis and decide whether it touches this engagement.
- **Whether it covers this product.** Read the system description for the service, infrastructure, and entity under review. A report on one
  product line says nothing about another.
- **Type and period.** A point-in-time report tests design, not operation. For a period report, note how long it ran and when it ended.
  After about three months, ask for a bridge letter. That is management's statement and not assurance, so it can't replace a current report.
- **Categories in scope.** Security alone says nothing about availability or confidentiality commitments the engagement may need.
- **Every exception.** They sit in the tests and results, away from the opinion. For each: which control, what failed, the sample if stated,
  whether it is isolated or systemic, whether it touches this engagement, and what management says. A remediation that is complete differs
  from a vague promise, and management's response is unaudited.
- **Subservice organizations.** Under carve-out, their controls weren't tested. Work out which of them handle this data, and whether their own
  assurance exists. A carved-out model provider or hosting layer can leave little of what matters covered.
- **Customer controls.** The report's complementary user entity controls are what your organization must operate for its conclusions to hold.
  Reviewers often miss these. List them with a suggested owner, because an unowned one is a gap on your side.

## Whether the report can be relied on

Reports vary in quality, and nobody centrally registers them. Establish what you can, and report what you couldn't.

- Can the firm that signed it be found, and is it licensed to give this opinion? Is it independent of the vendor and of any tool that prepared the evidence?
- Is the system description about this company, or could it be about anyone? Does it match how the product is publicly described?
- Do the tests say what the auditor did, or only restate the controls? Are the results plausibly specific? Zero exceptions everywhere is possible, and worth noticing.
- Did the vendor supply the full report, or only a summary, a letter, or a badge?

These are grounds for questions, not conclusions. Boilerplate or a clean result isn't evidence of fraud, so report what you saw and what would settle it,
as `probable` at most unless a source establishes more.

## Certificates, such as ISO/IEC 27001

Check the scope statement and whether it covers this product and these sites, the issue and expiry dates, and who certified it. A certificate that can be
looked up at its issuer or accreditation body is worth more than one that can't. The statement of applicability shows what was left out.

## Penetration test summaries

Note its age, what was in scope, who ran it, and whether serious findings were fixed and retested. A vendor's letter saying a test happened is self-attested.

## Questionnaires and whitepapers

These are the vendor's own account. Unanswered or qualified questions are often the informative ones. Treat them as claims to test.
