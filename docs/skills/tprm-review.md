# tprm-review

Researches a vendor before you connect it, and ends in a report a person reviews and signs. You give it the documents
you downloaded from the vendor's trust center. It reads them, researches the company independently, and reports where
the vendor's account doesn't hold together, what it leaves unsaid, and a recommended verdict with the evidence behind it.

Use it when someone wants to adopt a tool, renew a vendor, or re-check one whose subprocessors changed. It works from
what is written down: it doesn't contact the vendor or test its product. To assess an MCP server or a code repository, use
a skill made for that.

## Before you start

- Python 3.9 or newer, and an agent with web access for the research.
- A folder holding the vendor's documents: a SOC 2 report, a security whitepaper, the DPA or contract, the subprocessor
  list, whatever you have. Download them yourself, because trust centers are often gated. PDF, Word, Excel, PowerPoint, HTML,
  and text all work. Unpack any archives first.
- A session started **outside** that folder, so that nothing placed in it can load as instructions.
- Check that your agreement with the vendor lets you put its documents through your agent. Trust-center material is often
  under NDA, and your agent's model provider sees what the agent reads. The skill keeps document text out of web searches
  and out of everything else it does.

## Run it

Start a session outside the documents folder and ask:

> Use tprm-review on Example Corp. The documents are in /path/to/example-corp-docs. We'd connect it to our HR system, for
> recruiters, and it would see applicant records.

To compare with an earlier review, or measure against your own policy:

> Use tprm-review on Example Corp. The documents are in /path/to/docs. The last review is in /path/to/old-review, and our
> vendor policy is at /path/to/vendor-policy.pdf.

If you leave out the vendor, the folder, or the intended use, it asks.

## What it does

1. Copies the documents to its output folder and extracts their text. Where it can't, such as a scanned page, the agent
   transcribes what it can read and the report marks those quotes.
2. Reads every document whole and looks for text aimed at changing what an assessor concludes.
3. Researches the company from public sources: who it really is, whether its claims hold up, whether its auditor can be
   relied on, and what it didn't mention. The depth follows the risk of what you'd connect.
4. Compares everything for conflicts, and records what nobody says.
5. Challenges its own findings against their sources, works out a recommendation, checks every quote, and writes the report.

It writes only to its output folder, which is `tprm-review-<vendor>-<date>` in your session's folder unless you say otherwise.
Nothing is sent to the vendor. Web searches carry only public facts.

## What you get

`report.md` has the same sections on every run, laid out the way a vendor risk assessment usually is: the decision first, then
findings, then the supporting detail, with evidence in appendices. Word limits on each field keep it short without dropping
findings. `vendor-questions.md` holds the questions alone, because the report itself shouldn't go to the vendor.

| Section | What it holds |
| --- | --- |
| Executive summary | The recommendation and reasoning, conditions with owners and due points, and when to reassess |
| Scope and inherent risk | What you'd use the vendor for, the data involved, and the risk that engagement carries |
| Steering instructions | Text that tries to change the result, and what was done about it |
| Findings | A register of every finding by severity, then each conflict with both statements quoted, then the gaps |
| Independent assurance | Each attestation's opinion, period, age, scope, exceptions, subservice organizations, and the controls it expects from you |
| Control posture | Nine standing questions about data use, location, AI, access, protection, assurance, incidents, resilience, and exit |
| Subprocessors | Each one, with model providers first, and what changed since the last review |
| Vendor profile | Legal entity, jurisdiction, ownership, history, scale, finances, leadership, foreign influence, regulatory standing, and insurance |
| Public record | Incidents, regulatory actions, litigation, and corporate changes, marked established, reported, alleged, or vendor-stated |
| Policy fit | How the vendor measures against your policy, if you gave one |
| Questions for the vendor | One list, each tied to its finding |
| Not checked | What wasn't read or examined. Nothing listed here is a clean result |
| Sign-off | Blank, for you |
| Appendices | Claims tested, documents reviewed, research log and sources, dismissed leads, and every quote behind the tables |

The recommendation is approve, approve with conditions, reject, or insufficient evidence. The helper won't accept "approve"
while there are conditions, a critical or high finding, a contradicted answer, an unmet policy requirement, or no public
research, and it won't accept "approve with conditions" unless a condition addresses each critical or high finding.

**Inherent risk** comes from what you'd connect, never from the vendor's documents. **Residual risk** is the worst open finding, one
level lower where a condition addresses it. The helper works out both by a [fixed rule](../../skills/tprm-review/references/report-contract.md#risk-ratings),
so the same facts give the same rating. If your organization tiers vendors its own way, use that.

`assessment.json` beside the report has the same content as structured data, and it's what a later review compares with.

### How far to trust the quotes

The report's header says how many quotes rest on what:

- **Extracted text.** Found in text the helper pulled from your file. This is the strongest check.
- **Agent transcripts.** Found in the agent's transcription of a page the helper couldn't read, such as a scan. Check these
  against the original, especially on an opinion or signature page.
- **Saved public copies.** Found in a copy of the page the agent saved. That shows the agent's copy says it, not that the live
  page does.
- **Not machine-checked.** The agent's tools couldn't save the page. Open the address yourself.

Public-source addresses are shown as plain text, not links, because they came from what the agent read. Open the ones your
decision rests on.

## What it can't see

It reads documents and public sources, so it can't tell you how the service really behaves, or whether your copies are the
latest. It can't read what's behind a login. A clean result means the written record is consistent, not that the vendor is
safe. Text in images isn't read unless the agent can see it and transcribes it, and PDF extraction reads hidden text but can't
tell you it was hidden.

Agent judgment varies between runs. The shape of the report doesn't, and serious discrepancies should recur, but minor ones
and wording can differ. Treat what it says about a real company with care: it's a working assessment based on what the agent
found, and a person has to check it before relying on it or repeating it.

## What to do next

Read the steering instructions first, correct the engagement if it's wrong, then go through the discrepancies and check the
sources behind any that affect your decision. Send the questions to the vendor, and fill in the sign-off once you've decided.
See [`SKILL.md`](../../skills/tprm-review/SKILL.md) for the agent's instructions.
