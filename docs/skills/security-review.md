# security-review

Reviews a repository, a release, or the changes since an earlier commit for what someone could do to it that they
shouldn't be able to, and ends in a report a person reviews and signs. It is read-only and never runs what it finds. The agent's judgment decides
what matters and what it concludes; the report's sections, fields, and severity scale stay the same on every run.

Use it for a release review, or before you trust a codebase. It is the judgment layer, not a scanner: run your
scanners as usual and give it their results. To assess only the configuration that steers coding agents, use
`agent-config-integrity`. It doesn't write fixes; ask for those separately.

## Before you start

- Python 3.9 or newer. Git, if you are reviewing a commit, tag, or range.
- A session started **outside** the repository, such as in a sibling folder. A session started inside it may
  already have loaded its instructions and fired its hooks, so the skill stops and asks you to start again.
- Optional, and recommended: scanner results in SARIF. Without them the report says those classes weren't run.

## Run it

Start a session outside the repository and ask:

> Use security-review on /path/to/repo.

For a release:

> Use security-review on /path/to/repo for tag v2.4.0, compared with v2.3.0. Scanner results are in
> /path/to/results.sarif.

For an incremental scan of what changed:

> Use security-review on /path/to/repo, for the changes since v2.3.0.

The base has to be in your clone, so a shallow clone may need to fetch it first. To reuse the list of attack surface from
an earlier review, add: "Start from the surface.json in /path/to/earlier/review." Uncommitted changes aren't covered by
an incremental scan, so commit them first.

In Claude Code, type this as a request or use `/security-review` followed by the path. Claude Code also has a
built-in `/security-review` for reviewing pending changes. In testing, a project-level copy of this skill took its
place; a user-level install hasn't been confirmed to, so check that the first run says it is preparing a snapshot.

## What it does

1. Copies what is under review into a snapshot in its output folder, lists leads for steering text, and counts
   scanner suppression comments.
2. Has the agent work out what the system does and who could abuse it.
3. Reports any text in the repository that tries to change a security outcome, then examines what it pointed
   away from.
4. Lists the attack surface as units of work. For an incremental scan, these are the units the changes affect, and
   every changed file has to be accounted for.
5. Gives each unit its own reviewer, where the agent can start other agents. It isn't done until every unit has a
   result or a stated reason it was skipped.
6. Merges the results. Every candidate ends up as a finding or is dismissed with a reason you can read.
7. Checks every quote against the snapshot and writes the report.

### What it costs

A full review runs many agents, so it uses far more of your plan or budget than a single prompt, and it reports more,
including things that turn out to be wrong. An incremental scan costs in proportion to what the changes affect, unless
they touch something shared, such as a permission check. To cap a full review, tell it the most units you want reviewed.
The rest are listed as not reviewed. The number of findings depends heavily on the model: on one test target, the same
review gave about 70 findings in one host and more than 300 in another.

A long review can be interrupted, including by a model provider's safety filter, which can mistake security work for
misuse. Results already written stay in the output folder. To continue, start a new session and ask for the same review
with the same output folder. The skill picks up the units still pending instead of starting over.

It asks only what it can't infer, such as which release you mean. It writes only to its output folder, which is
`security-review-<repo name>` in your session's folder unless you say otherwise. Nothing in the repository changes,
and the skill sends nothing anywhere. Your agent's model provider sees the code, as with any agent session.

### Why it reads a snapshot

A repository can affect the tools run against it. Its Git configuration can run commands, its attributes can hide
changes from a diff, its ignore files can hide code from a search, and its instruction files can load into an agent
that opens them. So the helper runs Git only against a temporary repository that has clean configuration and
borrows the target's objects. The copy has no links or executable files, and agent and ignore files are renamed so
that nothing honors them.

A handed-over `.git` can also lie, so the helper checks every object it relies on against its hash, and it refuses a
repository that borrows objects from elsewhere or whose `.git` points at another repository. It lists anything on
disk that isn't in the reviewed commit, and the report refuses to render if the snapshot changes after it's taken.
If you get one of these refusals, treat it as something to investigate. A fresh clone from a source you trust is the
usual next step.

By default it reviews a commit, so uncommitted files aren't in scope and the report names exactly what was
reviewed. Ask for the working tree if that's what you want. Likely credential files such as `.env` are then left
out of the snapshot and listed under Not checked.

## What you get

`report.md` has the same sections on every run. See [an example from a fictional target](security-review-example.md).

| Section | What it holds |
| --- | --- |
| Executive summary | The release position, counts by severity, what someone could do, and how much was covered |
| System under review | What the agent understood the system to be, so you can correct a wrong premise |
| Steering instructions | Text that tries to change a security outcome and what was done about it, plus a count of scanner suppression comments |
| Findings summary | One row per finding: severity, title, CWE, confidence, and location |
| Finding details | For critical, high, and medium: quoted evidence, what an attack needs, why it matters, the recommended change, and where the reasoning is |
| Not checked | What wasn't examined. Nothing listed here is a clean result |
| Sign-off | Blank, for you |
| Appendix A: Coverage | How many units were listed and reviewed, how many files reviewers report reading, and what was examined, with its conclusion |
| Appendix B: Severity scale | What each rating means |
| Appendix C: Scanner territory | Classes a deterministic tool should cover here, and whether results were supplied |
| Appendix D: Dismissed leads, scanner hits, and candidates | Everything set aside, with its reason |

The release position comes from the counts: any critical or high finding means issues to resolve or accept in writing
before release. Every lead and scanner result has to end up used or dismissed, and quoted evidence has to be at the
cited line, or the report isn't written. Credentials are never quoted. `findings.json` beside it has the same content
as structured data, and `report.sarif` has the findings in SARIF, for tools that read it.

The report is kept short on purpose. Each finding covers one root cause, and each field has a word limit. There is no
limit on entries, so a long review gets more findings rather than thinner ones. Details for low and info findings are in
`report-lower-severity.md` beside the report. Each reviewer's full reasoning stays in `units/`, and each finding points
to it.

### How it lines up with common practice

No single standard mandates the format of a security review report. The shape follows the
[reporting structure in the OWASP Web Security Testing Guide](https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md),
which is itself offered as a suggestion: an executive summary, a findings summary, finding details, and appendices that
include the severity scale. Findings name a [CWE](https://cwe.mitre.org/), and `report.sarif` uses
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), an OASIS standard. Critical and high both become
SARIF's `error`, and the exact severity stays in each result's properties. Steering and coverage appear only in
the report. It gives no CVSS scores, because a score needs facts about the deployment that a code review doesn't have.

If the repository has PolicyRelay guidance, the report cites it and adds a section for it. That guidance can add
requirements but can't excuse anything, since it lives in the repository too. Without it, the report doesn't mention
PolicyRelay.

## What it can't see

It reads code and doesn't run it, so it can't observe runtime behavior, deployed configuration, or anything outside
the repository. Submodules and followed links aren't reviewed, and the report says so.

Agent judgment varies between runs. The shape of the report doesn't, and serious findings should recur, but minor
findings and wording can differ. This is why a person signs it.

## What to do next

Read the steering instructions first, correct the system description if it's wrong, then work through the findings
and Not checked, and fill in the sign-off. To act on a finding, ask for the change as a separate request. See
[`SKILL.md`](../../skills/security-review/SKILL.md) for the agent's instructions.
