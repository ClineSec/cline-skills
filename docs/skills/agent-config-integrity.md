# agent-config-integrity

Assesses the files that steer coding agents: instruction files, rules, skills, hooks, MCP servers, and
permission settings. It shows what someone who can commit to a repository could make an agent do on a
developer's machine, and ends in a report a person reviews and signs. It is read-only and never executes
what it finds.

Use it before trusting an unfamiliar repository, when reviewing a repository's agent setup, or as part of
a release review. To assess an MCP server's own code, or a vendor, use something else: this looks at the
configuration that connects things, not at what they do internally.

## Before you start

- Python 3.9 or newer.
- A session started **outside** the repository you are assessing, such as in a sibling folder. A session
  started inside it may already have loaded its instructions and fired its hooks, so the skill stops and
  asks you to start again.

## Run it

Start a session outside the repository and ask:

> Use agent-config-integrity to assess /path/to/repo.

Add "and my user-level agent config too" to include configuration such as `~/.claude/settings.json`. It is
left alone unless you ask.

The assessment is AI-driven and needs no security tools. To add a rule pack, name it, as in "also run the
rules at /path/to/rules". The helper can run OpenGrep or Semgrep rules, which you need to have installed. The
agent-config rules in [`cline-ai-rules`](https://github.com/ClineSec/cline-ai-rules) are written for this.

## What it does

1. Lists the agent configuration in the repository, including files Git ignores.
2. Has the agent read the configuration as data and work out what it allows.
3. If you named rules, scans a temporary copy of those files, and has the agent confirm or dismiss each hit.
4. Checks the findings against the files and writes the report.

It writes only to its output folder, which is
`agent-config-integrity-<repo name>` in your session's folder unless you say otherwise. Nothing in the
repository changes, and nothing is sent anywhere by the skill.

### Why a requested scan uses a copy

A repository can affect what a tool run against it reports. Scanners normally respect `.gitignore`, skip
directories such as `tests/` and `vendor/`, and honor inline `nosemgrep` comments, all of which are sensible
for your own code and all of which an untrusted repository can use to hide its config. The copy has no Git
metadata or ignore files, keeps those directories in scope, and is scanned with inline suppressions turned off.

The same reasoning applies if you run the rule pack yourself on a repository you don't trust.

## What you get

`report.md` has the same sections on every run:

| Section | What it holds |
| --- | --- |
| Summary | Counts by severity and what the configuration allows, in plain language |
| Steering instructions | Text or settings in the repository that change what people are told about security, listed first because they affect how far you can trust everything else |
| Findings | File, line, the offending text, why it matters, the recommended change, and whether a rule or the agent's judgment found it |
| Dismissed scanner hits | Any rule hit the agent decided was not real, with its reason |
| Configuration assessed | Each agent configuration file, and a count of the automation files listed |
| Limits | Whatever was not checked, such as symlinks not followed |
| Sign-off | Blank, for you |

Quoted evidence has to be present in the file at the cited line, and any rule hit has to end up in a finding or
a dismissal, or the report isn't written. Credentials are never quoted.

If the repository has PolicyRelay guidance, the skill reports configuration that breaks it. That guidance can
add requirements but can't excuse anything, since it lives in the repository too. Without it, the report does
not mention PolicyRelay.

## What it can't see

Only configuration on disk. Settings pushed by device management, a vendor's cloud console, or a SaaS product's
own agent features are out of reach, as is anything that happens when the configuration actually runs.

Agent judgment varies between runs, so two reports on the same repository can word things differently or differ
on a judgment call. The report's structure doesn't change. If you need results that repeat exactly, name a rule
pack as well.

## What to do next

Read the steering instructions first, then the findings, and fill in the sign-off. The skill does not change the
repository. To act on a finding, ask for the change as a separate request. See
[`SKILL.md`](../../skills/agent-config-integrity/SKILL.md) for the agent's instructions.
