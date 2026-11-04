# mcp-preflight

Answers one question before an MCP server connects anywhere: **is it safe for this team to use this server, with this data,
in this agent?** It ends in a recommendation with conditions that a person reviews and signs. The answer is about that use,
so the same server can be fine for one team and wrong for another.

It works on a commercial server with only documentation to read, an open-source server with all of its code to read, or
anything in between. The question stays the same, and each answer says what it rests on: documented, read in code,
configured, or observed.

To check the agent configuration already in a repository, use `agent-config-integrity`. To assess a vendor's contract, data
terms, and subprocessors, use `tprm-review`; this skill can run that as part of an assessment if you want both.

## Before you start

- Python 3.9 or newer.
- A session started **outside** any source or documents you're assessing, and without the server connected.
- Whatever you have on the server: a repository, a package archive, documentation, a configuration entry, or a saved tool
  listing. A name is enough to start if the agent has web access.

## Run it

> Use mcp-preflight on the Acme CRM MCP server. Our sales team would use it in their coding agent, with customer contact
> records. It would sit alongside our email server. Docs are at https://example.com/docs/mcp.

> Is it safe to let the platform team use the server in /path/to/clone? They'd use it on staging infrastructure only.

## What it will ask

Only what your request doesn't already say, in one message:

- **The use:** who would use it, in which agent, with what data, and what else is in the session. If you don't know, it
  assumes the widest reasonable use and says so.
- **Whether to connect**, when there's something it could connect to. Offline is what it suggests, because whether to connect
  is the thing being decided. If you don't answer, it stays offline.
- **How far to go on the vendor**, when a company stands behind the server. There's no reason to ask about an open-source
  project with no vendor, so it doesn't.

## If you already connected it

It tells you that the server's descriptions have already reached the session, and suggests starting a clean session and
disconnecting the server until there's an answer. It won't use the server's tools either way. If you carry on there, the report
says so and can't recommend a plain yes.

## What connecting does

Only if you say yes, the helper connects over HTTP and asks what the server exposes: its tools, prompts, and resources. It asks
as a generic client and, if it knows the name, again as your team's agent, because a server can show a clean listing to anything
that looks like a scanner. Its client can send those list requests and nothing else, so it has no way to call a tool, read a
resource, or answer a request from the server. It doesn't follow redirects, and it won't send a credential over unencrypted HTTP
to another machine.
Credentials come from an environment variable you set before starting the session, and they aren't written anywhere. Use a
throwaway account with the least access you can, because that credential goes to a server nobody has cleared yet.

It never launches a server, so it can't observe a local one. If you have a listing from elsewhere, give it that as JSON. A server
that needs a browser sign-in works the same way.

## What it changes

It writes only to its output folder, which is `mcp-preflight-<server>` in your session's folder unless you say otherwise. It
doesn't install, launch, configure, or approve anything. Your agent's model provider sees what the agent reads, as in any
agent session, and it may use the web to read public documentation.

## What you get

`report.md` has the same sections on every run, in the order security assessment reports usually take, and the executive summary
stands alone. The helper enforces a word limit on each field, so reports stay short without losing findings: more entries are
always allowed.

| Section | What it holds |
| --- | --- |
| Executive summary | The recommendation, why, its conditions and how to verify them, and when to review it. For not yet or no, what to do before asking again |
| Scope | The use being judged, any assumptions, and whether a vendor review was part of it |
| Findings summary | Every item by severity, with the conditions that contain it |
| Steering instructions | Text aimed at this assessment or at agents using the server |
| Findings | What could go wrong in this use and where sources disagree, each with evidence, impact, and remediation |
| Tools | Each tool's effects, what it touches, and whether this use should have it |
| Questions | What it can do, who it acts as, where data goes, where it runs, whether content can steer it, what it combines with, who owns it and how it changes, and who could tell, stop, and remove it |
| Policy guidance | Only if a policy was supplied |
| Changes since the previous assessment | Only with an earlier assessment, showing tools added, removed, or changed |
| Not checked | What wasn't established. Nothing listed here is a clean result |
| Sign-off | Blank, for your decision, the accountable owner, and the expiry |
| Appendices | Evidence with addresses and digests, the method and severity scale, and dismissed leads |

Findings can carry an OWASP MCP Top 10 or CWE label. `report.sarif` holds the same items in SARIF 2.1.0, for tools that track
findings.

The recommendation is one of yes, yes with conditions, not yet, or no. Not yet means a missing fact could change the answer and
no condition can stand in for it, so anything you could do yourself becomes a condition instead. The helper won't write a plain
yes while something is unsettled, some of the code couldn't be read, or nothing beyond documentation shows how the server behaves.
It won't write yes with conditions if a serious item or an open question has no condition addressing it, and it won't write not
yet once the evidence has settled the question. Any yes needs a review date within a year. A yes with conditions also says in its
headline whether the setup as you proposed it fits or isn't cleared, because conditions can narrow a use until it's no longer what
you asked about.

Every quote is checked against its source, and must be long enough to identify one place. That shows the words are there, not that
they prove the point. The agent can have the helper download a documentation page itself. A page the agent saved is marked in the
report, because the helper can't confirm those are the page's own words.

If you have PolicyRelay guidance, run from the folder that holds it or name it in your request, and the report measures the use
against it. It can only add requirements. Without it, the report doesn't mention PolicyRelay.

## What it can't see

It assesses one version or instance at one moment. A hosted server can change after you've signed, which is why the report
records a digest of the tool definitions and a review date. It never calls a tool, so it doesn't see what tools return or anything
that only happens when one runs. Without a listing it can't confirm what's deployed, and without code it can't confirm how tools
are built. Judgment varies between runs, so a person signs it.

## What to do next

Read any steering first, correct the Scope section if it describes the wrong use, then work through the conditions and Not
checked, and fill in the sign-off. Applying a condition is a separate request. See
[`SKILL.md`](../../skills/mcp-preflight/SKILL.md) for the agent's instructions.
