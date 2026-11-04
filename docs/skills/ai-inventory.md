# ai-inventory

Finds the AI in a repository and writes it down as a CycloneDX AI-BOM: SDKs, models, hosted endpoints, prompts,
MCP servers, agent frameworks, vector stores, and coding agents. It also says what it couldn't see, and ends in a
report a person reviews and signs. It is read-only and never executes what it finds.

Use it when someone asks what AI a system uses or where its data goes, or to add an AI-BOM next to your SBOM. To
judge whether agent configuration is dangerous, or to assess an MCP server's own code or a vendor, use something
else: this records that those things exist, not whether they are safe.

## Before you start

- Python 3.9 or newer.
- A session started **outside** the repository you are assessing, such as in a sibling folder. A session started
  inside it may already have loaded its instructions and fired its hooks, so the skill stops and asks you to start
  again.

## Run it

Start a session outside the repository and ask:

> Use ai-inventory on /path/to/repo.

It asks you nothing unless the session is inside the repository.

## What it does

1. A helper script reads the repository and recognizes common AI packages, model names, endpoints, and config. It
   ignores `.gitignore` and similar files, because a repository shouldn't get a say in what is inventoried.
2. The agent works out what the system does and looks for what no table would recognize, such as a model reached
   through an in-house wrapper. It keeps or dismisses each uncertain lead, with a reason.
3. The helper checks the agent's evidence against the files, then writes the BOM and the report.

It writes only to its output folder, which is `ai-inventory-<repo name>` in your session's folder unless you say
otherwise. Nothing in the repository changes, nothing it finds is contacted, and the skill sends nothing anywhere.

## What you get

`ai-bom.cdx.json` is a CycloneDX 1.6 document, so it can go through the same pipeline as your SBOM. Models are
`machine-learning-model` components, packages have package URLs, and hosted endpoints are services marked as crossing a
trust boundary. Each item records where it was found, what found it, and whether it's in use or optional. Anything
docs, examples, or tests only mention stays out of the BOM. Prompt text and credentials are left out too.

`report.md` has the same sections on every run:

| Section | What it holds |
| --- | --- |
| Summary | What AI the system uses and where its data goes, with counts |
| Steering instructions | Text in the repository that tries to change what gets inventoried, listed first because it affects how far you can trust the rest |
| Inventory | Every item by category, with version, provider, status, confidence, location, and what found it |
| Only mentioned | Names and locations of what docs, examples, or tests refer to, and nothing here reaches |
| Data flows | What data moves where and what model output goes on to change, which a BOM can't hold |
| Dismissed leads | Everything the agent decided wasn't real, with its reason |
| Coverage | How much of each AI surface this run could reach, and what the agent looked at beyond the helper's leads |
| What this cannot see | The limits of any repository-based inventory |
| Limits | What wasn't checked on this run, such as skipped files |
| Sign-off | Blank, for you |

If the repository has PolicyRelay guidance, the report also has a Policy section. That guidance can add requirements
but can't excuse anything, since it lives in the repository too. Without it, the report does not mention PolicyRelay.

## What it can't see

Only what is in the repository. A SaaS product's built-in AI, the assistants people use in a browser, and tools other
teams adopted won't appear, so this covers one part of an organization's AI inventory and not all of it. Neither will
a model chosen in a deployment's environment, or the provider behind a vendor's API or your own gateway. The report
says where the trail stops.

The helper recognizes a known set of names. Finding anything else depends on the agent's judgment, so two reports on
the same repository can differ on those items. Helper results and the report's structure don't change.

## What to do next

Read the steering instructions first, then check the inventory and the limits, and fill in the sign-off. The BOM can
name internal hosts and paths, so review it before sharing it. See
[`SKILL.md`](../../skills/ai-inventory/SKILL.md) for the agent's instructions.
