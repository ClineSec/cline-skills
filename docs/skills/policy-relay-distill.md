# policy-relay-distill

Turns policy documents into short, task-specific guidance for agents, and commits the result to a
local policy repository. Use it to create that repository and whenever a policy changes.

It reproduces your policy faithfully, without the prose and background that only people need. It doesn't
write policy, make it stricter, or fill gaps, so a gap in your policy shows up as a gap in the guidance.
Fix it in the policy, and every agent then gets the same answer.

To connect a repository to the result, use [`init-policy-relay`](init-policy-relay.md). For how the
pieces fit together, see the [PolicyRelay overview](policy-relay.md).

## Before you start

- Python 3.10 or newer and Git, on macOS or Linux.
- Access to the policy documents, through a tool your agent is already connected to or as local
  files.
- A decision about who settles what the policy means. The agent drafts, and you confirm.

## Run it

Ask your agent:

> Distill our secure coding and vulnerability policies into a new PolicyRelay policy repository at
> `/absolute/path/to/our-policy`.

## What it asks

- How to reach the documents, and which ones are in scope.
- Where the policy repository is, and whether to create or update it.
- The distillation date, and who resolves questions about policy meaning.

## How it works

1. **Collect the sources.** The agent records each document's exact revision and location, so every
   piece of guidance can be traced back to its source.
2. **Agree on the mapping.** The agent drafts routes and requirements for you to confirm. A route is
   one kind of task, such as `secure-coding`. Requirements use `MUST`, `MUST NOT`, `SHOULD`,
   `SHOULD NOT`, or `MAY`. Anything unresolved is recorded as a question, and the workflow won't
   continue until it's settled.
3. **Review.** The agent generates and validates the bundle outside your repository. It then checks the
   routes against the sources for dropped or added rules, and rereads each route as if it had nothing else.
4. **Preview.** The agent shows you what that review found, anything left out on purpose, where the policy
   is vague or silent, and the operation, routes, file changes, and index.
5. **Confirm and commit.** After you confirm, it creates one local commit that changes only `bundle/`,
   on `main`. Running it again with identical input changes nothing.

## What belongs in a route

Agents using a route have only the bundle, not your source documents. A route that says "use an
approved provider" is no use unless it also lists the approved providers, so lists, thresholds, and
definitions get copied in. The agent stops and asks if a source refers to something that isn't in scope,
if sources contradict each other, or if it can't tell what a passage requires. A vague term doesn't
stop it: the route keeps the policy's wording, and the preview points it out.

Copied content reaches every connected repository, so check during the preview that all of them should
see it. It also stays as it was until you distill again, so do that whenever a copied list changes.

For a complete fictional example, see the
[documents](../../skills/policy-relay-distill/assets/example-authorized-documents.json) and
[mapping](../../skills/policy-relay-distill/assets/example-source-mapping.json) files.

## What you get

```text
bundle/
├── manifest.json
└── payload/
    ├── index.md               a small router listing each route
    └── guidance/<route>.md    applicability, requirements, exceptions, and sources
```

## What to do next

The skill never creates a remote or pushes. When you're ready:

1. Push the policy repository somewhere your consumers can reach it, normally a private repository.
2. Protect its branch. Bundles are validated but not signed, so anyone who can write to that branch
   controls the guidance agents receive.
3. Connect repositories with [`init-policy-relay`](init-policy-relay.md).

Later changes reach every connected repository at its next agent session once they're on that
branch, so review them before you push.

The [skill instructions](../../skills/policy-relay-distill/SKILL.md) hold the full workflow, and its
references define the
[bundle contract](../../skills/policy-relay-distill/references/policy-bundle-contract.md).
