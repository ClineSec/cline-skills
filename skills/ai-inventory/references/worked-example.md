# Worked example

A fictional repository, `orderly`, is a Python service that summarizes customer support tickets.

## What the helper reported

Its `walk.json` had these detections:

- `D001`, `openai` 1.40.0 from `requirements.txt`, imported nowhere in application code.
- `D002`, `gpt-4o-mini`, seen only in `tests/test_summary.py`, marked for review.
- `D003`, `.mcp.json` server `tickets`, an unpinned package run with `npx`.
- `D004`, Claude Code, from `CLAUDE.md`.

## What the agent established

The README says tickets are summarized overnight. The helper has no lead for how, so the agent reads the job's
entry point instead of stopping at the leads. `jobs/summarize.py` calls `app/llm/client.py`, which posts ticket
text to a host read from a setting. The helper couldn't recognize that call: it has no SDK, and its URL path is
`/generate`. A migration, `db/migrations/0042_seed_prompts.sql`, holds the system prompt, and another setting
selects a model the tables don't know.

## The resulting assessment

```json
{
  "target": {"name": "orderly"},
  "summary": "Overnight jobs send customer ticket text through an internal gateway to a model chosen by a setting. The provider behind the gateway isn't visible from this repository.",
  "reviewed": [
    {"detection": "D002", "decision": "dismiss", "reason": "A placeholder in a unit test that mocks the client; no production path uses it."},
    {"detection": "D003", "decision": "keep", "status": "optional", "surface": "use", "reason": "Developers can use this server from their agents. The application never starts it."}
  ],
  "additions": [
    {
      "category": "hosted-service",
      "name": "llm-gateway.example.invalid",
      "status": "in-use",
      "provider": "unknown",
      "endpoint": "https://llm-gateway.example.invalid",
      "file": "app/llm/client.py",
      "line": 18,
      "evidence": "response = requests.post(f\"{settings.GATEWAY_URL}/generate\", json=body)",
      "confidence": "high",
      "why": "Every ticket summary goes through this call, so ticket text leaves this system here."
    },
    {
      "category": "model",
      "name": "support-summarizer-v3",
      "status": "in-use",
      "provider": "unknown",
      "file": "config/production.yaml",
      "line": 9,
      "evidence": "llm_profile: support-summarizer-v3",
      "confidence": "medium",
      "why": "The gateway client sends this as the model name. It could be overridden at deployment."
    },
    {
      "category": "prompt",
      "name": "prompts",
      "status": "in-use",
      "file": "db/migrations/0042_seed_prompts.sql",
      "line": 3,
      "evidence": "INSERT INTO prompts (name, body) VALUES ('ticket_summary',",
      "confidence": "high",
      "why": "The job loads its system prompt from this table, so the prompt lives in data and not in code."
    }
  ],
  "data_flows": [
    {
      "name": "Summaries reach support agents unreviewed",
      "file": "jobs/summarize.py",
      "line": 31,
      "evidence": "ticket.summary = response.json()[\"text\"]",
      "why": "Model output is saved straight onto the ticket, so support staff read it with nothing checking it first."
    }
  ],
  "steering": [],
  "examined": [
    "Followed jobs/summarize.py to the HTTP call in app/llm/client.py.",
    "Traced where the model name and system prompt come from, into config/ and db/migrations/."
  ],
  "not_checked": [
    "Which provider and model the gateway actually routes to. That configuration isn't in this repository, so ask the gateway's owner.",
    "Whether production overrides llm_profile. Deployment environment settings aren't in this repository."
  ]
}
```

The three additions are what this inventory is for: none of them is in a manifest, and no table would have named
them. The data flow stays out of the BOM because it isn't a thing anyone could list, though the signer needs to know it.
The first `not_checked` entry matters as much as any of them, because the honest answer to "where does the data go?"
stops at the gateway.
