# threat-model

Builds a threat model of a system by discovery instead of an interview, and ends in a report a person reviews and signs. It
starts from a repository or a design, branches out through whatever your agent can already reach, and stays read-only. The agent's
judgment decides what matters and what it concludes; the report's sections, fields, and rating scale stay the same on every run.

Use it to threat model a system or feature, at any stage. To trace specific flaws through a repository or review a release, use
`security-review`. To assess only the configuration that steers coding agents, use `agent-config-integrity`. It doesn't write fixes;
ask for those separately.

## Before you start

- Python 3.9 or newer. Git, if you are pointing it at a repository's commits.
- A session started **outside** any repository you name, such as in a sibling folder. A session started inside one may already have
  loaded its instructions and fired its hooks, so the skill stops and asks you to start again.
- Whatever access you want it to use, already set up in your agent. Connectors, plugins, and command-line tools with a configured
  identity all count. The more it can reach, the less it has to assume. A read-only identity is the safest way to run it.

## Run it

Start a session outside the repository and ask:

> Use threat-model on /path/to/repo. It's an existing system. Best effort if something's missing. Put the artifacts in
> /path/to/threat-models.

If you don't say, it asks these four things once, in one message, before it starts:

| It needs to know | Why |
| --- | --- |
| Where to start | Usually a repository, by path or URL, or else a design document or a description |
| What's being modeled | A system that exists, a planned system, or a planned change |
| What to do about gaps | Interview someone once discovery is done, or do best effort and record assumptions |
| Where artifacts go | Only you can choose this. The report maps how to attack the system, so it mentions that if the place is widely readable |

It doesn't ask how the system works. That's the point.

## What it does

1. Copies each repository into a snapshot in its working folder, and draws a first architecture diagram from what that shows.
2. Branches out through whatever it can reach that bears on this system, updating the diagram as it learns.
3. Reports any text, in any source, that tries to change a security outcome, then examines what that text pointed away from.
4. Works out the threats, answers the three LLM questions, and checks whether each mitigation really exists.
5. Uses STRIDE to check that no kind of threat was passed over, and accounts for every component and every flow across a trust
   boundary.
6. Interviews you once, or records its assumptions, as you chose.
7. Tests the model against past security fixes and incidents it can reach and, if your agent can hand work to a fresh agent, gets a
   second opinion on the architecture.
8. Checks the model and writes the report.

### What it will and won't touch

It changes nothing in any system it assesses, unless you explicitly say otherwise. The only writes are its own artifacts, to the
place you chose. Reading metadata and configuration needs no extra permission, including in production.

It stops and asks before anything that seems dangerous or risky, such as a read that would pull customer data or a secret's value, or a
call that might change state or cost money. The report records what it asked and what you decided. It never runs what it finds, and
never attempts to exploit anything.

A credential it finds in the material is a finding. It reports the location, never copies the value, and never uses it. It works only
with the access your session was given.

Your agent's model provider sees what the agent reads, as with any agent session.

## What you get

| File | What it is |
| --- | --- |
| `threat-model.md` | The report, with the same sections on every run |
| `diagram.mmd` | The architecture diagram, in Mermaid, also embedded in the report |
| `threat-model.json` | The same content as structured data |
| `threat-model.otm.json` | The same model in [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) format, for tools that read it |

The working folder also holds `snapshots/` and `files/`, which contain copies of the code. They're working material, and the skill
leaves them out of the deliverables if your destination is somewhere else.

| Section | What it holds |
| --- | --- |
| Summary | Open threats by rating, the top risks, and how much of the model was seen directly |
| Scope and access | Every source, used or not, and what it asked you before acting |
| Architecture | The diagram, then each component and flow and how it's known |
| Assets, actors, and trust boundaries | What's worth protecting, who could abuse it, and where trust changes |
| Threats | What each rating means here, a one-line-each register with a blank Decision column for you, then one short entry per threat |
| LLM questions | Where untrusted text enters a prompt, where model output goes, and what the tools can do, with locations |
| Conflicts between sources | Where code, running systems, and documents disagree, and which it believed |
| Assumptions and open questions | What it couldn't establish, ranked by what depends on it, and who could answer |
| Steering attempts | Text that tried to change the outcome, and what was done about it |
| Coverage | What STRIDE turned up, boundary crossings with no threat listed, and how the model held up against the past |
| Not checked | What wasn't examined. Nothing listed here is a clean result |
| Sign-off | Blank, for you |

The report is kept short on purpose: length limits apply to each field, and a report holds at most 30 threats. That's a ceiling and not a
target, so a small tool may have only two. Related threats are merged rather than dropped.

### How it lines up with common practice

No ratified standard exists for threat model reports, so this follows what the field has converged on. The sections answer the four questions
from the [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/):

| Question | Sections |
| --- | --- |
| What are we working on? | Scope and access, Architecture, Assets, actors, and trust boundaries |
| What can go wrong? | Threats, LLM questions, Conflicts between sources |
| What are we going to do about it? | The response on each threat, and the Decision column |
| Did we do a good enough job? | Assumptions and open questions, Coverage, Not checked, Sign-off |

Threats use the threat grammar from [AWS Threat Composer](https://github.com/awslabs/threat-composer). Responses use the mitigate, eliminate,
transfer, and accept options from the [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html),
and the skill leaves accept to you. The Open Threat Model file needs numeric scores, so it uses fixed bands rather than measurements.

### Reading the diagram

- **Fill** is the worst open threat on a component: red for critical, orange for high, yellow for medium, blue for low, green for
  assessed with nothing open, and grey for not assessed. People and outside actors are white.
- **A solid border or arrow** was observed directly in code or a running system. **A dashed one** is documented, inferred, or assumed.
- **Boxes** are trust zones.

The helper generates the diagram from the model, so the colors and legend are the same on every run.

### How far to trust it

Each claim says how it's known: observed, documented, inferred, or assumed. Each mitigation says whether it was seen running, seen in
code, only documented, looked for and not found, or couldn't be checked. A threat can't be marked mitigated on the strength of a
document alone.

Ratings come from a fixed table of likelihood and impact, and the agent has to say why it chose those two. A statement somewhere that
a risk was accepted is recorded but doesn't lower the rating, since accepting a risk is your decision.

Evidence from a repository is checked: a quote has to be at the cited line, or the report isn't written. **Evidence from anywhere else
can't be checked by the helper,** because it never sees those systems. The report labels which is which, with a locator and date so you
can look for yourself.

If the repository has PolicyRelay guidance, the report cites it and adds a section for it. That guidance can add requirements but can't
excuse anything. Without it, the report doesn't mention PolicyRelay.

## What it can't see

It knows only what your session can reach, and the report lists what it couldn't. Intent is the usual gap: what matters most, which
risks were accepted, and who is supposed to see what. Those show up as assumptions, ranked, ready to pass to whoever can answer.

It observes and doesn't attack, so a threat is something that could go wrong and hasn't been proven. For a planned system, nothing has
been checked against anything running, and the report says so.

Agent judgment varies between runs. The shape of the report doesn't, and serious threats should recur, but minor ones and wording can
differ. This is why a person signs it.

## What to do next

Read the steering attempts first, correct the architecture if it's wrong, then work through the open questions, since each one lists the
threats that hang on it. Then go through the threats and Not checked, and fill in the sign-off. To act on a threat, ask for the change
as a separate request. See [`SKILL.md`](../../skills/threat-model/SKILL.md) for the agent's instructions.
