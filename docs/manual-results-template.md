# Team Skills manual verification results

Every human result starts as **PENDING**. Do not change a row to pass without attaching sanitized
before/after evidence. Never include repository credentials or a managed clone's raw origin URL.

## Test identity

| Field | Value |
| --- | --- |
| Team Skills SHA | `<TEAM_SKILLS_SHA>` |
| Fixture root | `<DISPOSABLE_FIXTURE_ROOT>` |
| Tester | `<NAME>` |
| Date/time zone | `<DATE_AND_TIME_ZONE>` |
| OS/version | `<OS_VERSION>` |
| Shell/version | `<SHELL_VERSION>` |
| Git/version | `<GIT_VERSION>` |

## Results

| Target | Version | Result | Sanitized before/after evidence | Observations |
| --- | --- | --- | --- | --- |
| Claude Code startup + following-session visibility | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Claude Code `/clear`; no resume/compact update | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Claude Code fail-open, last-known-good, safe log, retry | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Codex hook review/trust + startup + following-session visibility | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Codex `/clear` capability; no resume/compact update | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | Record unsupported/version-gap separately from startup |
| Codex fail-open, last-known-good, safe log, retry | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Cursor new local conversation; following-conversation visibility | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Cursor workspace open/change does not update | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| Cursor fail-open and retry | `<VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |
| WSL validation + disposable merge/update smoke test | `<WSL_VERSION>` | PENDING | `<PATH_OR_NOTE>` | `<NOTES>` |

## Evidence notes

- Record the relevant hook JSON, `last-success`, `last-update.log`, active `SKILL.md`, and Git commit
  before and after each event. Redact usernames and local paths if the report will be shared.
- Record a timestamp before resume, compact, workspace open, or workspace change and show that the
  instance's `last-success` and log did not change.
- A product remaining usable after a failed update is human evidence. Automated tests separately
  prove that the hook returns success and keeps the last-known-good view.
- WSL evidence does not prove that Windows-hosted Cursor reads WSL configuration.
