#!/usr/bin/env python3
"""Prove the PolicyRelay skills against a real repository and, optionally, real agent CLIs.

This is a manual proof, not part of the automatic suite. It pushes to --upstream, so name a
disposable repository. All other work happens in --workdir; product skill locations are disposable
and agents see the skills only through project-level links, so user profiles are left alone.

    python3 tests/policy_relay/live_e2e.py --upstream URL [--also URL ...]
        [--agents claude,codex,cursor] [--workdir DIR] [--report FILE]

Each agent also runs the sufficiency stage, which checks that a route can be acted on with only the
bundle. To run that stage alone, with no upstream and nothing pushed:

    python3 tests/policy_relay/live_e2e.py --sufficiency-only --agents claude,codex [--workdir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy_relay import e2e_support as e2e  # noqa: E402
from policy_relay.support import CATALOG, FIXTURES  # noqa: E402

E2E = FIXTURES / "e2e"
DOCUMENTS = E2E / "authorized-documents.json"
MAPPING = E2E / "source-mapping.json"
DATE = "2026-08-27"
ADDED_REQUIREMENT = "record the reviewer of each redirect allowlist change."
AGENT_TIMEOUT_SECONDS = 900
SUFFICIENCY = E2E / "sufficiency"
READER_ANSWERS = {
    "zephyrine-internal": "allowed",
    "quillmark-internal": "denied",
    "tarnwell-public": "denied",
    "unpinned-logged-ticketed": "allowed",
    "unpinned-not-logged": "denied",
    # The sources never define high-impact, so a route that answers this added policy.
    "delete-record-high-impact": "unknown",
}


class Report:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def check(self, stage: str, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append({"stage": stage, "check": name, "passed": bool(passed), "detail": detail})
        suffix = f" ({detail})" if detail else ""
        print(f"{'PASS' if passed else 'FAIL'}  [{stage}] {name}{suffix}", flush=True)
        return bool(passed)

    def attempt(self, stage: str, name: str, action: Callable[[], Any]) -> Any:
        try:
            result = action()
        except Exception as error:  # A failed step is a result to report, not a crash.
            self.check(stage, name, False, f"{type(error).__name__}: {str(error)[:300]}")
            return None
        self.check(stage, name, True)
        return result


def install_catalog(base: Path) -> tuple[Path, Path]:
    """Deliver the skills with the catalog's real installer, into disposable locations."""
    work = base / "catalog"
    shutil.copytree(CATALOG, work, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
    e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(work)])
    e2e.git(work, "add", ".")
    e2e.git(work, "commit", "--quiet", "-m", "catalog")
    origin = base / "catalog-origin.git"
    e2e.run(["git", "clone", "--quiet", "--bare", str(work), str(origin)])
    home = base / "catalog-home"
    home.mkdir()
    claude_root = base / "installed-claude-skills"
    environment = {
        "HOME": str(home),
        "TEAM_SKILLS_STATE_ROOT": str(base / "catalog-state"),
        "TEAM_SKILLS_AGENTS_ROOT": str(base / "installed-agents-skills"),
        "TEAM_SKILLS_CLAUDE_ROOT": str(claude_root),
        "TEAM_SKILLS_CLAUDE_HOOKS_FILE": str(base / "claude-settings.json"),
        "TEAM_SKILLS_CODEX_HOOKS_FILE": str(base / "codex-hooks.json"),
        "TEAM_SKILLS_CURSOR_HOOKS_FILE": str(base / "cursor-hooks.json"),
    }
    e2e.run(["sh", str(work / "scripts" / "team-skills.sh"), "install", str(origin)],
            environment=environment)
    return claude_root / "init-policy-relay", claude_root / "policy-relay-distill"


def updated_mapping(base: Path) -> Path:
    mapping = json.loads(MAPPING.read_text(encoding="utf-8"))
    route = next(r for r in mapping["routes"] if r["task"] == "secure-coding")
    source = route["normativeRequirements"][0]["sourceIds"]
    route["normativeRequirements"].append(
        {"force": "MUST", "text": ADDED_REQUIREMENT, "sourceIds": source}
    )
    path = base / "mapping-v2.json"
    path.write_text(json.dumps(mapping), encoding="utf-8")
    return path


def new_consumer(path: Path) -> Path:
    shutil.copytree(E2E / "consumer", path)
    e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(path)])
    e2e.git(path, "add", ".")
    e2e.git(path, "commit", "--quiet", "-m", "consumer")
    return path


class Plans:
    def __init__(self, base: Path) -> None:
        self.base, self.count = base, 0

    def next(self) -> Path:
        self.count += 1
        return self.base / f"plan-{self.count}"


def live_stage(
    report: Report, base: Path, upstream: str, also: list[str], init_skill: Path, distill_skill: Path
) -> bool:
    stage = "live"
    policy = base / "policy"
    plans = Plans(base)
    empty = not e2e.git(base, "ls-remote", upstream, "refs/heads/main").strip()
    if not empty:
        e2e.run(["git", "clone", "--quiet", upstream, str(policy)])

    def publish() -> None:
        e2e.git(policy, "push", "--quiet", upstream, "main")

    e2e.distill(distill_skill, DOCUMENTS, MAPPING, policy, plans.next(), DATE)
    publish()
    payload_v1 = e2e.tree(policy / "bundle" / "payload")
    report.check(stage, "distilled bundle pushed to the real upstream", True)

    consumer = new_consumer(base / "live-consumer")
    e2e.install(init_skill, consumer, upstream)
    first = e2e.session_start(consumer)
    managed = consumer / "security" / "PolicyRelay"
    report.check(stage, "first sync from the private upstream", e2e.tree(managed) == payload_v1,
                 first.stdout.strip())

    for index, location in enumerate(also):
        other = new_consumer(base / f"live-consumer-form-{index}")
        e2e.install(init_skill, other, location)
        result = e2e.session_start(other, expected=0)
        report.check(stage, f"sync over {location.split('://')[0].split('@')[0]} location form",
                     e2e.tree(other / "security" / "PolicyRelay") == payload_v1, result.stdout.strip())

    report.check(stage, "repeat sync reports unchanged",
                 "status=unchanged" in e2e.session_start(consumer).stdout)

    e2e.distill(distill_skill, DOCUMENTS, updated_mapping(base), policy, plans.next(), DATE)
    publish()
    second = e2e.session_start(consumer)
    guidance = (managed / "guidance" / "secure-coding.md").read_text(encoding="utf-8")
    report.check(stage, "pushed policy update reaches the consumer", ADDED_REQUIREMENT in guidance,
                 second.stdout.strip())

    accepted = e2e.tree(managed)
    e2e.corrupt_manifest(policy)
    publish()
    rejected = e2e.session_start(consumer, expected=1)
    report.check(stage, "malformed bundle from upstream is rejected",
                 "phase=validation code=candidate-rejected" in rejected.stderr,
                 rejected.stderr.strip().splitlines()[0])
    report.check(stage, "last accepted guidance stayed byte-identical", e2e.tree(managed) == accepted)

    e2e.distill(distill_skill, DOCUMENTS, MAPPING, policy, plans.next(), DATE)
    publish()
    recovered = e2e.session_start(consumer)
    report.check(stage, "good bundle recovers the consumer", e2e.tree(managed) == payload_v1,
                 recovered.stdout.strip())

    (consumer / ".gitignore").write_text(
        "security/PolicyRelay/\nsecurity/.PolicyRelay.lock\n", encoding="utf-8"
    )
    e2e.git(consumer, "add", "-A")
    e2e.git(consumer, "commit", "--quiet", "-m", "install PolicyRelay")
    teammate = base / "live-teammate"
    e2e.run(["git", "clone", "--quiet", str(consumer), str(teammate)])
    e2e.session_start(teammate)
    report.check(stage, "teammate clone syncs from the private upstream without the catalog",
                 e2e.tree(teammate / "security" / "PolicyRelay") == payload_v1)
    return True


# Agent stage ---------------------------------------------------------------------------------


def expose_skills(workspace: Path, skills: list[Path]) -> None:
    excluded: list[str] = []
    for root in (".claude/skills", ".agents/skills"):
        directory = workspace / root
        directory.mkdir(parents=True)
        for skill in skills:
            (directory / skill.name).symlink_to(skill.resolve(), target_is_directory=True)
        excluded.append(root.split("/")[0] + "/")
    if (workspace / ".git").exists():
        with (workspace / ".git" / "info" / "exclude").open("a", encoding="utf-8") as handle:
            handle.write("\n".join(excluded) + "\n")


def agent_command(agent: str, prompt: str) -> list[str]:
    if agent == "claude":
        return ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
                "--setting-sources", "project", "--permission-mode", "acceptEdits",
                "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep,Skill", "--max-turns", "40"]
    if agent == "codex":
        return ["codex", "exec", "--json", "--skip-git-repo-check", "--sandbox", "workspace-write",
                "-c", "sandbox_workspace_write.network_access=true", prompt]
    if agent == "cursor":
        return ["cursor-agent", "-p", "--force", "--output-format", "stream-json", prompt]
    raise ValueError(agent)


def run_agent(agent: str, name: str, prompt: str, cwd: Path, logs: Path) -> list[str]:
    """Run one fresh headless session and return what it asked its tools to do."""
    environment = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE_CODE_")}
    for variable in ("CLAUDECODE", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE"):
        environment.pop(variable, None)
    log = logs / f"{agent}-{name}.jsonl"
    with log.open("w", encoding="utf-8") as handle:
        subprocess.run(agent_command(agent, prompt), cwd=cwd, env=environment,
                       stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                       timeout=AGENT_TIMEOUT_SECONDS, check=False)
    return tool_calls(log)


def tool_calls(log: Path) -> list[str]:
    """Extract tool inputs only. Tool output is excluded because the index names every route."""
    calls: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, dict):
            kind = value.get("type")
            if kind == "tool_use":
                calls.append(json.dumps(value.get("input", {})))
            elif kind == "command_execution":
                calls.append(str(value.get("command", "")))
            elif kind == "file_change":
                calls.append(json.dumps(value.get("changes", value.get("path", ""))))
            elif kind == "tool_call" and value.get("subtype") == "started":
                calls.append(json.dumps(value.get("tool_call", {})))
            else:
                for key, item in value.items():
                    if key not in {"tool_use_result", "aggregated_output", "result", "output"}:
                        walk(item)

    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            walk(json.loads(line))
        except json.JSONDecodeError:
            continue
    # Codex reports each item when it starts and when it completes.
    return list(dict.fromkeys(calls))


def first_index(calls: list[str], text: str) -> int | None:
    return next((index for index, call in enumerate(calls) if text in call), None)


def agent_stage(report: Report, base: Path, agent: str, upstream: str, skills: list[Path]) -> None:
    stage = agent
    logs = base / "agent-logs"
    logs.mkdir(exist_ok=True)
    home = base / f"agent-{agent}"
    home.mkdir()
    consumer = new_consumer(home / "consumer")
    expose_skills(consumer, skills)
    head = e2e.git(consumer, "rev-parse", "HEAD")

    calls = run_agent(agent, "init", (
        f"Use the init-policy-relay skill to connect this repository to the policy repository at "
        f"{upstream}, branch main. This repository is the consumer. Do not track synced guidance. "
        "These answers are final, so proceed without asking me anything. Do not commit anything; "
        "tell me the Git change you propose instead."
    ), consumer, logs)
    config = consumer / ".policyrelay" / "config.json"
    report.check(stage, "skill: used the bundled installer",
                 first_index(calls, "install_policy_relay.py") is not None)
    report.check(stage, "skill: configured the right upstream",
                 config.is_file() and json.loads(config.read_text(encoding="utf-8"))["upstream"] == upstream)
    report.check(stage, "skill: first sync produced the index",
                 (consumer / "security" / "PolicyRelay" / "index.md").is_file())
    report.check(stage, "skill: made no commit", e2e.git(consumer, "rev-parse", "HEAD") == head)
    if not config.is_file():
        report.check(stage, "task: skipped because install failed", False)
    else:
        probe = json.loads((E2E / "task-probe.json").read_text(encoding="utf-8"))
        before = e2e.git(consumer, "status", "--porcelain", "--", "src")
        calls = run_agent(agent, "task", probe["request"], consumer, logs)
        synced = first_index(calls, "session-start")
        loaded = first_index(calls, "secure-coding")
        report.check(stage, "task: ran session-start unprompted", synced is not None)
        report.check(stage, "task: loaded the secure-coding guidance", loaded is not None)
        report.check(stage, "task: synced before loading guidance",
                     synced is not None and loaded is not None and synced <= loaded)
        report.check(stage, "task: did not load the unrelated route",
                     first_index(calls, "vulnerability-triage") is None)
        report.check(stage, "task: changed src/redirects.py",
                     "redirects.py" in e2e.git(consumer, "status", "--porcelain", "--", "src")
                     and before != e2e.git(consumer, "status", "--porcelain", "--", "src"))

    workspace = home / "distill"
    workspace.mkdir()
    e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(workspace)])
    expose_skills(workspace, skills)
    shutil.copy(DOCUMENTS, workspace / "documents.json")
    shutil.copy(MAPPING, workspace / "mapping.json")
    destination = workspace / "policy-repository"
    calls = run_agent(agent, "distill", (
        "Use the policy-relay-distill skill. The authorized source is the local file documents.json "
        "in this directory, every source in it is in scope, and I may read them. The confirmed "
        f"mapping is mapping.json in this directory. The date is {DATE}. The destination is "
        f"{destination}, which should be created. I resolve all policy questions, and there are "
        "none. Put the plan in a new directory named plan here. I have reviewed the preview in "
        "advance and I confirm the initialize operation and one local commit on main. Do not push "
        "or add a remote."
    ), workspace, logs)
    report.check(stage, "distill: used the bundled script",
                 first_index(calls, "distill_policy.py") is not None)
    committed = (destination / "bundle" / "manifest.json").is_file()
    report.check(stage, "distill: committed a bundle", committed)
    if committed:
        report.check(stage, "distill: bundle matches the deterministic expectation",
                     e2e.tree(destination / "bundle") == e2e.tree(base / "offline-bundle"))
        report.check(stage, "distill: added no remote", e2e.git(destination, "remote") == "")


# Sufficiency stage ---------------------------------------------------------------------------


def committed_route(destination: Path) -> str | None:
    """Return the committed route text, or None if no bundle was committed."""
    if not (destination / "bundle" / "manifest.json").is_file():
        return None
    if not e2e.git(destination, "log", "--oneline", expected=None).strip():
        return None
    guidance = destination / "bundle" / "payload" / "guidance"
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(guidance.glob("*.md")))


def distill_workspace(home: Path, name: str, skills: list[Path], files: dict[str, Path]) -> Path:
    workspace = home / name
    workspace.mkdir()
    e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(workspace)])
    expose_skills(workspace, skills)
    for target, source in files.items():
        shutil.copy(source, workspace / target)
    return workspace


def draft_prompt(destination: Path) -> str:
    return (
        "Use the policy-relay-distill skill. The authorized sources are the local file documents.json "
        "in this directory, every source in it is in scope, and I may read them. Draft the mapping "
        "yourself, with routes named ai-provider-use, ai-feature-launch, and model-output-handling. "
        "Keep each route concise, because agents load one at the start of a task. "
        f"The date is {DATE}. The destination is "
        f"{destination}, which should be created. I resolve all policy questions. Put the plan in a "
        "new directory named plan here. I am not available during this run. If you have no open "
        "questions, I confirm your draft mapping, the initialize operation, and one local commit on "
        "main. If you have an open question, stop and report it instead of committing. Do not push or "
        "add a remote."
    )


def read_answers(agent: str, name: str, bundle: Path, home: Path, logs: Path) -> tuple[dict[str, Any], bool]:
    """Ask a fresh session with only the bundle, and report whether it stayed within it."""
    reader = home / name
    shutil.copytree(bundle / "payload", reader / "security" / "PolicyRelay")
    calls = run_agent(agent, name, (
        "Answer from the policy guidance in security/PolicyRelay in this directory: read index.md, then "
        "the routes that apply. Do not look outside this directory or use the network. Write "
        "answers.json here with exactly these keys, for these questions. May we send this data to this "
        "AI provider? zephyrine-internal (Zephyrine Models, Internal data), quillmark-internal "
        "(Quillmark AI, Internal data), tarnwell-public (Tarnwell Cloud, Public data). May production "
        "use an unpinned model tag? unpinned-logged-ticketed (the gateway logs the resolved version and "
        "the change has an approved ticket), unpinned-not-logged (the gateway does not log it). "
        "delete-record-high-impact: does the guidance say that an agent tool deleting one record is a "
        "high-impact action that needs approval? Each value is allowed, denied, or unknown, and for the "
        "last one, allowed means no approval is needed and denied means it is. Use unknown when the "
        "guidance does not let you tell. Do not guess. Do not change any other file."
    ), reader, logs)
    answers_file = reader / "answers.json"
    answers = json.loads(answers_file.read_text(encoding="utf-8")) if answers_file.is_file() else {}
    return answers, first_index(calls, "documents") is None


def sufficiency_stage(report: Report, base: Path, agent: str, distill_skill: Path, skills: list[Path]) -> None:
    """Prove a route can be acted on with only the bundle, using a real session for each role."""
    stage = f"{agent}-sufficiency"
    logs = base / "agent-logs"
    logs.mkdir(exist_ok=True)
    home = base / f"sufficiency-{agent}"
    home.mkdir()

    # The list lives in a second source, so a route that only cites it is the easy mistake. The
    # standard leaves terms like high-impact undefined, which must neither stop this nor get defined.
    workspace = distill_workspace(home, "draft", skills, {"documents.json": SUFFICIENCY / "documents.json"})
    destination = workspace / "policy-repository"
    run_agent(agent, "sufficiency-draft", draft_prompt(destination), workspace, logs)
    route = committed_route(destination)
    if report.check(stage, "draft: committed a bundle", route is not None):
        report.check(stage, "draft: the route carries the approved list",
                     all(entry in route for entry in e2e.SCHEDULE_ENTRIES))
        report.check(stage, "draft: kept the conditional rule with its exception",
                     any(all(word in line.lower() for word in ("unpinned", "log", "ticket"))
                         for line in route.splitlines()))
        answers, contained = read_answers(agent, "sufficiency-reader", destination / "bundle", home, logs)
        report.check(stage, "reader: decided correctly from the bundle alone", answers == READER_ANSWERS,
                     json.dumps(answers))
        report.check(stage, "reader: stayed within the bundle", contained)

    # Control: the same question against a route that cites the list without carrying it. Without
    # this, the reader's correct answers wouldn't show that the list was what made them possible.
    control = home / "control-policy"
    e2e.distill(distill_skill, SUFFICIENCY / "documents.json", SUFFICIENCY / "mapping-omits-schedule.json",
                control, home / "control-plan", DATE)
    answers, _ = read_answers(agent, "sufficiency-control", control / "bundle", home, logs)
    report.check(stage, "control: a route without the list can't answer",
                 answers == dict.fromkeys(READER_ANSWERS, "unknown"), json.dumps(answers))

    # The sources name the list but don't contain it, so nothing truthful can fill the gap.
    workspace = distill_workspace(home, "missing", skills,
                                  {"documents.json": SUFFICIENCY / "documents-missing-schedule.json"})
    destination = workspace / "policy-repository"
    run_agent(agent, "sufficiency-missing", draft_prompt(destination), workspace, logs)
    report.check(stage, "missing: stopped instead of committing a gap", committed_route(destination) is None)

    # The user confirmed a mapping with a gap in advance, without seeing the gap.
    workspace = distill_workspace(home, "confirmed-gap", skills, {
        "documents.json": SUFFICIENCY / "documents.json",
        "mapping.json": SUFFICIENCY / "mapping-omits-schedule.json",
    })
    destination = workspace / "policy-repository"
    run_agent(agent, "sufficiency-confirmed-gap", (
        "Use the policy-relay-distill skill. The authorized source is the local file documents.json "
        "in this directory, every source in it is in scope, and I may read them. The confirmed "
        f"mapping is mapping.json in this directory. The date is {DATE}. The destination is "
        f"{destination}, which should be created. I resolve all policy questions. Put the plan in a "
        "new directory named plan here. I confirm the initialize operation and one local commit on "
        "main in advance. Do not push or add a remote."
    ), workspace, logs)
    route = committed_route(destination)
    report.check(stage, "confirmed gap: didn't commit a route missing the list",
                 route is None or all(entry in route for entry in e2e.SCHEDULE_ENTRIES))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", help="disposable repository this will push to")
    parser.add_argument("--sufficiency-only", action="store_true",
                        help="run only the sufficiency stage, which needs no upstream")
    parser.add_argument("--also", action="append", default=[], help="another URL form to sync from")
    parser.add_argument("--agents", default="", help="comma-separated: claude,codex,cursor")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.upstream and not args.sufficiency_only:
        parser.error("--upstream is required unless --sufficiency-only is set")
    agents = list(filter(None, args.agents.split(",")))

    base = (args.workdir or Path(tempfile.mkdtemp(prefix="policy-relay-live-"))).resolve()
    base.mkdir(parents=True, exist_ok=True)
    if any(base.iterdir()):
        parser.error(f"--workdir must be empty: {base}")
    print(f"Workspace: {base}", flush=True)
    report = Report()

    views = report.attempt("catalog", "skills delivered by the real catalog installer",
                           lambda: install_catalog(base))
    if views:
        init_skill, distill_skill = views
        for view in views:
            report.check("catalog", f"{view.name} is present", (view / "SKILL.md").is_file())
        skills = [init_skill, distill_skill]
        if not args.sufficiency_only:
            report.attempt("live", "private upstream end-to-end sequence ran to completion",
                           lambda: live_stage(report, base, args.upstream, args.also, init_skill, distill_skill))
            e2e.distill(distill_skill, DOCUMENTS, MAPPING, base / "offline", base / "offline-plan", DATE)
            shutil.copytree(base / "offline" / "bundle", base / "offline-bundle")
            for agent in agents:
                report.attempt(agent, "agent stage ran to completion",
                               lambda agent=agent: agent_stage(report, base, agent, args.upstream, skills))
        for agent in agents:
            report.attempt(agent, "sufficiency stage ran to completion",
                           lambda agent=agent: sufficiency_stage(report, base, agent, distill_skill, skills))

    failed = [check for check in report.checks if not check["passed"]]
    print(f"\n{len(report.checks) - len(failed)} of {len(report.checks)} checks passed.", flush=True)
    if args.report:
        args.report.write_text(json.dumps(report.checks, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
