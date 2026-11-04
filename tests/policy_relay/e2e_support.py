"""Shared steps for the offline and live PolicyRelay end-to-end proofs."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROUTE_LINK = re.compile(r"^- \[([a-z0-9-]+)]\((guidance/[a-z0-9-]+\.md)\) — (.+)$")
WORD = re.compile(r"[a-z][a-z0-9-]*")
STOP_WORDS = {
    "a", "an", "and", "at", "before", "for", "from", "in", "is", "it", "of", "or", "so", "that",
    "the", "this", "to", "when",
}
# Providers in fixtures/e2e/sufficiency/documents.json, which a sufficient route has to carry.
SCHEDULE_ENTRIES = (
    "Zephyrine", "Quillmark", "Brackenfield", "Corvane", "Halden", "Merrowgate", "Ostlund", "Perrin",
    "Sablewood", "Thornquist",
)
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "PolicyRelay Test",
    "GIT_AUTHOR_EMAIL": "policyrelay@example.invalid",
    "GIT_COMMITTER_NAME": "PolicyRelay Test",
    "GIT_COMMITTER_EMAIL": "policyrelay@example.invalid",
}


def run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    expected: int | None = 0,
    environment: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **GIT_IDENTITY, **(environment or {})}
    result = subprocess.run(
        list(arguments),
        cwd=cwd,
        env=merged,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if expected is not None and result.returncode != expected:
        raise AssertionError(
            f"{Path(arguments[0]).name} {' '.join(arguments[1:3])} returned "
            f"{result.returncode}, expected {expected}\n{result.stdout}\n{result.stderr}"
        )
    return result


def git(repository: Path, *arguments: str, expected: int | None = 0) -> str:
    return run(["git", "-C", str(repository), *arguments], expected=expected).stdout


def distill(
    distill_skill: Path, documents: Path, mapping: Path, repository: Path, plan: Path, date: str
) -> dict[str, Any]:
    """Follow the skill: plan, validate, apply, then return the apply report."""
    script = str(distill_skill / "scripts" / "distill_policy.py")
    run([sys.executable, script, "plan", "--documents", str(documents), "--mapping", str(mapping),
         "--distilled-at", date, "--destination", str(repository), "--output", str(plan)])
    validated = run([sys.executable, script, "validate", str(plan / "bundle")])
    if not validated.stdout.startswith("VALID"):
        raise AssertionError(validated.stdout)
    applied = run([sys.executable, script, "apply", "--plan", str(plan),
                   "--destination", str(repository), "--confirm-local-commit"])
    return json.loads(applied.stdout)


def install(init_skill: Path, consumer: Path, upstream: str, branch: str = "main") -> str:
    script = str(init_skill / "scripts" / "install_policy_relay.py")
    return run([sys.executable, script, "install", "--consumer-root", str(consumer),
                "--upstream", upstream, "--branch", branch]).stdout


def session_start(consumer: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    """Run the installed launcher with no help from the catalog or caller's Python path."""
    environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    result = subprocess.run(
        [str(consumer / ".policyrelay" / "session-start")],
        cwd=consumer,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(f"session-start returned {result.returncode}: {result.stderr}")
    return result


def tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _terms(text: str) -> set[str]:
    return {word for word in WORD.findall(text.lower()) if word not in STOP_WORDS}


def select_route(request: str, routes: Mapping[str, tuple[str, str]]) -> str | None:
    """Select only a unique, substantive match between a request and the router's summaries."""
    scores = {route: len(_terms(request) & _terms(summary)) for route, (_, summary) in routes.items()}
    best = max(scores.values(), default=0)
    winners = [route for route, score in scores.items() if score == best]
    return winners[0] if best >= 2 and len(winners) == 1 else None


def installed_routes(consumer: Path) -> dict[str, tuple[str, str]]:
    routes: dict[str, tuple[str, str]] = {}
    index = consumer / "security" / "PolicyRelay" / "index.md"
    for line in index.read_text(encoding="utf-8").splitlines():
        match = ROUTE_LINK.fullmatch(line)
        if match:
            routes[match.group(1)] = (match.group(2), match.group(3))
    return routes


def corrupt_manifest(repository: Path) -> None:
    """Commit a bundle a consumer must refuse."""
    path = repository / "bundle" / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["contractVersion"] = "9.9"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    git(repository, "add", "bundle/manifest.json")
    git(repository, "commit", "--quiet", "-m", "Introduce rejected bundle")
