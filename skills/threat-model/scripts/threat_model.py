#!/usr/bin/env python3
"""Read-only helper for the threat-model skill. Standard library only.

    threat_model.py prepare --out DIR [--repo PATH [--name NAME] [--head REF] [--working-tree] [--allow-inside-target]]
    threat_model.py diagram --out DIR
    threat_model.py render --out DIR

`prepare` copies each repository into a snapshot outside it and lists steering leads. Run it again for each
repository discovery turns up, or once with no repository when there is none. `diagram` draws the architecture from
threat-model.json, and runs as often as the model changes. `render` checks the whole model and writes the report,
plus the same model as Open Threat Model JSON for tools that read that format.

Sources the agent reads through its own access, such as a live environment or a document store, never pass through
here. This helper can check a quote against a snapshot, but it can only record what the agent says about anything else,
and the report says which is which.

Nothing here executes anything found in a repository, and nothing writes to one. A repository's own Git
configuration can run commands and its attributes can hide content, so Git only ever runs against a
temporary repository that has clean configuration and borrows the target's objects. Git doesn't check an
object against its name when reading it, so this helper does, for everything the report relies on.

Exit codes: 0 success, 1 problems to correct, 2 refused or bad usage.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

SCHEMA = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
MAX_LEADS = 300
MAX_SUPPRESSIONS_LISTED = 2000
MAX_EVIDENCE_CHARS = 4000
MIN_EVIDENCE_CHARS = 6
MAX_TREE_ENTRIES = 300000
MAX_TREE_DEPTH = 256
MAX_DISK_COMPARE = 50000
OBJECT_BATCH = 100
GIT_TIMEOUT_SECONDS = 300
EVIDENCE_EXTRA_LINES = 2
SKIPPED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", ".tox", "__pycache__"}
SECRET_FILES = re.compile(r"^(\.env(\..*)?|.*\.(pem|key|p12|pfx|keystore))$", re.I)
AS_DATA = ".as-data"
# Agents discover these by name, so a snapshot must not offer them under a name they would load.
AGENT_PATH_NAMES = {
    ".agents", ".aider.conf.yml", ".claude", ".claude.json", ".clinerules", ".cline", ".codex", ".continue",
    ".cursor", ".cursorrules", ".devin", ".gemini", ".kiro", ".mcp.json", ".opencode", ".qwen", ".roo",
    ".vscode", ".windsurf", ".windsurfrules", ".zed", ".amazonq", ".augment", ".junie", ".trae", "agent.md",
    "agents.md", "agents.override.md", "claude.local.md", "claude.md", "conventions.md", "copilot-instructions.md",
    "gemini.md", "mcp.json", "qwen.md", "skill.md",
    # Search tools and agents honor these, so a committed one could hide code from the reviewer.
    ".aiderignore", ".clineignore", ".codeiumignore", ".cursorignore", ".geminiignore", ".gitignore", ".ignore",
    ".rgignore",
}
SUPPRESSION_FILES = {
    ".bandit", ".checkov.yaml", ".checkov.yml", ".gitleaksignore", ".grype.yaml", ".opengrepignore",
    ".semgrepignore", ".snyk", ".trivyignore", ".trivyignore.yaml",
}
POLICY_ROOT = "security/PolicyRelay"
# Leads only. They start the search for steering text; the skill's reader decides what each one means
# and looks past them, because a phrase list can never be the whole answer.
STEERING_TEXT = re.compile(
    r"\b(ignore|skip|suppress|downgrade|omit|exclude|hide|(do not|don'?t|never|no need to) (report|flag|mention|raise|review))\b"
    r"[^\n]{0,80}\b(finding|vulnerabilit|security|cve|scan|audit|alert)"
    r"|\b(finding|vulnerabilit|security issue|cve)\w*[^\n]{0,60}\b(known|accepted|false positive|wont.?fix|won'?t fix|not applicable|out of scope)\b"
    r"|\b(security|ai|llm|agent|automated)[ -]?(review|reviewer|scanner|assistant|auditor|tool|agent)s?\b[^\n]{0,60}\b(should not|must not|need not|do not|don'?t|ignore|skip|treat)\b",
    re.I,
)
INLINE_SUPPRESSION = re.compile(
    r"\b(nosec|nosemgrep|nosonar|gitleaks:allow|trivy:ignore|checkov:skip|tfsec:ignore|kics scan ignore)\b"
    r"|\bnolint\b(?!:)|\bnolint:[^\n]*\bgosec\b", re.I
)
# Controls, format characters, invisible fillers, and variation selectors. Tab and newlines stay.
INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    "\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb\U000e0000-\U000e0fff]"
)
# Everywhere else, only what has no innocent use in source text, so emoji and soft hyphens stay quiet.
HIDDEN_ANYWHERE = re.compile("[\u061c\u115f\u1160\u202a-\u202e\u2066-\u2069\u3164\uffa0\U000e0000-\U000e0fff]")
CREDENTIAL_SHAPES = re.compile(
    r"(?<![A-Za-z0-9_-])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"
    r"|(?s:-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z))"
)

TYPES = ("actor", "process", "data", "model", "external")
BASES = ("observed", "documented", "inferred", "assumed")
SOURCE_KINDS = ("repo", "live", "document", "person", "other")
SOURCE_STATUS = ("used", "not-reachable", "declined", "not-needed")
SOURCE_STATUS_LABEL = {"used": "Used", "not-reachable": "Not reachable", "declined": "Declined", "not-needed": "Not needed"}
STAGES = ("existing", "planned", "change")
STAGE_LABEL = {"existing": "An existing system", "planned": "A planned system", "change": "A planned change to an existing system"}
GAPS = ("interview", "best-effort")
GAPS_LABEL = {"interview": "Interview allowed, once, after discovery", "best-effort": "Best effort: gaps are recorded as assumptions"}
STRIDE = ("spoofing", "tampering", "repudiation", "information-disclosure", "denial-of-service", "elevation-of-privilege")
STRIDE_RESULTS = ("threats-listed", "none-found", "not-assessed")
STRIDE_RESULT_LABEL = {"threats-listed": "Threats listed", "none-found": "None found", "not-assessed": "Not assessed"}
SEVERITIES = ("critical", "high", "medium", "low")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
LIKELIHOODS = ("high", "medium", "low")
# Agents judge likelihood and impact. The rating follows from those, so it can't drift between runs for the same judgment.
SEVERITY_MATRIX = {
    ("critical", "high"): "critical", ("critical", "medium"): "critical", ("critical", "low"): "high",
    ("high", "high"): "high", ("high", "medium"): "high", ("high", "low"): "medium",
    ("medium", "high"): "medium", ("medium", "medium"): "medium", ("medium", "low"): "low",
    ("low", "high"): "low", ("low", "medium"): "low", ("low", "low"): "low",
}
THREAT_STATUS = ("open", "partly-mitigated", "mitigated")
THREAT_STATUS_LABEL = {"open": "Open", "partly-mitigated": "Partly mitigated", "mitigated": "Mitigated"}
MITIGATION_STATUS = ("running", "in-code", "documented", "not-found", "could-not-check")
MITIGATION_LABEL = {
    "running": "Seen running", "in-code": "Seen in code, not seen running", "documented": "Only documented",
    "not-found": "Looked for, not found", "could-not-check": "Could not check",
}
# Accepting a risk is a person's decision, so it isn't offered here. The signer records it in the register.
RESPONSES = ("mitigate", "eliminate", "transfer")
OBJECTIVES = ("confidentiality", "integrity", "availability")
TRUST_LEVELS = ("low", "medium", "high")
UNKNOWN_STATUS = ("open", "answered")
DECISIONS = ("approved", "declined")
LLM_KEYS = ("untrusted_text_into_prompts", "where_model_output_goes", "what_tools_can_do")
LLM_LABEL = {
    "untrusted_text_into_prompts": "Where does untrusted text enter a prompt?",
    "where_model_output_goes": "Where does model output go?",
    "what_tools_can_do": "What can the tools do?",
}
LLM_REFERENCE = {
    "untrusted_text_into_prompts": "OWASP LLM01, prompt injection",
    "where_model_output_goes": "OWASP LLM05, improper output handling",
    "what_tools_can_do": "OWASP LLM06, excessive agency",
}

IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
REPO_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_DIAGRAM_COMPONENTS = 80
MAX_DIAGRAM_CHARS = 45000
MAX_LABEL_CHARS = 80
MAX_METADATA_CHARS = 60
MAX_METADATA_SHOWN = 4
MAX_TOP_RISKS = 5
# Reports get read when they say things once. These limits make the agent choose, and they cap words, not facts.
MAX_THREATS = 30
MAX_TITLE_CHARS = 120
MAX_TEXT_CHARS = 300
MAX_PART_CHARS = {"source": 100, "prerequisites": 120, "action": 200, "consequence": 200}
MAX_SUMMARY_CHARS = 800
MAX_EVIDENCE_PER_ITEM = 3
MAX_HISTORY_COMMITS = 5000
MAX_INLINE_QUOTE_CHARS = 160
# Open Threat Model requires numbers. These are fixed bands, not measurements.
ID_IN_PROSE = re.compile(r"[A-Z]{1,3}-?\d+")
OTM_VERSION = "0.2.0"
OTM_SCORE = {"critical": 100, "high": 75, "medium": 50, "low": 25}
OTM_TRUST = {"low": 10, "medium": 50, "high": 90}
OTM_REDUCTION = {"running": 50, "in-code": 25, "documented": 0, "not-found": 0, "could-not-check": 0}

OUTPUT_NAMES = {"manifest.json", "snapshots", "files", "threat-model.json", "diagram.mmd", "threat-model.md", "threat-model.otm.json"}
TOP_KEYS = {"target", "intake", "system", "summary", "sources", "confirmations", "zones", "components", "flows", "assets",
            "actors", "calibration", "threats", "boundary_reviews", "llm_questions", "conflicts", "unknowns", "steering",
            "dismissed_leads", "stride_coverage", "backtest", "architecture_check", "not_checked"}
INTAKE_KEYS = {"started_from", "stage", "gaps"}
SYSTEM_KEYS = {"what_it_does", "worth_protecting"}
SOURCE_KEYS = {"id", "name", "kind", "status", "read", "repo", "observed", "note"}
CONFIRMATION_KEYS = {"action", "why_risky", "decision"}
ZONE_KEYS = {"id", "name", "trust", "trust_level"}
COMPONENT_KEYS = {"id", "name", "type", "zone", "basis", "sources", "reasoning", "unknown", "metadata", "no_open_threats", "not_assessed"}
FLOW_KEYS = {"id", "from", "to", "label", "channel", "guarantees", "basis", "sources", "reasoning", "unknown"}
ASSET_KEYS = {"id", "name", "why", "objectives", "where", "basis", "sources", "reasoning", "unknown"}
ACTOR_KEYS = {"name", "can", "cannot"}
THREAT_KEYS = {"id", "title", "stride", "components", "flows", "assets", "source", "prerequisites", "action", "consequence",
               "likelihood", "impact", "rating_reason", "status", "evidence", "mitigations", "response", "recommendation",
               "detection", "references", "depends_on", "policy_route", "claimed_acceptance"}
MITIGATION_KEYS = {"control", "status", "evidence", "looked_in", "note"}
EVIDENCE_KEYS = {"source", "file", "line", "quote", "credential", "locator", "observed"}
UNKNOWN_KEYS = {"id", "question", "assumed", "who_can_answer", "status", "answer", "affects"}
CONFLICT_KEYS = {"about", "sides", "believed", "why_it_matters", "threats"}
SIDE_KEYS = {"source", "says", "evidence"}
STEERING_KEYS = {"evidence", "effect", "handled", "leads"}


class Refused(Exception):
    """The helper will not proceed, and the reason is for the operator."""


# ------------------------------------------------- snapshot code, as in security-review


def is_within(path: Path, root: Path) -> bool:
    """Compare by file identity, because paths that differ in case can name one directory."""
    for candidate in (path, *path.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def make_writable(root: Path) -> None:
    for directory, _subdirectories, files in os.walk(root):
        for name in files:
            with contextlib.suppress(OSError):
                os.chmod(Path(directory) / name, stat.S_IREAD | stat.S_IWRITE)


def make_read_only(root: Path) -> None:
    for directory, _subdirectories, files in os.walk(root):
        for name in files:
            os.chmod(Path(directory) / name, stat.S_IREAD)


def digest_snapshot(root: Path) -> str:
    hasher = hashlib.sha256()
    for directory, subdirectories, files in os.walk(root):
        subdirectories.sort()
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            hasher.update(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n".encode("utf-8", "surrogateescape"))
    return hasher.hexdigest()


def data_path(relative: str) -> str:
    """Name a repository path so no agent discovers it as its own instructions or configuration."""
    parts = [part + AS_DATA if part.lower() in AGENT_PATH_NAMES else part for part in relative.split("/")]
    return "/".join(parts)


def original_path(relative: str) -> str:
    """Undo data_path, so people always read the path as it is in the repository."""
    parts = relative.replace("\\", "/").split("/")
    return "/".join(
        part[: -len(AS_DATA)] if part.endswith(AS_DATA) and part[: -len(AS_DATA)].lower() in AGENT_PATH_NAMES else part
        for part in parts
    )


class SnapshotWriter:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.total_bytes = 0
        self.file_count = 0
        self.skipped: dict[str, list[str]] = {}
        self.written: dict[str, str] = {}

    def skip(self, reason: str, path: str) -> None:
        self.skipped.setdefault(reason, []).append(path)

    def add(self, relative: str, content: bytes) -> None:
        """Write one file as plain data: never a link, and never executable."""
        if not safe_relative(relative):
            self.skip("an unsafe path", relative)
            return
        if b"\0" in content[:8192]:
            self.skip("binary", relative)
            return
        if self.total_bytes + len(content) > MAX_SNAPSHOT_BYTES:
            raise Refused(f"the target is larger than {MAX_SNAPSHOT_BYTES} bytes of text. Review it in smaller parts.")
        destination = self.root / data_path(relative)
        try:
            if destination.exists():
                self.skip("a name that collides on this file system", relative)
                return
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        except (OSError, ValueError):
            self.skip("a name this file system can't hold", relative)
            return
        self.total_bytes += len(content)
        self.file_count += 1
        self.written[relative] = hashlib.sha256(content).hexdigest()

    def agent_files(self) -> list[str]:
        found = []
        for path in sorted(self.written):
            if any(part.lower() in AGENT_PATH_NAMES for part in path.split("/")) or is_suppression_file(path) \
                    or path.lower().endswith(".instructions.md"):
                found.append(path)
        return found

    def limits(self) -> list[str]:
        return [
            f"Not read, {reason}: {preview(sorted(paths))}"
            for reason, paths in sorted(self.skipped.items())
        ]


def preview(paths: list[str], limit: int = 12) -> str:
    shown = ", ".join(paths[:limit])
    return f"{shown}, and {len(paths) - limit} more, all named in manifest.json" if len(paths) > limit else shown


def is_suppression_file(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower() in SUPPRESSION_FILES


def safe_relative(relative: str) -> bool:
    parts = relative.split("/")
    return bool(relative) and not relative.startswith("/") and all(
        part and part != ".." and part != "." and part.lower() != ".git" and ":" not in part and "\\" not in part
        for part in parts
    )


def copy_working_tree(target: Path, writer: SnapshotWriter) -> None:
    def unreadable(error: OSError) -> None:
        name = Path(error.filename or "").resolve()
        writer.skip("a directory that couldn't be read", name.relative_to(target).as_posix() if target in name.parents else str(name))

    for directory, subdirectories, files in os.walk(target, followlinks=False, onerror=unreadable):
        current = Path(directory)
        kept = []
        for name in sorted(subdirectories):
            child = current / name
            if child.is_symlink():
                writer.skip("a symbolic link that was not followed", child.relative_to(target).as_posix())
            elif name in SKIPPED_DIRECTORIES:
                if child != target / ".git":
                    writer.skip("a directory of tools or installed packages, left out", child.relative_to(target).as_posix())
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted(files):
            child = current / name
            relative = child.relative_to(target).as_posix()
            mode = child.lstat().st_mode
            if stat.S_ISLNK(mode):
                writer.skip("a symbolic link that was not followed", relative)
            elif not stat.S_ISREG(mode):
                writer.skip("not a regular file", relative)
            elif SECRET_FILES.match(name):
                writer.skip("a likely credential file, left out of the snapshot", relative)
            elif child.stat().st_size > MAX_FILE_BYTES:
                writer.skip("larger than the file limit", relative)
            else:
                try:
                    writer.add(relative, child.read_bytes())
                except OSError:
                    writer.skip("unreadable", relative)


def find_repository(target: Path, head_given: bool) -> tuple[Path | None, str | None]:
    """Locate the target's own Git directory, and refuse to be pointed at someone else's."""
    dot_git = target / ".git"
    if dot_git.is_symlink():
        return None, "The target's .git is a link, so what it holds can't be tied to this target."
    if dot_git.is_dir():
        if (dot_git / "commondir").exists():
            return None, "The target's .git borrows another repository's history through a commondir file."
        return dot_git, None
    if dot_git.is_file():
        match = re.match(r"gitdir:\s*(.+)", read_small(dot_git))
        pointed = None
        if match:
            pointed = Path(match.group(1).strip())
            pointed = (pointed if pointed.is_absolute() else target / pointed).resolve()
        if pointed and pointed.is_dir() and points_back(pointed, target):
            return pointed, None
        return None, "The target's .git file points at a repository that doesn't point back at this target."
    # A directory that merely looks bare could be a decoy beside the real code, so it takes an explicit commit.
    if head_given and (target / "HEAD").is_file() and (target / "objects").is_dir() and (target / "refs").is_dir():
        return target, None
    return None, None


def points_back(gitdir: Path, target: Path) -> bool:
    """A linked worktree or submodule records where its working directory is. Other repositories don't."""
    if gitdir.parent.name == "worktrees":
        recorded = read_small(gitdir / "gitdir").strip()
        commondir = read_small(gitdir / "commondir").strip()
        if not recorded or not commondir:
            return False
        recorded_path = Path(recorded) if Path(recorded).is_absolute() else gitdir / recorded
        return recorded_path.resolve() == (target / ".git").resolve() and (gitdir / commondir).resolve() == gitdir.parent.parent.resolve()
    match = re.search(r"^\s*worktree\s*=\s*(.+?)\s*$", read_small(gitdir / "config"), re.I | re.M)
    if not match:
        return False
    worktree = Path(match.group(1))
    return (worktree if worktree.is_absolute() else gitdir / worktree).resolve() == target


def read_small(path: Path, limit: int = MAX_FILE_BYTES) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def build_clean_view(gitdir: Path, view: Path) -> Path:
    """A temporary repository with clean configuration that borrows the target's objects and refs."""
    common = gitdir
    commondir = read_small(gitdir / "commondir").strip()
    if commondir:
        common = (gitdir / commondir).resolve()
    target_config = read_small(common / "config")
    if re.search(r"^\s*refstorage\s*=\s*reftable", target_config, re.I | re.M):
        raise Refused("this repository stores refs in reftable format, which this helper can't read. Use --working-tree.")
    sha256 = re.search(r"^\s*objectformat\s*=\s*sha256", target_config, re.I | re.M)
    objects = check_object_store(common)
    (view / "objects" / "info").mkdir(parents=True)
    (view / "refs").mkdir()
    (view / "objects" / "info" / "alternates").write_text(f"{objects}\n", encoding="utf-8")
    config = "[core]\n\trepositoryformatversion = 1\n\tbare = true\n" if sha256 else "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
    if sha256:
        config += "[extensions]\n\tobjectformat = sha256\n"
    (view / "config").write_text(config, encoding="utf-8")
    head = read_small(gitdir / "HEAD").strip()
    if not re.fullmatch(r"ref: refs/[^\s]+|[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise Refused("the target's Git HEAD isn't readable.")
    (view / "HEAD").write_text(head + "\n", encoding="utf-8")
    packed = read_small(common / "packed-refs", 256 * 1024 * 1024)
    if packed:
        kept, skipping = [], False
        for line in packed.splitlines():
            if line.startswith("^"):
                if not skipping:
                    kept.append(line)
                continue
            name = line.split(" ", 1)[1] if " " in line else ""
            skipping = not line.startswith("#") and (name.startswith("refs/replace/") or name.count("/") < 2)
            if not skipping:
                kept.append(line)
        (view / "packed-refs").write_text("\n".join(kept) + "\n", encoding="utf-8")
    shallow = read_small(common / "shallow")
    if shallow:
        (view / "shallow").write_text(shallow, encoding="utf-8")
    copy_loose_refs(common / "refs", view / "refs", "refs")
    if gitdir != common:
        copy_loose_refs(gitdir / "refs", view / "refs", "refs")
    return view


def check_object_store(common: Path) -> Path:
    """Only this repository's own objects may enter a review, so nothing may lead outside it."""
    objects = common / "objects"
    if objects.is_symlink() or not objects.is_dir():
        raise Refused("the target's Git object directory is missing or is a link.")
    for child in sorted(objects.iterdir()):
        if child.is_symlink():
            raise Refused("the target's Git objects contain a link. Get a fresh clone, or use --working-tree.")
        if child.is_dir():
            for grandchild in child.iterdir():
                mode = grandchild.lstat().st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise Refused("the target's Git objects contain a link or special file. Get a fresh clone, or use --working-tree.")
    alternates = objects / "info" / "alternates"
    if alternates.exists() or alternates.is_symlink():
        if alternates.is_symlink() or not alternates.is_file():
            raise Refused("the target's Git alternates entry isn't a regular file.")
        if alternates.read_text(encoding="utf-8", errors="replace").strip():
            raise Refused(
                "this repository borrows Git objects from elsewhere on disk, which could bring another repository's "
                "content into the review. Make an unshared clone, or use --working-tree."
            )
    return objects.resolve()


def copy_loose_refs(source: Path, destination: Path, prefix: str) -> None:
    if source.is_symlink() or not source.is_dir():
        return
    for child in sorted(source.iterdir()):
        name = f"{prefix}/{child.name}"
        if name == "refs/replace" or child.is_symlink():
            continue
        if child.is_dir():
            (destination / child.name).mkdir(exist_ok=True)
            copy_loose_refs(child, destination / child.name, name)
        elif child.is_file() and prefix != "refs":  # Git would prefer refs/x over refs/tags/x, so x can shadow a tag.
            value = read_small(child, 4096).strip()
            if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}|ref: refs/[^\s]+", value):
                (destination / child.name).write_text(value + "\n", encoding="utf-8")


def run_git(view: Path, *args: str, stdin: bytes | None = None) -> bytes:
    """Run Git against the clean view only. No configuration from the target or this machine applies."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1", GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", LC_ALL="C",
    )
    command = [
        "git", "--no-pager", "--git-dir", str(view), "-c", f"core.attributesFile={os.devnull}",
        "-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false", "-c", "core.quotePath=false",
        "-c", "core.commitGraph=false", "-c", "core.multiPackIndex=false", *args,
    ]
    try:
        done = subprocess.run(command, input=stdin, cwd=view, env=environment, capture_output=True,
                              timeout=GIT_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        raise Refused(f"Git timed out running {args[0]}.") from None
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise Refused(f"Git {args[0]} failed: {detail[0] if detail else 'no detail'}")
    return done.stdout


def resolve_commit(view: Path, ref: str) -> dict[str, str]:
    if not ref or ref.startswith("-") or not re.fullmatch(r"[\w./@{}~^+-]+", ref):
        raise Refused(f"{ref!r} isn't a usable Git revision.")
    try:
        commit = run_git(view, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    except Refused:
        raise Refused(f"{ref!r} isn't a commit in this repository. Without commits, use --working-tree.") from None
    if re.fullmatch(r"[0-9a-fA-F]{4,64}", ref) and not commit.startswith(ref.lower()):
        raise Refused(f"a ref named {ref} shadows the commit with that name. Give the full commit ID, or the ref's full name.")
    full_name = run_git(view, "rev-parse", "--symbolic-full-name", ref).decode().strip()
    return {"ref": ref, "full_ref": full_name, "commit": commit}


def read_objects(view: Path, names: list[str]) -> Iterator[tuple[str, str | None, bytes]]:
    """Read objects and prove each one matches its name, which cat-file doesn't check. Missing gives None."""
    for start in range(0, len(names), OBJECT_BATCH):
        batch = names[start:start + OBJECT_BATCH]
        output = run_git(view, "cat-file", "--batch", stdin="".join(f"{name}\n" for name in batch).encode())
        offset = 0
        for name in batch:
            newline = output.index(b"\n", offset)
            header = output[offset:newline].split()
            if len(header) == 2 and header[1] == b"missing":
                offset = newline + 1
                yield name, None, b""
                continue
            if len(header) != 3:
                raise Refused(f"Git returned something unexpected for object {name}.")
            kind, size = header[1], int(header[2])
            body = output[newline + 1:newline + 1 + size]
            offset = newline + 1 + size + 1
            algorithm = "sha256" if len(name) == 64 else "sha1"
            if hashlib.new(algorithm, kind + b" %d\0" % size + body).hexdigest() != name:
                raise Refused(
                    f"object {name} doesn't match its name, so this repository's history is damaged or has been altered. "
                    "Get a fresh clone, or use --working-tree."
                )
            yield name, kind.decode(), body


def walk_commit(view: Path, commit: str) -> list[tuple[str, str, str]]:
    """Every (path, mode, object name) in a commit, with the commit and every tree checked on the way down."""
    _, kind, body = next(read_objects(view, [commit]))
    match = re.match(rb"tree ([0-9a-f]{40,64})\n", body)
    if kind != "commit" or not match:
        raise Refused(f"{commit} isn't a readable commit.")
    width = len(commit) // 2
    entries: list[tuple[str, str, str]] = []
    pending = [("", match.group(1).decode())]
    depth = 0
    while pending:
        depth += 1
        if depth > MAX_TREE_DEPTH:
            raise Refused("this commit's directories nest too deeply to review.")
        unique = sorted({name for _prefix, name in pending})
        trees = {}
        for name, kind, body in read_objects(view, unique):
            if kind != "tree":
                raise Refused(f"this repository is incomplete: tree {name} is missing or isn't a tree.")
            trees[name] = body
        following = []
        for prefix, name in pending:
            body, offset = trees[name], 0
            while offset < len(body):
                space = body.index(b" ", offset)
                nul = body.index(b"\0", space)
                mode = body[offset:space].decode("ascii", "replace")
                path = prefix + body[space + 1:nul].decode("utf-8", "surrogateescape")
                child = body[nul + 1:nul + 1 + width].hex()
                offset = nul + 1 + width
                if len(entries) + len(following) >= MAX_TREE_ENTRIES:
                    raise Refused(f"this commit has more than {MAX_TREE_ENTRIES} paths. Review it in smaller parts.")
                if mode == "40000":
                    following.append((path + "/", child))
                else:
                    entries.append((path, mode, child))
        pending = following
    return entries


def object_sizes(view: Path, names: list[str]) -> dict[str, tuple[str, int]]:
    """Kind and size of each object. A missing one isn't in the result."""
    output = run_git(view, "cat-file", "--batch-check", stdin="".join(f"{name}\n" for name in names).encode())
    sizes = {}
    for line in output.decode("ascii", "replace").splitlines():
        parts = line.split()
        if len(parts) == 3:
            sizes[parts[0]] = (parts[1], int(parts[2]))
    return sizes


def copy_revision(view: Path, commit: str, writer: SnapshotWriter) -> tuple[dict[str, str], dict[str, str]]:
    """Copy a commit into the snapshot through verified objects. Returns its files and its symbolic links, by object name."""
    entries = walk_commit(view, commit)
    files = [(path, name) for path, mode, name in entries if mode not in ("120000", "160000")]
    sizes = object_sizes(view, sorted({name for _path, name in files}))
    for path, mode, _name in entries:
        if mode == "120000":
            writer.skip("a symbolic link that was not followed", path)
        elif mode == "160000":
            writer.skip("a submodule, whose code is in another repository", path)
    wanted: dict[str, list[str]] = {}
    for path, name in files:
        kind, size = sizes.get(name, (None, 0))
        if kind is None:
            writer.skip("missing from this clone", path)
        elif kind != "blob":
            writer.skip("an entry that isn't a file", path)
        elif size > MAX_FILE_BYTES:
            writer.skip("larger than the file limit", path)
        else:
            wanted.setdefault(name, []).append(path)
    for name, _kind, body in read_objects(view, sorted(wanted)):
        for path in wanted[name]:
            writer.add(path, body)
    return {path: name for path, name in files}, {path: name for path, mode, name in entries if mode == "120000"}


def disk_entry_differs(child: Path, relative: str, tree: dict[str, str], links: dict[str, str], algorithm: str) -> bool:
    """A link is compared by where it points and never followed. A checkout without link support holds that text in a file."""
    expected = links.get(relative) or tree.get(relative)
    if expected is None:
        return True
    status = child.lstat()
    if stat.S_ISLNK(status.st_mode):
        if relative not in links:
            return True
        content = os.fsencode(os.readlink(child).replace(os.sep, "/"))
    elif not stat.S_ISREG(status.st_mode):
        return True
    elif status.st_size > MAX_FILE_BYTES:
        return False
    else:
        content = child.read_bytes()
    return hashlib.new(algorithm, b"blob %d\0" % len(content) + content).hexdigest() != expected


def compare_disk(target: Path, tree: dict[str, str], links: dict[str, str]) -> tuple[list[str], str | None]:
    """Name what's on disk but not in the reviewed commit, so a decoy history can't pass as the code."""
    differences: list[str] = []
    examined = 0
    algorithm = "sha256" if any(len(name) == 64 for name in [*tree.values(), *links.values()]) else "sha1"
    for directory, subdirectories, files in os.walk(target, followlinks=False):
        current = Path(directory)
        kept, entries = [], []
        for name in sorted(subdirectories):
            relative = (current / name).relative_to(target).as_posix()
            if relative == ".git" or relative == POLICY_ROOT:
                continue
            if (current / name).is_symlink():
                entries.append(name)  # os.walk lists a link to a directory here, and won't enter it.
            elif name in SKIPPED_DIRECTORIES:
                differences.append(relative + "/ (not compared)")
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted([*entries, *files]):
            child = current / name
            relative = child.relative_to(target).as_posix()
            if relative == ".git":
                continue
            examined += 1
            if examined > MAX_DISK_COMPARE:
                return differences, f"Only the first {MAX_DISK_COMPARE} files on disk were compared with the reviewed commit."
            if disk_entry_differs(child, relative, tree, links, algorithm):
                differences.append(relative)
    return differences, None


def find_policy(snapshot: Path, target: Path, writer: SnapshotWriter, limits: list[str]) -> dict[str, Any] | None:
    """Locate PolicyRelay guidance. It's commonly gitignored, so also look on disk beside the commit."""
    index = f"{POLICY_ROOT}/index.md"
    if (snapshot / index).is_file():
        return {"index": index, "source": "the reviewed files"}
    root = target / POLICY_ROOT
    if (target / "security").is_symlink() or root.is_symlink() or (root / "index.md").is_symlink() or not (root / "index.md").is_file():
        return None
    copied = []
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        current = Path(directory)
        subdirectories[:] = sorted(name for name in subdirectories if not (current / name).is_symlink())
        for name in sorted(files):
            child = current / name
            relative = child.relative_to(target).as_posix()
            if relative in writer.written:
                continue
            if child.is_symlink() or not child.is_file() or not name.lower().endswith(".md"):
                writer.skip("in the policy directory but not Markdown guidance", relative)
            elif child.stat().st_size > MAX_FILE_BYTES:
                writer.skip("larger than the file limit", relative)
            else:
                writer.add(relative, child.read_bytes())
                copied.append(relative)
    limits.append(f"PolicyRelay guidance was read from disk beside the reviewed commit, so it isn't part of that commit: {preview(copied)}")
    return {"index": index, "source": "the target's working tree, beside the reviewed commit", "files_from_disk": copied}


def walk_snapshot(snapshot: Path) -> Iterator[tuple[str, Path]]:
    for directory, subdirectories, files in os.walk(snapshot):
        subdirectories.sort()
        for name in sorted(files):
            path = Path(directory) / name
            yield original_path(path.relative_to(snapshot).as_posix()), path


def find_leads(snapshot: Path, writer: SnapshotWriter) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """Suppressions are kept apart from leads: they are counted, and a flood of them can't use up the lead list."""
    agent_files = set(writer.agent_files())
    found: list[tuple[int, str, int, str, str]] = []
    suppressions: list[dict[str, Any]] = []
    per_file: dict[str, int] = {}
    for relative, path in walk_snapshot(snapshot):
        is_agent = relative in agent_files
        if is_suppression_file(relative):
            found.append((0, relative, 1, "suppression-file", "Scanner suppression file"))
        text = path.read_text(encoding="utf-8", errors="replace")
        hidden = INVISIBLE if is_agent else HIDDEN_ANYWHERE
        for number, line in enumerate(text.split("\n"), 1):
            if hidden.search(line):
                kind = "hidden-text"
            elif STEERING_TEXT.search(line):
                kind = "instruction-text"
            elif INLINE_SUPPRESSION.search(line):
                per_file[relative] = per_file.get(relative, 0) + 1
                if len(suppressions) < MAX_SUPPRESSIONS_LISTED:
                    suppressions.append({"file": relative, "line": number, "text": display_line(line)})
                continue
            else:
                continue
            found.append((0 if is_agent else 1, relative, number, kind, display_line(line)))
    found.sort(key=lambda item: item[:3])
    leads = [
        {"id": f"L{index:03d}", "file": file, "line": line, "kind": kind, "text": text}
        for index, (_rank, file, line, kind, text) in enumerate(found[:MAX_LEADS], 1)
    ]
    counted = {"total": sum(per_file.values()), "files": per_file, "listed": suppressions}
    return leads, max(0, len(found) - MAX_LEADS), counted


def display_line(line: str) -> str:
    """Show one line of target text safely: invisible characters become visible, and credentials masked."""
    return visible(mask(re.sub(r"\s+", " ", line).strip()))[:240]


def visible(text: str) -> str:
    return INVISIBLE.sub(lambda match: f"<U+{ord(match.group()):04X}>", text)


def mask(text: str) -> str:
    return CREDENTIAL_SHAPES.sub("[credential withheld]", text)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def text_problem(value: Any, label: str, problems: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{label} must be non-empty text.")


def keys_problem(value: Any, allowed: set[str], required: set[str], label: str, problems: list[str]) -> bool:
    if not isinstance(value, dict):
        problems.append(f"{label} must be an object.")
        return False
    for key in sorted(set(value) - allowed):
        problems.append(f"{label} has an unknown field: {key}.")
    for key in sorted(required - set(value)):
        problems.append(f"{label} is missing: {key}.")
    return True


def snapshot_file(snapshot: Path, cited: str) -> Path | None:
    if not isinstance(cited, str) or not cited or not safe_relative(cited.replace("\\", "/")):
        return None
    for candidate in (data_path(original_path(cited)), cited):
        path = snapshot / candidate
        try:
            if path.is_file() and not path.is_symlink():
                return path
        except (OSError, ValueError):
            return None
    return None


def normalized(text: str) -> str:
    return re.sub(r"\s+", " ", INVISIBLE.sub("", text)).strip()


def inline(value: Any) -> str:
    """One line of supplied text, safe to place in Markdown. It may quote the target, so nothing renders."""
    text = visible(re.sub(r"\s+", " ", mask(str(value))).strip()).replace("\\", "\\\\")
    text = re.sub(r"[`*\[\]~|]", r"\\\g<0>", text)
    text = re.sub(r"(?<!\w)_|_(?!\w)", r"\\_", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"^[#+=-]", r"\\\g<0>", text)
    return re.sub(r"^(\d+)([.)])", r"\1\\\2", text)


def fenced(value: str) -> list[str]:
    text = visible(mask(value)).strip("\n")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", text, fence]


def code(value: Any) -> str:
    text = visible(re.sub(r"\s+", " ", mask(str(value))).strip()).replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}" if longest else f"`{text}`"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare, draw, and render a threat model.")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--repo", help="A repository to snapshot. Leave out when there is none. Run again for each more you find.")
    prepare.add_argument("--name", help="What to call this repository in the report. Default: its folder name.")
    prepare.add_argument("--head", help="Commit, tag, or branch to read. Default: the repository's HEAD.")
    prepare.add_argument("--working-tree", action="store_true", help="Read files on disk instead of a commit.")
    prepare.add_argument("--allow-inside-target", action="store_true")
    for name in ("diagram", "render"):
        commands.add_parser(name).add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        return {"prepare": cmd_prepare, "diagram": cmd_diagram, "render": cmd_render}[args.command](args)
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError) as error:
        print(f"Refused: couldn't complete this because of a file problem: {error}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------------------- prepare


def cmd_prepare(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    if args.repo:
        check_location(out, args)  # Before anything is created, so a refusal leaves the repository untouched.
    elif args.name or args.head or args.working_tree:
        raise Refused("--name, --head, and --working-tree only apply with --repo.")
    manifest = open_output(out)
    if args.repo:
        snapshot_repository(out, manifest, args)
    write_json(out / "manifest.json", manifest)
    if not args.repo:
        print(f"Prepared {out} with no repository.")
    return 0


def check_location(out: Path, args: argparse.Namespace) -> None:
    target = Path(args.repo).expanduser()
    if not target.is_absolute():
        raise Refused("--repo must be an absolute path.")
    target = target.resolve()
    if not target.is_dir():
        raise Refused(f"{target} is not a directory.")
    if is_within(Path.cwd().resolve(), target) and not args.allow_inside_target:
        raise Refused(
            "this session is inside the repository, so it may already have loaded its instructions and fired its "
            "hooks. Start a new session in a directory outside it."
        )
    if is_within(out, target):
        raise Refused("--out must be outside the repository, so nothing is written to it.")
    if is_within(target, out):
        raise Refused("--out must not contain the repository.")
    if args.working_tree and args.head:
        raise Refused("--working-tree can't be combined with --head, which names a commit.")


def open_output(out: Path) -> dict[str, Any]:
    """Create the output folder or carry on with this skill's own, keeping whatever earlier steps wrote."""
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise Refused(f"{out} must be a real directory.")
    out.mkdir(parents=True, exist_ok=True)
    unexpected = [child.name for child in out.iterdir() if child.name not in OUTPUT_NAMES]
    if unexpected:
        raise Refused(f"{out} holds files this helper didn't write ({unexpected[0]}). Choose an empty directory.")
    path = out / "manifest.json"
    if not path.exists():
        return {"schema": SCHEMA, "tool": "threat-model", "repos": {}}
    return load_manifest(out)


def load_manifest(out: Path) -> dict[str, Any]:
    try:
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        if manifest["tool"] != "threat-model" or not isinstance(manifest["repos"], dict):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("manifest.json isn't what prepare wrote. Run prepare again in a new folder.") from None
    return manifest


def snapshot_repository(out: Path, manifest: dict[str, Any], args: argparse.Namespace) -> None:
    target = Path(args.repo).expanduser().resolve()
    inside = is_within(Path.cwd().resolve(), target)
    name = args.name or target.name
    if not REPO_NAME.match(name):
        raise Refused(f"{name!r} can't name a snapshot. Use --name with letters, digits, dots, hyphens, or underscores.")
    earlier = manifest["repos"].get(name)
    if earlier and earlier["target"] != str(target):
        raise Refused(f"a different repository is already called {name}. Use --name to tell them apart.")

    limits = ["Nothing was executed, so behavior that only appears at runtime was not observed from this repository."]
    gitdir, repository_note = find_repository(target, bool(args.head))
    if repository_note and not args.working_tree:
        if args.head:
            raise Refused(f"{repository_note} Use --working-tree.")
        limits.append(repository_note + " So the files on disk were read, not a commit.")
    use_git = bool(gitdir) and not args.working_tree
    if use_git and not shutil.which("git"):
        if args.head:
            raise Refused("Git isn't installed, so --head can't be read. Install Git or use --working-tree.")
        use_git = False
        limits.append("Git isn't installed here, so the files on disk were read, not a commit.")
    if args.head and not gitdir:
        raise Refused(f"{target} isn't a Git repository, so --head doesn't apply.")

    snapshot = out / "snapshots" / name
    if snapshot.exists():
        make_writable(snapshot)
        shutil.rmtree(snapshot)
    snapshot.mkdir(parents=True)
    writer = SnapshotWriter(snapshot)
    head_info: dict[str, str] | None = None
    disk_differences: list[str] = []
    history = ""
    if use_git:
        assert gitdir is not None
        with tempfile.TemporaryDirectory(prefix="threat-model-") as scratch:
            view = build_clean_view(gitdir, Path(scratch) / "view.git")
            head_info = resolve_commit(view, args.head or "HEAD")
            tree, links = copy_revision(view, head_info["commit"], writer)
            history = read_history(view, head_info["commit"])
        limits.append("Uncommitted changes were not read. Only the named commit was.")
        if gitdir != target:
            disk_differences, note = compare_disk(target, tree, links)
            if disk_differences:
                limits.append(
                    f"{len(disk_differences)} path(s) on disk are not in the commit that was read or differ from it, and were "
                    f"not read: {preview(disk_differences)}"
                )
            if note:
                limits.append(note)
    else:
        copy_working_tree(target, writer)
        limits.append("The files on disk were read, so no commit identifies exactly what was examined.")

    policy = find_policy(snapshot, target, writer, limits)
    limits.extend(writer.limits())
    leads, truncated, suppressions = find_leads(snapshot, writer)
    if truncated:
        limits.append(
            f"The steering sweep stopped listing leads at {MAX_LEADS}; {truncated} more were not listed, "
            "so read past the list."
        )
    for lead in leads:
        lead["id"] = f"{name}/{lead['id']}"
        lead["repo"] = name
    file_list = out / "files" / f"{name}.txt"
    file_list.parent.mkdir(exist_ok=True)
    file_list.write_text("".join(f"{path}\n" for path in sorted(writer.written)), encoding="utf-8", errors="replace")
    if history:
        (out / "files" / f"{name}.history.txt").write_text(history, encoding="utf-8", errors="replace")
    digest = digest_snapshot(snapshot)
    make_read_only(snapshot)
    entry: dict[str, Any] = {
        "target": str(target),
        "mode": "revision" if use_git else "working-tree",
        "head": head_info,
        "inside_target": inside,
        "snapshot": f"snapshots/{name}",
        "snapshot_sha256": digest,
        "files": writer.file_count,
        "bytes": writer.total_bytes,
        "agent_files": writer.agent_files(),
        "leads": leads,
        "suppressions": suppressions,
        "skipped": {reason: sorted(paths) for reason, paths in sorted(writer.skipped.items())},
        "disk_differences": disk_differences,
        "limits": limits,
    }
    if policy:
        entry["policyrelay"] = policy
    manifest["repos"][name] = entry
    described = head_info["commit"][:12] if head_info else "files on disk"
    print(f"Prepared {name} at {described}: {writer.file_count} files, {len(leads)} leads.")
    print(f"Read the snapshot, not the repository: {snapshot}")


def read_history(view: Path, commit: str) -> str:
    """Commit subjects, for testing the model against what has already gone wrong. They are data, like everything else."""
    try:
        raw = run_git(view, "log", "--no-show-signature", f"--max-count={MAX_HISTORY_COMMITS}", "--date=short", "--format=%h %ad %s", commit)
    except Refused:
        return ""
    return "".join(display_line(line) + "\n" for line in raw.decode("utf-8", "replace").splitlines())


# ---------------------------------------------------------------------------------------- the model


def load_model(out: Path) -> tuple[Any, list[str]]:
    path = out / "threat-model.json"
    if not (out / "manifest.json").is_file():
        raise Refused(f"{out} has no manifest.json. Run prepare first.")
    if not path.is_file():
        raise Refused(f"{out} has no threat-model.json. Write it first, using references/model-contract.md.")
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as error:
        return None, [f"threat-model.json isn't valid JSON: {error}"]
    problems = []
    if CREDENTIAL_SHAPES.search(raw):
        problems.append("threat-model.json holds text shaped like a credential. Cite where it is, and don't copy its value.")
    return data, problems


def report_problems(problems: list[str]) -> int:
    print(f"threat-model.json has {len(problems)} problem(s). Correct them against the evidence:", file=sys.stderr)
    for problem in problems:
        print(f"- {problem}", file=sys.stderr)
    return 1


def text_list_problem(value: Any, label: str, problems: list[str]) -> list[Any]:
    if not isinstance(value, list):
        problems.append(f"{label} must be a list.")
        return []
    return value


def identified(items: list[Any], label: str, problems: list[str]) -> dict[str, dict[str, Any]]:
    """Index items by id, and name any id that can't be used to refer to them."""
    found: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            problems.append(f"{label} {index} must be an object.")
            continue
        value = item.get("id")
        if not isinstance(value, str) or not IDENTIFIER.match(value):
            problems.append(f"{label} {index}: id must start with a letter and hold only letters, digits, hyphens, or underscores.")
        elif value in found:
            problems.append(f"{label} id {value} is used more than once.")
        else:
            found[value] = item
    return found


def check_architecture(data: dict[str, Any], problems: list[str]) -> None:
    """What the diagram needs. It runs from the first draft on, so it asks for nothing else."""
    zones = identified(text_list_problem(data.get("zones", []), "zones", problems), "zone", problems)
    components = identified(text_list_problem(data.get("components", []), "components", problems), "component", problems)
    flows = identified(text_list_problem(data.get("flows", []), "flows", problems), "flow", problems)
    if len(components) > MAX_DIAGRAM_COMPONENTS:
        problems.append(f"{len(components)} components is too many to read in one diagram. Merge alike ones, up to {MAX_DIAGRAM_COMPONENTS}.")
    for key, zone in zones.items():
        text_problem(zone.get("name"), f"zone {key} name", problems)
    for key, component in components.items():
        text_problem(component.get("name"), f"component {key} name", problems)
        if component.get("type") not in TYPES:
            problems.append(f"component {key}: type must be one of {', '.join(TYPES)}.")
        if component.get("zone") not in zones:
            problems.append(f"component {key}: zone {component.get('zone')!r} isn't in zones.")
        if component.get("basis") not in BASES:
            problems.append(f"component {key}: basis must be one of {', '.join(BASES)}.")
        metadata = component.get("metadata", {})
        if not isinstance(metadata, dict) or not all(isinstance(value, (str, int, float)) for value in metadata.values()):
            problems.append(f"component {key}: metadata must map names to short text.")
    for key, flow in flows.items():
        for end in ("from", "to"):
            if flow.get(end) not in components:
                problems.append(f"flow {key}: {end} {flow.get(end)!r} isn't in components.")
        if flow.get("basis") not in BASES:
            problems.append(f"flow {key}: basis must be one of {', '.join(BASES)}.")


def severity_of(threat: Any) -> str | None:
    if not isinstance(threat, dict):
        return None
    try:
        return SEVERITY_MATRIX.get((threat.get("impact"), threat.get("likelihood")))
    except TypeError:
        return None


def component_tier(component: dict[str, Any], threats: list[Any]) -> str:
    """The fill: the worst open threat on this component, grey until someone has assessed it."""
    if component.get("type") == "actor":
        return "actor"
    tiers = []
    touched = False
    for threat in threats:
        if isinstance(threat, dict) and isinstance(threat.get("components"), list) and component["id"] in threat["components"]:
            touched = True
            severity = severity_of(threat)
            if severity and threat.get("status") != "mitigated":
                tiers.append(severity)
    if tiers:
        return min(tiers, key=lambda name: RANK[name])
    return "clear" if touched or component.get("no_open_threats") else "unassessed"


# ---------------------------------------------------------------------------------------- the diagram


TIER_STYLE = {
    "critical": "fill:#b91c1c,color:#ffffff,stroke:#450a0a",
    "high": "fill:#f97316,color:#111111,stroke:#7c2d12",
    "medium": "fill:#fde047,color:#111111,stroke:#713f12",
    "low": "fill:#93c5fd,color:#111111,stroke:#1e3a8a",
    "clear": "fill:#86efac,color:#111111,stroke:#14532d",
    "unassessed": "fill:#e5e7eb,color:#111111,stroke:#374151",
    "actor": "fill:#ffffff,color:#111111,stroke:#111827",
}
TIER_LABEL = {
    "critical": "Critical open threat", "high": "High open threat", "medium": "Medium open threat", "low": "Low open threat",
    "clear": "Assessed, nothing open", "unassessed": "Not assessed yet", "actor": "Person or outside actor",
}
ZONE_STYLE = "fill:#f8fafc,stroke:#64748b,color:#111111"
SHAPES = {"actor": '(["{}"])', "process": '["{}"]', "data": '[("{}")]', "model": '{{{{"{}"}}}}', "external": '[/"{}"/]'}


def mermaid_text(value: Any, limit: int = MAX_LABEL_CHARS) -> str:
    """One label's text, with everything Mermaid could treat as syntax written as a numeric code."""
    text = re.sub(r"\s+", " ", mask(INVISIBLE.sub("", str(value)))).strip()
    if len(text) > limit:
        text = text[:limit - 3].rstrip() + "..."
    return re.sub(r"[^A-Za-z0-9 .,:;/_+=()@-]", lambda match: f"#{ord(match.group())};", text)


def build_diagram(data: dict[str, Any]) -> str:
    zones, components, flows = data.get("zones", []), data.get("components", []), data.get("flows", [])
    threats = data.get("threats", [])
    threats = threats if isinstance(threats, list) else []
    nodes = {item["id"]: f"n{index}" for index, item in enumerate(components, 1)}
    lines = ["flowchart LR"]
    lines += [f"  classDef {name} {style}" for name, style in TIER_STYLE.items()]
    lines.append("  classDef unverified stroke-dasharray:6 4,stroke-width:2px")
    for index, zone in enumerate(zones, 1):
        lines.append(f'  subgraph z{index}["{mermaid_text(zone["name"])}"]')
        for item in components:
            if item["zone"] == zone["id"]:
                label = component_label(item, threats)
                lines.append("    " + nodes[item["id"]] + SHAPES[item["type"]].format(label))
        lines.append("  end")
    for flow in flows:
        arrow = "-->" if flow["basis"] == "observed" else "-.->"
        label = f'|"{mermaid_text(flow["label"])}"|' if flow.get("label") else ""
        lines.append(f"  {nodes[flow['from']]} {arrow}{label} {nodes[flow['to']]}")
    for item in components:
        lines.append(f"  class {nodes[item['id']]} {component_tier(item, threats)}")
        if item["basis"] != "observed":
            lines.append(f"  class {nodes[item['id']]} unverified")
    lines.append('  subgraph legend["Legend"]')
    entries = [*TIER_LABEL.items(), ("unverified", "Dashed: documented, inferred, or assumed")]
    lines += [f'    key{index}["{mermaid_text(text)}"]' for index, (_name, text) in enumerate(entries, 1)]
    lines.append("  end")
    for index, (name, _text) in enumerate(entries, 1):
        lines.append(f"  class key{index} {name if name != 'unverified' else 'actor'}")
    lines.append(f"  class key{len(entries)} unverified")
    # Mermaid's default box is pale yellow, which would read as a rating here.
    lines += [f"  style {name} {ZONE_STYLE}" for name in [*(f"z{index}" for index in range(1, len(zones) + 1)), "legend"]]
    return "\n".join(lines) + "\n"


def component_label(component: dict[str, Any], threats: list[Any]) -> str:
    parts = [mermaid_text(component["name"])]
    metadata = component.get("metadata") or {}
    parts += [mermaid_text(f"{key}: {value}", MAX_METADATA_CHARS) for key, value in list(metadata.items())[:MAX_METADATA_SHOWN]]
    tier = component_tier(component, threats)
    if tier in RANK:
        count = sum(1 for threat in threats if isinstance(threat, dict) and threat.get("status") != "mitigated"
                    and component["id"] in (threat.get("components") or []))
        parts.append(f"{tier.upper()}: {count} open")
    return "<br/>".join(parts)


def write_diagram(out: Path, data: dict[str, Any]) -> tuple[str, list[str]]:
    diagram = build_diagram(data)
    if len(diagram) > MAX_DIAGRAM_CHARS:
        return diagram, [f"the diagram is {len(diagram)} characters, more than most viewers will draw. Merge alike components or shorten metadata."]
    (out / "diagram.mmd").write_text(diagram, encoding="utf-8")
    return diagram, []


def cmd_diagram(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    data, problems = load_model(out)
    if not isinstance(data, dict):
        return report_problems(problems or ["threat-model.json must be an object."])
    check_architecture(data, problems)
    if problems:
        return report_problems(problems)
    _diagram, problems = write_diagram(out, data)
    if problems:
        return report_problems(problems)
    components = data.get("components", [])
    threats = data.get("threats", [])
    waiting = sum(1 for item in components if component_tier(item, threats if isinstance(threats, list) else []) == "unassessed")
    print(f"Wrote {out / 'diagram.mmd'}: {len(components)} components, {len(data.get('flows', []))} flows, {waiting} not assessed yet.")
    return 0


# ----------------------------------------------------------------------------------------- render


def cmd_render(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    data, problems = load_model(out)
    manifest = load_manifest(out)
    for name, entry in manifest["repos"].items():
        if digest_snapshot(out / entry["snapshot"]) != entry["snapshot_sha256"]:
            raise Refused(f"the snapshot of {name} changed after prepare, so its evidence can't be trusted. Run prepare again.")
    if data is None:
        return report_problems(problems)
    try:
        problems += validate(data, manifest, out)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        problems.append(f"a field has the wrong type ({error}). Compare it with references/model-contract.md.")
    if problems:
        return report_problems(problems)
    diagram, problems = write_diagram(out, data)
    if problems:
        return report_problems(problems)
    report = out / "threat-model.md"
    text = build_report(data, manifest, diagram)
    report.write_text(text, encoding="utf-8", errors="replace")
    write_json(out / "threat-model.otm.json", build_otm(data))
    counts = open_counts(data["threats"])
    print("Wrote", report, f"({len(text) // 1024} KB) |", ", ".join(f"{counts[name]} {name} open" for name in SEVERITIES))
    return 0


class Checker:
    """Validation that needs the sources, the snapshots, and the problem list at hand."""

    def __init__(self, data: dict[str, Any], manifest: dict[str, Any], out: Path, problems: list[str]) -> None:
        self.manifest, self.out, self.problems = manifest, out, problems
        self.sources = identified(data["sources"], "source", problems)
        self.unknowns = identified(data["unknowns"], "unknown", problems)
        self.components = {item["id"]: item for item in data["components"] if isinstance(item, dict) and "id" in item}
        self.flows = {item["id"]: item for item in data["flows"] if isinstance(item, dict) and "id" in item}
        self.threats = identified(data["threats"], "threat", problems)
        self.assets = identified(data["assets"], "asset", problems)

    def text(self, value: Any, label: str, limit: int = MAX_TEXT_CHARS) -> None:
        text_problem(value, label, self.problems)
        if isinstance(value, str) and len(value) > limit:
            self.problems.append(f"{label} is {len(value)} characters, over the limit of {limit}. Say it once, in plain words, and keep the facts.")

    def source_used(self, value: Any, label: str) -> dict[str, Any] | None:
        source = self.sources.get(value) if isinstance(value, str) else None
        if source is None:
            self.problems.append(f"{label}: source {value!r} isn't in sources.")
            return None
        if source.get("status") != "used":
            self.problems.append(f"{label}: source {value} is marked {source.get('status')}, so nothing can cite it.")
            return None
        return source

    def evidence(self, item: Any, label: str) -> None:
        if not keys_problem(item, EVIDENCE_KEYS, {"source"}, label, self.problems):
            return
        source = self.source_used(item.get("source"), label)
        if source is None:
            return
        if source.get("kind") != "repo":
            if "file" in item or "line" in item or "credential" in item:
                self.problems.append(f"{label}: only a repository source has file and line. Use locator.")
            self.text(item.get("locator"), f"{label} locator")
            if "quote" in item:
                self.text(item["quote"], f"{label} quote")
            if "observed" in item and not (isinstance(item["observed"], str) and DATE.match(item["observed"])):
                self.problems.append(f"{label}: observed must be a date, as YYYY-MM-DD.")
            return
        if "locator" in item or "observed" in item:
            self.problems.append(f"{label}: a repository source uses file and line, not locator or observed.")
        entry = self.manifest["repos"].get(source.get("repo"))
        if entry is None:
            return  # Named by the source's own check.
        self.quote(self.out / entry["snapshot"], item, label)

    def quote(self, snapshot: Path, item: dict[str, Any], label: str) -> None:
        cited, line, quote = item.get("file"), item.get("line"), item.get("quote")
        path = snapshot_file(snapshot, cited)
        if path is None:
            self.problems.append(f"{label}: {cited!r} isn't a file in the snapshot. Paths are as in the repository.")
            return
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            self.problems.append(f"{label}: line must be a positive whole number.")
            return
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        if line > len(lines):
            self.problems.append(f"{label}: {cited} has only {len(lines)} lines, not {line}.")
            return
        if item.get("credential") is True and "quote" not in item:
            return
        if not isinstance(quote, str) or not quote.strip():
            self.problems.append(f"{label}: quote the evidence. Only a credential goes unquoted, with credential set to true.")
            return
        if len(quote) > MAX_EVIDENCE_CHARS:
            self.problems.append(f"{label}: the quote is too long. Quote only the lines that prove the point.")
            return
        wanted = normalized(quote)
        if len(wanted) < MIN_EVIDENCE_CHARS:
            self.problems.append(f"{label}: the quote is too short to prove anything. Quote the whole line.")
            return
        span = sum(1 for part in quote.split("\n") if part.strip()) + EVIDENCE_EXTRA_LINES
        if wanted not in normalized("\n".join(lines[line - 1:line - 1 + span])):
            self.problems.append(f"{label}: the quote doesn't appear at or just after {cited}:{line}. Quote the file.")

    def evidence_list(self, value: Any, label: str, required: bool = False) -> list[Any]:
        items = text_list_problem(value if value is not None else [], f"{label} evidence", self.problems)
        if required and not items:
            self.problems.append(f"{label}: evidence is required.")
        if len(items) > MAX_EVIDENCE_PER_ITEM:
            self.problems.append(f"{label}: {len(items)} pieces of evidence is too many. Keep the {MAX_EVIDENCE_PER_ITEM} that prove the most.")
        for index, item in enumerate(items, 1):
            self.evidence(item, f"{label} evidence {index}")
        return items

    def basis(self, item: dict[str, Any], label: str) -> None:
        """Every claim about the system says how it's known, and backs that up."""
        basis = item.get("basis")
        cited = text_list_problem(item.get("sources", []), f"{label} sources", self.problems)
        kinds = [self.source_used(value, label) for value in cited]
        if basis not in BASES:
            self.problems.append(f"{label}: basis must be one of {', '.join(BASES)}.")
        if basis == "observed" and not any(source and source.get("kind") in ("repo", "live", "other") for source in kinds):
            self.problems.append(f"{label}: observed needs a source that shows the thing itself. A document or a person makes it documented.")
        if basis == "documented" and not any(kinds):
            self.problems.append(f"{label}: documented needs the source that says so.")
        if basis == "inferred":
            self.text(item.get("reasoning"), f"{label} reasoning")
        if basis == "assumed" and item.get("unknown") not in self.unknowns:
            self.problems.append(f"{label}: assumed needs unknown, naming the entry in unknowns that would settle it.")
        if "unknown" in item and item["unknown"] not in self.unknowns:
            self.problems.append(f"{label}: unknown {item['unknown']!r} isn't in unknowns.")

    def references(self, values: Any, known: dict[str, Any], noun: str, label: str) -> list[Any]:
        items = text_list_problem(values if values is not None else [], f"{label} {noun}s", self.problems)
        for value in items:
            if value not in known:
                self.problems.append(f"{label}: {noun} {value!r} isn't in {noun}s.")
        return items


def validate(data: Any, manifest: dict[str, Any], out: Path) -> list[str]:
    problems: list[str] = []
    if not keys_problem(data, TOP_KEYS, TOP_KEYS, "threat-model.json", problems):
        return problems
    text_problem(data["target"], "target", problems)
    text_problem(data["summary"], "summary", problems)
    if isinstance(data["summary"], str) and len(data["summary"]) > MAX_SUMMARY_CHARS:
        problems.append(f"summary is {len(data['summary'])} characters, over the limit of {MAX_SUMMARY_CHARS}. Say what matters most.")
    for key in ("sources", "confirmations", "zones", "components", "flows", "assets", "actors", "threats", "boundary_reviews",
                "conflicts", "unknowns", "steering", "dismissed_leads", "not_checked"):
        if not isinstance(data[key], list):
            problems.append(f"{key} must be a list.")
    if problems:
        return problems
    if keys_problem(data["intake"], INTAKE_KEYS, INTAKE_KEYS, "intake", problems):
        text_problem(data["intake"].get("started_from"), "intake started_from", problems)
        if data["intake"].get("stage") not in STAGES:
            problems.append(f"intake: stage must be one of {', '.join(STAGES)}.")
        if data["intake"].get("gaps") not in GAPS:
            problems.append(f"intake: gaps must be one of {', '.join(GAPS)}.")
    if keys_problem(data["system"], SYSTEM_KEYS, SYSTEM_KEYS, "system", problems):
        for key in sorted(SYSTEM_KEYS):
            text_problem(data["system"].get(key), f"system {key}", problems)
    check_architecture(data, problems)
    if problems:
        return problems
    check = Checker(data, manifest, out, problems)
    if not any(item.get("status") == "used" for item in check.sources.values()):
        problems.append("sources has nothing marked used. A threat model needs something to rest on.")
    check_sources(check, manifest)
    for index, item in enumerate(data["confirmations"], 1):
        label = f"confirmation {index}"
        if keys_problem(item, CONFIRMATION_KEYS, CONFIRMATION_KEYS, label, problems):
            check.text(item.get("action"), f"{label} action")
            check.text(item.get("why_risky"), f"{label} why_risky")
            if item.get("decision") not in DECISIONS:
                problems.append(f"{label}: decision must be one of {', '.join(DECISIONS)}.")
    check_system_model(data, check)
    check_threats(data, check, manifest)
    check_llm(data["llm_questions"], check)
    check_conflicts(data, check)
    check_unknowns(data, check)
    check_steering(data, check, manifest)
    check_stride(data, check)
    check_id_mentions(data, problems)
    if keys_problem(data["backtest"], {"checked", "result"}, {"checked", "result"}, "backtest", problems):
        check.text(data["backtest"].get("checked"), "backtest checked")
        check.text(data["backtest"].get("result"), "backtest result")
    check.text(data["architecture_check"], "architecture_check")
    for index, item in enumerate(data["not_checked"], 1):
        text_problem(item, f"not_checked {index}", problems)
    return problems


def check_sources(check: Checker, manifest: dict[str, Any]) -> None:
    named_repos = []
    for key, item in check.sources.items():
        label = f"source {key}"
        if not keys_problem(item, SOURCE_KEYS, {"id", "name", "kind", "status"}, label, check.problems):
            continue
        check.text(item.get("name"), f"{label} name")
        if item.get("kind") not in SOURCE_KINDS:
            check.problems.append(f"{label}: kind must be one of {', '.join(SOURCE_KINDS)}.")
        if item.get("status") not in SOURCE_STATUS:
            check.problems.append(f"{label}: status must be one of {', '.join(SOURCE_STATUS)}.")
        if item.get("status") == "used":
            check.text(item.get("read"), f"{label} read")
            if item.get("kind") == "repo":
                named_repos.append(item.get("repo"))
                if item.get("repo") not in manifest["repos"]:
                    check.problems.append(f"{label}: repo {item.get('repo')!r} has no snapshot. Run prepare, or use another kind if you read it some other way.")
            elif not (isinstance(item.get("observed"), str) and DATE.match(item["observed"])):
                check.problems.append(f"{label}: observed must say when this was read, as YYYY-MM-DD.")
        elif item.get("status") in ("not-reachable", "declined"):
            check.text(item.get("note"), f"{label} note")
    for name in sorted(set(manifest["repos"]) - set(named_repos)):
        check.problems.append(f"the snapshot of {name} isn't in sources. List it as a used repo source.")


def check_system_model(data: dict[str, Any], check: Checker) -> None:
    problems = check.problems
    if not data["components"]:
        problems.append("components is empty. A threat model needs a system to describe.")
    if not data["zones"]:
        problems.append("zones is empty. Say where the trust boundaries are, even if there is one.")
    for item in data["zones"]:
        label = f"zone {item.get('id')}"
        if keys_problem(item, ZONE_KEYS, ZONE_KEYS, label, problems):
            check.text(item.get("trust"), f"{label} trust")
            if item.get("trust_level") not in TRUST_LEVELS:
                problems.append(f"{label}: trust_level must be one of {', '.join(TRUST_LEVELS)}.")
    threatened = {value for threat in check.threats.values() for value in (threat.get("components") or [])}
    for key, item in check.components.items():
        label = f"component {key}"
        if not keys_problem(item, COMPONENT_KEYS, {"id", "name", "type", "zone", "basis"}, label, problems):
            continue
        check.basis(item, label)
        if item.get("type") == "actor":
            continue
        for field in ("no_open_threats", "not_assessed"):
            if field in item:
                check.text(item[field], f"{label} {field}")
        if "no_open_threats" in item and "not_assessed" in item:
            problems.append(f"{label}: no_open_threats and not_assessed can't both hold.")
        if key in threatened and "not_assessed" in item:
            problems.append(f"{label}: it has threats listed, so it can't also be not_assessed.")
        if key not in threatened and "no_open_threats" not in item and "not_assessed" not in item:
            problems.append(f"{label} isn't accounted for. List a threat on it, or say why none is open (no_open_threats), or why it wasn't assessed (not_assessed).")
    for key, item in check.flows.items():
        label = f"flow {key}"
        if keys_problem(item, FLOW_KEYS, {"id", "from", "to", "basis"}, label, problems):
            check.basis(item, label)
            for field in ("channel", "guarantees"):
                if field in item:
                    check.text(item[field], f"{label} {field}")
    for key, item in check.assets.items():
        label = f"asset {key}"
        if keys_problem(item, ASSET_KEYS, {"id", "name", "why", "objectives", "basis"}, label, problems):
            check.text(item.get("name"), f"{label} name")
            check.text(item.get("why"), f"{label} why")
            objectives = text_list_problem(item.get("objectives"), f"{label} objectives", problems)
            if not objectives or any(value not in OBJECTIVES for value in objectives):
                problems.append(f"{label}: objectives must list at least one of {', '.join(OBJECTIVES)}.")
            check.basis(item, label)
            check.references(item.get("where"), check.components, "component", label)
    if not data["assets"]:
        problems.append("assets is empty. Say what is worth protecting, even if that has to be an assumption.")
    for index, item in enumerate(data["actors"], 1):
        label = f"actor {index}"
        if keys_problem(item, ACTOR_KEYS, ACTOR_KEYS, label, problems):
            check.text(item.get("name"), f"{label} name")
            check.text(item.get("can"), f"{label} can")
            check.text(item.get("cannot"), f"{label} cannot")
    if not data["actors"]:
        problems.append("actors is empty. Say who could abuse this system.")
    # Every flow that crosses a trust boundary gets a threat or a stated conclusion, so none is passed over in silence.
    crossing = {key for key, flow in check.flows.items()
                if check.components[flow["from"]]["zone"] != check.components[flow["to"]]["zone"]}
    reviewed = []
    for index, item in enumerate(data["boundary_reviews"], 1):
        label = f"boundary review {index}"
        if keys_problem(item, {"flow", "conclusion"}, {"flow", "conclusion"}, label, problems):
            check.text(item.get("conclusion"), f"{label} conclusion")
            if item.get("flow") not in crossing:
                problems.append(f"{label}: {item.get('flow')!r} isn't a flow that crosses a trust boundary.")
            reviewed.append(item.get("flow"))
    in_threats = {value for threat in check.threats.values() for value in (threat.get("flows") or [])}
    for key in sorted(crossing - in_threats - set(reviewed)):
        flow = check.flows[key]
        problems.append(f"flow {key} crosses a trust boundary ({flow['from']} to {flow['to']}) and isn't accounted for. Name it in a threat, or add a boundary review.")


def check_threats(data: dict[str, Any], check: Checker, manifest: dict[str, Any]) -> None:
    problems = check.problems
    has_policy = any("policyrelay" in entry for entry in manifest["repos"].values())
    if len(check.threats) > MAX_THREATS:
        problems.append(f"{len(check.threats)} threats is a list of findings, not a threat model. Merge what shares a root cause or a fix, and fold hygiene into one low entry per area, up to {MAX_THREATS}.")
    calibration = data["calibration"]
    if keys_problem(calibration, set(SEVERITIES), set(SEVERITIES), "calibration", problems):
        for name in SEVERITIES:
            check.text(calibration.get(name), f"calibration {name}")
    for key, item in check.threats.items():
        label = f"threat {key}"
        required = {"id", "title", "stride", "components", "assets", "source", "action", "consequence", "likelihood", "impact",
                    "rating_reason", "status", "evidence", "mitigations"}
        if not keys_problem(item, THREAT_KEYS, required, label, problems):
            continue
        check.text(item.get("title"), f"{label} title", MAX_TITLE_CHARS)
        for field in ("source", "action", "consequence"):
            check.text(item.get(field), f"{label} {field}", MAX_PART_CHARS[field])
        check.text(item.get("rating_reason"), f"{label} rating_reason")
        if "prerequisites" in item:
            check.text(item["prerequisites"], f"{label} prerequisites", MAX_PART_CHARS["prerequisites"])
        if "detection" in item:
            check.text(item["detection"], f"{label} detection")
        for value in text_list_problem(item.get("references", []), f"{label} references", problems):
            check.text(value, f"{label} reference", MAX_TITLE_CHARS)
        if not check.references(item.get("assets"), check.assets, "asset", label):
            problems.append(f"{label}: name the assets it harms.")
        categories = text_list_problem(item.get("stride"), f"{label} stride", problems)
        if not categories or any(value not in STRIDE for value in categories):
            problems.append(f"{label}: stride must list at least one of {', '.join(STRIDE)}.")
        if not check.references(item.get("components"), check.components, "component", label):
            problems.append(f"{label}: name the components it affects.")
        check.references(item.get("flows"), check.flows, "flow", label)
        depends = check.references(item.get("depends_on"), check.unknowns, "unknown", label)
        if item.get("impact") not in SEVERITIES:
            problems.append(f"{label}: impact must be one of {', '.join(SEVERITIES)}.")
        if item.get("likelihood") not in LIKELIHOODS:
            problems.append(f"{label}: likelihood must be one of {', '.join(LIKELIHOODS)}.")
        if item.get("status") not in THREAT_STATUS:
            problems.append(f"{label}: status must be one of {', '.join(THREAT_STATUS)}.")
        evidence = check.evidence_list(item.get("evidence"), label)
        if not evidence and not depends:
            problems.append(f"{label}: it rests on nothing. Give evidence, or name the unknown it depends on in depends_on.")
        statuses = []
        for index, mitigation in enumerate(text_list_problem(item.get("mitigations"), f"{label} mitigations", problems), 1):
            statuses.append(check_mitigation(mitigation, f"{label} mitigation {index}", check))
        if item.get("status") == "mitigated" and not any(value in ("running", "in-code") for value in statuses):
            problems.append(f"{label}: mitigated needs a mitigation seen running or in code. One that's only documented isn't verified.")
        if item.get("status") != "mitigated":
            check.text(item.get("recommendation"), f"{label} recommendation")
            if item.get("response") not in RESPONSES:
                problems.append(f"{label}: response must be one of {', '.join(RESPONSES)}. Accepting a risk is the signer's decision.")
        if "policy_route" in item:
            if not has_policy:
                problems.append(f"{label}: policy_route doesn't apply, because no policy guidance was found.")
            check.text(item["policy_route"], f"{label} policy_route")
        if "claimed_acceptance" in item:
            accepted = item["claimed_acceptance"]
            if keys_problem(accepted, {"evidence", "note"}, {"evidence", "note"}, f"{label} claimed_acceptance", problems):
                check.text(accepted.get("note"), f"{label} claimed_acceptance note")
                check.evidence(accepted.get("evidence"), f"{label} claimed_acceptance evidence")


def check_mitigation(item: Any, label: str, check: Checker) -> str | None:
    problems = check.problems
    if not keys_problem(item, MITIGATION_KEYS, {"control", "status"}, label, problems):
        return None
    check.text(item.get("control"), f"{label} control")
    status = item.get("status")
    if status not in MITIGATION_STATUS:
        problems.append(f"{label}: status must be one of {', '.join(MITIGATION_STATUS)}.")
        return None
    evidence = check.evidence_list(item.get("evidence"), label, required=status in ("running", "in-code", "documented"))
    kinds = {check.sources.get(entry.get("source"), {}).get("kind") for entry in evidence if isinstance(entry, dict)}
    if status == "running" and "live" not in kinds:
        problems.append(f"{label}: running needs evidence from a live source. Code or a document doesn't show what's running.")
    if status == "in-code" and "repo" not in kinds and "other" not in kinds:
        problems.append(f"{label}: in-code needs evidence from a repository.")
    if status == "not-found":
        looked = text_list_problem(item.get("looked_in"), f"{label} looked_in", problems)
        if not looked:
            problems.append(f"{label}: not-found must say where you looked, in looked_in.")
        for value in looked:
            check.source_used(value, f"{label} looked_in")
    if status == "could-not-check":
        check.text(item.get("note"), f"{label} note")
    return status


def check_llm(value: Any, check: Checker) -> None:
    problems = check.problems
    if not isinstance(value, dict) or not isinstance(value.get("has_ai"), bool):
        problems.append("llm_questions must be an object with has_ai set to true or false.")
        return
    allowed = {"has_ai", "why", "additional", *LLM_KEYS}
    keys_problem(value, allowed, {"has_ai"}, "llm_questions", problems)
    if value["has_ai"]:
        for key in LLM_KEYS:
            answer = value.get(key)
            label = f"llm_questions {key}"
            if not keys_problem(answer, {"answer", "evidence", "determined"}, {"answer"}, label, problems):
                continue
            check.text(answer.get("answer"), f"{label} answer")
            check.evidence_list(answer.get("evidence"), label, required=answer.get("determined") is not False)
    else:
        check.text(value.get("why"), "llm_questions why")
        for key in LLM_KEYS:
            if key in value:
                problems.append(f"llm_questions: {key} doesn't apply when has_ai is false.")
    for index, item in enumerate(text_list_problem(value.get("additional", []), "llm_questions additional", problems), 1):
        label = f"llm_questions additional {index}"
        if keys_problem(item, {"question", "answer", "evidence"}, {"question", "answer"}, label, problems):
            check.text(item.get("question"), f"{label} question")
            check.text(item.get("answer"), f"{label} answer")
            check.evidence_list(item.get("evidence"), label)


def check_conflicts(data: dict[str, Any], check: Checker) -> None:
    problems = check.problems
    for index, item in enumerate(data["conflicts"], 1):
        label = f"conflict {index}"
        if not keys_problem(item, CONFLICT_KEYS, CONFLICT_KEYS - {"threats"}, label, problems):
            continue
        for field in ("about", "believed", "why_it_matters"):
            check.text(item.get(field), f"{label} {field}")
        sides = text_list_problem(item.get("sides"), f"{label} sides", problems)
        if len(sides) < 2:
            problems.append(f"{label}: a conflict needs at least two sides.")
        for number, side in enumerate(sides, 1):
            if keys_problem(side, SIDE_KEYS, SIDE_KEYS - {"evidence"}, f"{label} side {number}", problems):
                check.source_used(side.get("source"), f"{label} side {number}")
                check.text(side.get("says"), f"{label} side {number} says")
                if "evidence" in side:
                    check.evidence(side["evidence"], f"{label} side {number} evidence")
        check.references(item.get("threats"), check.threats, "threat", label)


def unknown_dependents(key: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Threats that would change if this unknown turned out differently."""
    components = {item["id"] for item in data["components"] if item.get("unknown") == key}
    flows = {item["id"] for item in data["flows"] if item.get("unknown") == key}
    return [threat for threat in data["threats"]
            if key in (threat.get("depends_on") or []) or components & set(threat.get("components") or [])
            or flows & set(threat.get("flows") or [])]


def check_unknowns(data: dict[str, Any], check: Checker) -> None:
    problems = check.problems
    for key, item in check.unknowns.items():
        label = f"unknown {key}"
        if not keys_problem(item, UNKNOWN_KEYS, {"id", "question", "assumed", "who_can_answer", "status"}, label, problems):
            continue
        for field in ("question", "assumed", "who_can_answer"):
            check.text(item.get(field), f"{label} {field}")
        if item.get("status") not in UNKNOWN_STATUS:
            problems.append(f"{label}: status must be one of {', '.join(UNKNOWN_STATUS)}.")
        if item.get("status") == "answered":
            check.text(item.get("answer"), f"{label} answer")
        elif "answer" in item:
            problems.append(f"{label}: an open unknown has no answer yet.")
        linked = any(entry.get("unknown") == key for entry in [*data["components"], *data["flows"], *data["assets"]])
        if not linked and not unknown_dependents(key, data) and not item.get("affects"):
            problems.append(f"{label} changes nothing in this model. Name what depends on it, say what it affects, or drop it.")


def check_steering(data: dict[str, Any], check: Checker, manifest: dict[str, Any]) -> None:
    problems = check.problems
    known = {lead["id"]: lead for entry in manifest["repos"].values() for lead in entry["leads"]}
    used: list[str] = []
    for index, item in enumerate(data["steering"], 1):
        label = f"steering {index}"
        if not keys_problem(item, STEERING_KEYS, STEERING_KEYS - {"leads"}, label, problems):
            continue
        check.evidence(item.get("evidence"), f"{label} evidence")
        check.text(item.get("effect"), f"{label} effect")
        check.text(item.get("handled"), f"{label} handled")
        for value in text_list_problem(item.get("leads", []), f"{label} leads", problems):
            used.append(str(value))
            evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            if str(value) in known and known[str(value)]["file"] != original_path(str(evidence.get("file"))):
                problems.append(f"{label}: lead {value} is in {known[str(value)]['file']}, not the file this cites.")
    for index, entry in enumerate(data["dismissed_leads"], 1):
        label = f"dismissed_leads {index}"
        if keys_problem(entry, {"leads", "reason"}, {"leads", "reason"}, label, problems):
            check.text(entry.get("reason"), f"{label} reason")
            used.extend(str(value) for value in text_list_problem(entry.get("leads"), f"{label} leads", problems))
    for value in sorted(set(used) - set(known)):
        problems.append(f"{value} isn't a lead from this run.")
    for value in sorted({item for item in used if used.count(item) > 1}):
        problems.append(f"lead {value} is used more than once. Each belongs in exactly one place.")
    for value in sorted(set(known) - set(used)):
        problems.append(f"lead {value} isn't accounted for. Use it or dismiss it with a reason.")


def check_stride(data: dict[str, Any], check: Checker) -> None:
    problems = check.problems
    coverage = data["stride_coverage"]
    if not keys_problem(coverage, set(STRIDE), set(STRIDE), "stride_coverage", problems):
        return
    listed = {value for threat in check.threats.values() if isinstance(threat.get("stride"), list) for value in threat["stride"] if isinstance(value, str)}
    for name in STRIDE:
        item = coverage.get(name)
        label = f"stride_coverage {name}"
        if not keys_problem(item, {"result", "note"}, {"result", "note"}, label, problems):
            continue
        check.text(item.get("note"), f"{label} note")
        result = item.get("result")
        if result not in STRIDE_RESULTS:
            problems.append(f"{label}: result must be one of {', '.join(STRIDE_RESULTS)}.")
        elif (result == "threats-listed") != (name in listed):
            problems.append(f"{label}: result says {result}, but {'a threat lists' if name in listed else 'no threat lists'} this category.")


# ----------------------------------------------------------------------------------------- report


def open_counts(threats: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for threat in threats:
        if threat["status"] != "mitigated":
            counts[severity_of(threat)] += 1  # type: ignore[index]
    return counts


def natural(value: str) -> list[Any]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value)]


def ranked_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(threats, key=lambda item: (item["status"] == "mitigated", RANK[severity_of(item)], THREAT_STATUS.index(item["status"]), natural(item["id"])))  # type: ignore[index]


def indented(lines: list[str]) -> list[str]:
    return [f"  {line}" if line else line for line in lines]


def unchecked_tag(item: dict[str, Any], source: dict[str, Any]) -> str:
    """Scope and access gives each source's date, so a date here means this evidence differs from it."""
    if item.get("observed") and item["observed"] != source.get("observed"):
        return f"unchecked, seen {item['observed']}"
    return "unchecked"


def evidence_lines(item: dict[str, Any], sources: dict[str, dict[str, Any]]) -> list[str]:
    """One line where the evidence fits on one. The label says whether the helper could check it."""
    source = sources[item["source"]]
    quote = item.get("quote") or ""
    if source["kind"] == "repo":
        where = code(f"{source['repo']}:{original_path(item['file'])}:{item['line']}")
        if item.get("credential") and not quote:
            return [f"- {where} (checked): a credential, value withheld"]
        tag = "checked"
    else:
        where = f"{inline(source['name'])}, {code(item['locator'])}"
        tag = unchecked_tag(item, source)
    if not quote:
        return [f"- {where} ({tag})"]
    if "\n" in quote.strip() or len(quote) > MAX_INLINE_QUOTE_CHARS:
        return [f"- {where} ({tag})", "", *indented(fenced(quote))]
    return [f"- {where} ({tag}): {code(quote.strip())}"]


def evidence_place(item: dict[str, Any], sources: dict[str, dict[str, Any]], named: bool = True) -> str:
    """Where a claim's evidence is, for sections that restate it in words. The quote stays in threat-model.json."""
    source = sources[item["source"]]
    if source["kind"] == "repo":
        return f"{code(source['repo'] + ':' + original_path(item['file']) + ':' + str(item['line']))} (checked)"
    name = f"{inline(source['name'])}, " if named else ""
    return f"{name}{code(item['locator'])} ({unchecked_tag(item, source)})"


def basis_note(item: dict[str, Any], sources: dict[str, dict[str, Any]], unknown_label: dict[str, str]) -> str:
    parts = [item["basis"]]
    cited = [inline(sources[value]["name"]) for value in item.get("sources", [])]
    if cited:
        parts.append(", ".join(cited))
    if item.get("reasoning"):
        parts.append(inline(item["reasoning"]))
    if item.get("unknown"):
        parts.append(unknown_label[item["unknown"]])
    return "; ".join(parts)


def repo_described(name: str, entry: dict[str, Any]) -> str:
    if entry.get("head"):
        return f"{code(name)} at commit {code(entry['head']['commit'])}"
    return f"{code(name)}, files on disk"


# Fields holding ids or copied text. Everything else is the agent's prose.
NOT_PROSE = {"id", "from", "to", "zone", "sources", "components", "flows", "assets", "where", "depends_on", "threats", "unknown",
             "leads", "looked_in", "flow", "quote", "file", "locator", "line", "observed", "stride", "status", "type", "basis",
             "likelihood", "impact", "response", "decision", "kind", "repo", "policy_route", "references"}


def prose_values(value: Any, key: str, source_ids: set[str]) -> Iterator[str]:
    if isinstance(value, str):
        if key not in NOT_PROSE and not (key == "source" and value in source_ids):
            yield value
    elif isinstance(value, list):
        for item in value:
            yield from prose_values(item, key, source_ids)
    elif isinstance(value, dict):
        for name, item in value.items():
            yield from prose_values(item, name, source_ids)


def check_id_mentions(data: dict[str, Any], problems: list[str]) -> None:
    """The report renumbers threats and unknowns, so a mention it can't resolve would point the reader at the wrong one."""
    known = {item["id"] for key in ("threats", "unknowns") for item in data[key] if isinstance(item, dict) and isinstance(item.get("id"), str)}
    letters = {value[0] for value in known if ID_IN_PROSE.fullmatch(value)}
    if not letters:
        return
    prefix = "[" + "".join(sorted(letters)) + "]"
    mention = re.compile(rf"(?<![\w./:-]){prefix}\d+(?![\w/-])(?!\.\w)")
    span = re.compile(rf"(?<![\w./:-]){prefix}\d+\s*(?:-|\u2013|\u2014)\s*(?:{prefix})?\d+\b")
    source_ids = {item["id"] for item in data["sources"] if isinstance(item, dict) and isinstance(item.get("id"), str)}
    for text in prose_values(data, "", source_ids):
        for found in span.finditer(text):
            problems.append(f"\"{found.group(0)}\" is a range, and the report renumbers these ids. Write each id out.")
        for found in mention.finditer(text):
            if found.group(0) not in known:
                problems.append(f"\"{found.group(0)}\" appears in text but no threat or unknown has that id: {text[:80]}")


def report_model(data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    """Rank threats and unknowns, then make the prose cite what the reader will see, because the agent writes T1 before ranks exist."""
    threat_label = threat_labels(ranked_threats(data["threats"]))

    def unknown_key(item: dict[str, Any]) -> tuple[Any, ...]:
        worst = min((RANK[severity_of(threat)] for threat in unknown_dependents(item["id"], data)), default=len(SEVERITIES))  # type: ignore[index]
        return (item["status"] != "open", worst, natural(item["id"]))
    unknown_label = {item["id"]: f"U-{number:03d}" for number, item in enumerate(sorted(data["unknowns"], key=unknown_key), 1)}
    names = {**{item["id"]: item["name"] for item in data["components"]}, **{item["id"]: item["name"] for item in data["assets"]},
             **unknown_label, **threat_label}
    names = {key: value for key, value in names.items() if ID_IN_PROSE.fullmatch(key)}
    if not names:
        return data, threat_label, unknown_label
    pattern = re.compile(r"(?<![\w./:-])(" + "|".join(re.escape(key) for key in sorted(names, key=len, reverse=True)) + r")(?![\w/-])(?!\.\w)")
    source_ids = {item["id"] for item in data["sources"]}

    def rewrite(value: Any, key: str = "") -> Any:
        if isinstance(value, str):
            if key in NOT_PROSE or (key == "source" and value in source_ids):
                return value
            return pattern.sub(lambda match: names[match.group(1)], value)
        if isinstance(value, list):
            return [rewrite(item, key) for item in value]
        if isinstance(value, dict):
            # metadata keys are labels the diagram also shows, and every other key is part of the contract
            return {name: rewrite(item, name) for name, item in value.items()}
        return value
    return rewrite(data), threat_label, unknown_label


def threat_statement(item: dict[str, Any], assets: dict[str, dict[str, Any]], show: Any = inline) -> str:
    """The threat grammar: a source, with prerequisites, can act, which leads to an impact on named assets."""
    prerequisites = f" with {show(item['prerequisites'])}" if item.get("prerequisites") else ""
    harmed = ", ".join(show(assets[value]["name"]) for value in item["assets"])
    return (f"{show(item['source'])}{prerequisites} can {show(item['action'])}, which leads to "
            f"{show(item['consequence'])}, negatively impacting {harmed}.")


def build_report(data: dict[str, Any], manifest: dict[str, Any], diagram: str) -> str:
    data, threat_label, unknown_label = report_model(data)
    sources = {item["id"]: item for item in data["sources"]}
    components = {item["id"]: item for item in data["components"]}
    flows = {item["id"]: item for item in data["flows"]}
    assets = {item["id"]: item for item in data["assets"]}
    threats = ranked_threats(data["threats"])
    # Open questions first, then by the worst threat that hangs on each.
    unknowns = sorted(data["unknowns"], key=lambda item: natural(unknown_label[item["id"]]))
    counts = open_counts(threats)
    mitigated = sum(1 for item in threats if item["status"] == "mitigated")
    repos = manifest["repos"]
    live = [item for item in sources.values() if item["kind"] == "live" and item["status"] == "used"]

    lines = [f"# Threat model: {inline(data['target'])}", "", "| | |", "| --- | --- |"]
    lines.append(f"| Modeled | {STAGE_LABEL[data['intake']['stage']]} |")
    lines.append(f"| Started from | {inline(data['intake']['started_from'])} |")
    lines.append(f"| Gaps | {GAPS_LABEL[data['intake']['gaps']]} |")
    for name, entry in sorted(repos.items()):
        lines.append(f"| Repository | {repo_described(name, entry)}, snapshot SHA-256 {code(entry['snapshot_sha256'])} |")
    if any(entry["inside_target"] for entry in repos.values()):
        lines.append("| Session | Inside a repository, at the request of the operator |")
    lines.append(f"| Rendered | {datetime.date.today().isoformat()} |")
    lines.append("| Status | **Unsigned.** A person has to review this before anyone relies on it. |")
    lines.append("| Handling | **Sensitive.** It maps how to attack the system. Share it like a penetration test report. |")

    serious = counts["critical"] + counts["high"]
    position = (f"{serious} open critical or high threat(s)." if serious else
                "No open critical or high threats in what was examined. That says nothing about anything under Not checked.")
    tally = ", ".join(f"{counts[name]} {name}" for name in SEVERITIES)
    lines += ["", "## Summary", "", f"**Position:** {position}", "", f"**Open threats:** {tally}. **Mitigated:** {mitigated}.", "",
              inline(data["summary"]), ""]
    top = [item for item in threats if item["status"] != "mitigated"][:MAX_TOP_RISKS]
    lines += ["**Top risks:**", ""]
    lines += [f"{number}. {threat_label[item['id']]} [{severity_of(item).upper()}] {inline(item['title'])}" for number, item in enumerate(top, 1)] or ["None open."]  # type: ignore[union-attr]
    claims = [*data["components"], *data["flows"], *data["assets"]]
    basis_counts = ", ".join(f"{sum(1 for item in claims if item['basis'] == name)} {name}" for name in BASES)
    open_unknowns = sum(1 for item in unknowns if item["status"] == "open")
    lines += ["", f"**How this model is known:** {basis_counts}. {open_unknowns} open question(s)."]

    lines += ["", "## Scope and access", "", inline(data["system"]["what_it_does"]), "",
              "| Source | Kind | Status | What was read, or why not | Observed |", "| --- | --- | --- | --- | --- |"]
    for item in data["sources"]:
        detail = " ".join(inline(item[key]) for key in ("read", "note") if item.get(key)) or "Nothing."
        when = "See above" if item["kind"] == "repo" and item["status"] == "used" else (item.get("observed") or "")
        lines.append(f"| {inline(item['name'])} | {item['kind']} | {SOURCE_STATUS_LABEL[item['status']]} | {detail} | {when} |")
    if not live:
        lines += ["", "**No live system was examined.** Everything here describes code or documents, not what is deployed."]
    if data["confirmations"]:
        lines += ["", "**Asked before acting:**", "", "| Action | Why it was risky | Decision |", "| --- | --- | --- |"]
        lines += [f"| {inline(item['action'])} | {inline(item['why_risky'])} | {item['decision'].capitalize()} |" for item in data["confirmations"]]

    lines += ["", "## Architecture", "", "```mermaid", diagram.rstrip("\n"), "```", "",
              "| Component | Type | Zone | How it's known |", "| --- | --- | --- | --- |"]
    zones = {item["id"]: item for item in data["zones"]}
    for item in data["components"]:
        lines.append(f"| {inline(item['name'])} | {item['type']} | {inline(zones[item['zone']]['name'])} | {basis_note(item, sources, unknown_label)} |")

    def crosses(flow: dict[str, Any]) -> bool:
        return components[flow["from"]]["zone"] != components[flow["to"]]["zone"]
    crossing = [item for item in data["flows"] if crosses(item)]
    flow_label = {item["id"]: f"F-{number:02d}" for number, item in enumerate(crossing, 1)}
    lines += ["", "**Flows crossing a trust boundary:**", ""]
    if crossing:
        lines += ["| | Flow | Carries | Channel | Guarantees | How it's known |", "| --- | --- | --- | --- | --- | --- |"]
        for item in crossing:
            lines.append(f"| {flow_label[item['id']]} | {inline(components[item['from']]['name'])} to {inline(components[item['to']]['name'])} | {inline(item.get('label') or 'Not stated')} "
                         f"| {inline(item.get('channel') or 'Not stated')} | {inline(item.get('guarantees') or 'None stated')} | {basis_note(item, sources, unknown_label)} |")
    else:
        lines.append("None.")

    lines += ["", "## Assets, actors, and trust boundaries", "", "**Worth protecting:** " + inline(data["system"]["worth_protecting"]), "",
              "| Asset | Why it matters | Objectives | Where | How it's known |", "| --- | --- | --- | --- | --- |"]
    for item in data["assets"]:
        where = ", ".join(inline(components[value]["name"]) for value in item.get("where", [])) or "Not placed"
        objectives = "".join(name[0].upper() for name in OBJECTIVES if name in item["objectives"])
        lines.append(f"| {inline(item['name'])} | {inline(item['why'])} | {objectives} | {where} | {basis_note(item, sources, unknown_label)} |")
    lines += ["", "| Actor | Starts with | Doesn't have |", "| --- | --- | --- |"]
    lines += [f"| {inline(item['name'])} | {inline(item['can'])} | {inline(item['cannot'])} |" for item in data["actors"]]
    lines += ["", "| Trust zone | Trust | What separates it |", "| --- | --- | --- |"]
    lines += [f"| {inline(item['name'])} | {item['trust_level']} | {inline(item['trust'])} |" for item in data["zones"]]

    lines += ["", "## Threats", "", "| Rating | What it means here |", "| --- | --- |"]
    lines += [f"| {name} | {inline(data['calibration'][name])} |" for name in SEVERITIES]
    lines.append("")
    if threats:
        lines += ["| Id | Threat | Rating | Status | Response | Decision |", "| --- | --- | --- | --- | --- | --- |"]
        for item in threats:
            response = item["response"].capitalize() if item.get("response") else "None needed"
            lines.append(f"| {threat_label[item['id']]} | {inline(item['title'])} | {severity_of(item)} | {THREAT_STATUS_LABEL[item['status']]} | {response} | |")
        lines += ["", "Decision is for the signer: mitigate, eliminate, transfer, or accept. Evidence marked checked was verified against a snapshot. "
                  "Evidence marked unchecked was recorded by the agent, with where to find it, on the date under Scope and access.", ""]
        for item in threats:
            lines += threat_lines(item, threat_label[item["id"]], sources, components, flow_label, assets, unknown_label)
        lines.pop()
    else:
        lines.append("None in what was examined. Read this with Coverage and Not checked.")

    if any("policyrelay" in entry for entry in repos.values()):
        routed = sum(1 for item in threats if item.get("policy_route"))
        indexes = ", ".join(f"{code(name)}: {code(entry['policyrelay']['index'])}" for name, entry in sorted(repos.items()) if "policyrelay" in entry)
        lines += ["", "## Policy guidance", "", f"Read as required guidance from {indexes}. {routed} threat(s) cite a policy route."]

    lines += ["", "## LLM questions", ""]
    llm = data["llm_questions"]
    if llm["has_ai"]:
        for key in LLM_KEYS:
            answer = llm[key]
            lines += [f"**{LLM_LABEL[key]}** ({LLM_REFERENCE[key]})", "", inline(answer["answer"]), ""]
            if answer.get("determined") is False:
                lines += ["This couldn't be determined from what was reachable.", ""]
            if answer.get("evidence"):
                lines += ["Evidence: " + "; ".join(evidence_place(entry, sources) for entry in answer["evidence"]), ""]
        lines.pop()
    else:
        lines.append(f"This system has no AI: {inline(llm['why'])}")
    for item in llm.get("additional", []):
        lines += ["", f"**{inline(item['question'])}**", "", inline(item["answer"])]
        if item.get("evidence"):
            lines += ["", "Evidence: " + "; ".join(evidence_place(entry, sources) for entry in item["evidence"])]

    lines += ["", "## Conflicts between sources", ""]
    if data["conflicts"]:
        for number, item in enumerate(data["conflicts"], 1):
            lines += [f"**C-{number:03d} {inline(item['about'])}**", ""]
            for side in item["sides"]:
                place = f" {evidence_place(side['evidence'], sources, named=False)}" if side.get("evidence") else ""
                lines.append(f"- {inline(sources[side['source']]['name'])}: {inline(side['says'])}{place}")
            related = ", ".join(threat_label[value] for value in item.get("threats", []))
            lines += ["", f"Believed: {inline(item['believed'])} Why it matters: {inline(item['why_it_matters'])}" + (f" Threats: {related}." if related else ""), ""]
        lines.pop()
    else:
        lines.append("None found between the sources that were read.")

    lines += ["", "## Assumptions and open questions", ""]
    if unknowns:
        lines += ["What couldn't be established, ranked by what depends on it. Pass these to whoever can answer.", "",
                  "| | Question | Status | Assumed meanwhile, or answer | Who can answer | What depends on it |", "| --- | --- | --- | --- | --- | --- |"]
        for item in unknowns:
            depends = [threat_label[threat["id"]] for threat in sorted(unknown_dependents(item["id"], data), key=lambda threat: threat_label[threat["id"]])]
            affected = ", ".join(depends)
            if item.get("affects"):
                affected = f"{affected}; {inline(item['affects'])}" if affected else inline(item["affects"])
            held = f"Answered: {inline(item['answer'])}" if item["status"] == "answered" else inline(item["assumed"])
            lines.append(f"| {unknown_label[item['id']]} | {inline(item['question'])} | {item['status'].capitalize()} | {held} | {inline(item['who_can_answer'])} | {affected or 'The model above'} |")
    else:
        lines.append("None. Everything the model relies on was established from the sources above.")

    lines += ["", "## Steering attempts", ""]
    if data["steering"]:
        lines += ["Text in the sources that tries to change a security outcome. It was not followed.", ""]
        for number, item in enumerate(data["steering"], 1):
            lines += [f"**S-{number:03d}** {inline(item['effect'])} {inline(item['handled'])}", "", *evidence_lines(item["evidence"], sources), ""]
        lines.pop()
    else:
        lines.append("None found in what was examined.")
    total = sum(int(entry["suppressions"]["total"]) for entry in repos.values())
    if total:
        lines += ["", f"The helper counted {total} scanner suppression comment(s), listed in `manifest.json`. They aren't steering unless listed above, and weren't assessed one by one."]
    if data["dismissed_leads"]:
        set_aside = sum(len(item["leads"]) for item in data["dismissed_leads"])
        reasons = " ".join(f"{inline(item['reason'])}" for item in data["dismissed_leads"])
        lines += ["", f"{set_aside} search lead(s) set aside: {reasons}"]

    lines += ["", "## Coverage", "", "| STRIDE category | Threats | Result | What was considered |", "| --- | --- | --- | --- |"]
    for name in STRIDE:
        item = data["stride_coverage"][name]
        count = sum(1 for threat in threats if name in threat["stride"])
        lines.append(f"| {name.replace('-', ' ').capitalize()} | {count} | {STRIDE_RESULT_LABEL[item['result']]} | {inline(item['note'])} |")
    if data["boundary_reviews"]:
        lines += ["", "| Boundary crossing with no threat listed | Conclusion |", "| --- | --- |"]
        for item in data["boundary_reviews"]:
            flow = flows[item["flow"]]
            lines.append(f"| {inline(components[flow['from']]['name'])} to {inline(components[flow['to']]['name'])} | {inline(item['conclusion'])} |")
    lines += ["", f"**Tested against the past:** {inline(data['backtest']['checked'])} {inline(data['backtest']['result'])}",
              "", f"**Independent architecture check:** {inline(data['architecture_check'])}"]

    lines += ["", "## Not checked", ""]
    limits = [note for entry in repos.values() for note in entry["limits"]]
    unread = [item["name"] for item in data["sources"] if item["status"] in ("not-reachable", "declined")]
    if unread:
        limits.append(f"Sources not read, with reasons under Scope and access: {', '.join(unread)}.")
    for item in data["components"]:
        if item.get("not_assessed"):
            limits.append(f"Component not assessed, {item['name']}: {item['not_assessed']}")
    unchecked = [f"{threat_label[threat['id']]} {mitigation['control']}" for threat in threats for mitigation in threat["mitigations"] if mitigation["status"] == "could-not-check"]
    if unchecked:
        limits.append(f"Controls that couldn't be checked, with reasons on each threat: {'; '.join(unchecked)}.")
    for name in STRIDE:
        if data["stride_coverage"][name]["result"] == "not-assessed":
            limits.append(f"STRIDE category not assessed, {name}: {data['stride_coverage'][name]['note']}")
    if llm["has_ai"]:
        limits += [f"Not determined: {LLM_LABEL[key]}" for key in LLM_KEYS if llm[key].get("determined") is False]
    limits += data["not_checked"]
    lines += [f"- {inline(item)}" for item in dict.fromkeys(limits)] or ["Nothing was recorded as unchecked."]
    lines += ["", "## Sign-off", "", "| | |", "| --- | --- |", "| Reviewer | |", "| Date | |", "| Decision | |", ""]
    return "\n".join(lines)


def threat_labels(threats: list[dict[str, Any]]) -> dict[str, str]:
    return {item["id"]: f"T-{number:03d}" for number, item in enumerate(threats, 1)}


def threat_lines(
    item: dict[str, Any], number: str, sources: dict[str, dict[str, Any]], components: dict[str, dict[str, Any]],
    flow_label: dict[str, str], assets: dict[str, dict[str, Any]], unknown_label: dict[str, str],
) -> list[str]:
    severity = severity_of(item)
    assert severity
    lines = [f"### {number} [{severity.upper()}] {inline(item['title'])}", "", threat_statement(item, assets), ""]
    facts = [f"**STRIDE:** {', '.join(value.replace('-', ' ') for value in item['stride'])}",
             f"**Affects:** {', '.join(inline(components[value]['name']) for value in item['components'])}"]
    crossed = [flow_label[value] for value in item.get("flows", []) if value in flow_label]
    if crossed:
        facts.append(f"**Crosses:** {', '.join(crossed)}")
    if item.get("depends_on"):
        facts.append(f"**Depends on:** {', '.join(unknown_label[value] for value in item['depends_on'])}")
    if item.get("references"):
        facts.append(f"**Maps to:** {', '.join(inline(value) for value in item['references'])}")
    if item.get("policy_route"):
        facts.append(f"**Policy route:** {code(item['policy_route'])}")
    lines += [" | ".join(facts), "",
              f"**Rating:** {item['likelihood']} likelihood, {item['impact']} impact. {inline(item['rating_reason'])}", ""]
    if item.get("evidence"):
        lines += ["**Evidence:**", ""]
        for entry in item["evidence"]:
            lines += evidence_lines(entry, sources)
        lines.append("")
    lines += ["**Controls:**", ""]
    if item["mitigations"]:
        for mitigation in item["mitigations"]:
            detail = f" {inline(mitigation['note'])}" if mitigation.get("note") else ""
            if mitigation.get("looked_in"):
                detail += " Looked in: " + ", ".join(inline(sources[value]["name"]) for value in mitigation["looked_in"]) + "."
            lines.append(f"- {MITIGATION_LABEL[mitigation['status']]}: {inline(mitigation['control'])}.{detail}")
            if mitigation.get("evidence"):
                lines.append("  - Evidence: " + "; ".join(evidence_place(entry, sources) for entry in mitigation["evidence"]))
    else:
        lines.append("None identified.")
    lines.append("")
    if item.get("claimed_acceptance"):
        accepted = item["claimed_acceptance"]
        lines += [f"**A source says this was accepted:** {inline(accepted['note'])} This doesn't change the rating.", "",
                  *evidence_lines(accepted["evidence"], sources), ""]
    if item.get("recommendation"):
        response = f"{item['response'].capitalize()}. " if item.get("response") else ""
        lines += [f"**Response:** {response}{inline(item['recommendation'])}", ""]
    if item.get("detection"):
        lines += [f"**Detection:** {inline(item['detection'])}", ""]
    return lines


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "system"


def build_otm(data: dict[str, Any]) -> dict[str, Any]:
    """The model as Open Threat Model JSON. Scores are fixed bands, because the format requires numbers."""
    data, label, _unknowns = report_model(data)
    threats = ranked_threats(data["threats"])
    mitigations: list[dict[str, Any]] = []
    instances: dict[str, list[dict[str, Any]]] = {}
    for threat in threats:
        applied = []
        for index, mitigation in enumerate(threat["mitigations"], 1):
            identifier = f"{label[threat['id']]}-M{index}"
            status = mitigation["status"]
            mitigations.append({"id": identifier, "name": mitigation["control"], "description": mitigation.get("note"),
                                "riskReduction": OTM_REDUCTION[status], "attributes": {"status": status}})
            applied.append({"mitigation": identifier, "state": "implemented" if status in ("running", "in-code") else "required"})
        instances[threat["id"]] = [{"threat": label[threat["id"]], "state": "mitigated" if threat["status"] == "mitigated" else "exposed", "mitigations": applied}]
    assets = {item["id"]: item for item in data["assets"]}

    def linked(key: str, identifier: str) -> list[dict[str, Any]]:
        return [instance for threat in threats if identifier in (threat.get(key) or []) for instance in instances[threat["id"]]]

    components = []
    for item in data["components"]:
        held = [asset["id"] for asset in data["assets"] if item["id"] in (asset.get("where") or [])]
        entry: dict[str, Any] = {"id": item["id"], "name": item["name"], "type": item["type"], "parent": {"trustZone": item["zone"]},
                                 "tags": [item["basis"]], "threats": linked("components", item["id"]),
                                 "attributes": {str(key): str(value) for key, value in (item.get("metadata") or {}).items()}}
        if held:
            entry["assets"] = {"stored": held} if item["type"] == "data" else {"processed": held}
        components.append(entry)
    return {
        "otmVersion": OTM_VERSION,
        "project": {"name": data["target"], "id": slug(data["target"]), "description": data["system"]["what_it_does"],
                    "attributes": {"status": "unsigned", "generatedBy": "threat-model"}},
        "assets": [{"id": item["id"], "name": item["name"], "description": item["why"],
                    "risk": {name: 100 if name in item["objectives"] else 0 for name in OBJECTIVES}} for item in data["assets"]],
        "trustZones": [{"id": item["id"], "name": item["name"], "description": item["trust"],
                        "risk": {"trustRating": OTM_TRUST[item["trust_level"]]}} for item in data["zones"]],
        "components": components,
        "dataflows": [{"id": item["id"], "name": item.get("label") or f"{item['from']} to {item['to']}", "source": item["from"], "destination": item["to"],
                       "tags": [item["basis"]], "threats": linked("flows", item["id"])} for item in data["flows"]],
        "threats": [{"id": label[item["id"]], "name": item["title"],
                     "description": threat_statement(item, assets, mask),
                     "categories": list(item["stride"]),
                     "cwes": [value for value in item.get("references", []) if re.fullmatch(r"CWE-\d+", value)],
                     "risk": {"likelihood": OTM_SCORE[item["likelihood"]], "likelihoodComment": item["rating_reason"], "impact": OTM_SCORE[item["impact"]]},
                     "attributes": {"status": item["status"], "rating": severity_of(item)}} for item in threats],
        "mitigations": mitigations,
    }


if __name__ == "__main__":
    sys.exit(main())
