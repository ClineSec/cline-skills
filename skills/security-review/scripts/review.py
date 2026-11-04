#!/usr/bin/env python3
"""Read-only helper for the security-review skill. Standard library only.

    review.py prepare --target PATH --out DIR [--head REF] [--base REF] [--working-tree]
                      [--sarif FILE]... [--allow-inside-target] [--restart]
    review.py status --out DIR
    review.py render --out DIR

`prepare` copies what is being reviewed into a snapshot outside the target and lists leads. `render`
checks the findings against that snapshot and writes a report whose shape never changes, along with the same findings
in SARIF.

Nothing here executes anything found in the target, and nothing writes to it. A repository's own Git
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
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
MAX_LEADS = 300
MAX_SUPPRESSIONS_LISTED = 2000
MAX_HITS = 2000
MAX_EVIDENCE_CHARS = 4000
MIN_EVIDENCE_CHARS = 6
MAX_TREE_ENTRIES = 300000
MAX_TREE_DEPTH = 256
MAX_DISK_COMPARE = 50000
OBJECT_BATCH = 100
GIT_TIMEOUT_SECONDS = 300
EVIDENCE_EXTRA_LINES = 2
MAX_PATHS_SHOWN = 5

# A report nobody finishes protects nothing. These limit each field, never how many entries there are, so nothing has to
# be left out to fit. The reviewers' fuller reasoning stays in units/.
WORD_LIMITS = {
    "summary": 100, "system": 40, "title": 20, "requires": 30, "why": 60, "recommendation": 50, "severity_reason": 25,
    "effect": 50, "examined_anyway": 75, "suppressions_reviewed": 60, "area": 20, "conclusion": 40, "note": 30,
    "reason": 30, "not_checked": 30, "not_reviewed": 30,
}

OUTPUT_NAMES = {"manifest.json", "snapshot", "changes.diff", "files.txt", "surface.json", "units", "findings.json", "report.md", "report-lower-severity.md", "report.sarif"}
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

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
CONFIDENCE = ("confirmed", "probable")
ORIGINS = ("judgment", "scanner-hit", "scanner-territory")
ORIGIN_LABEL = {
    "judgment": "Reviewer judgment",
    "scanner-hit": "Scanner result, confirmed by the reviewer",
    "scanner-territory": "Reviewer, though a scanner should catch this class",
}
RESULTS = ("issue-found", "no-issue-found", "inconclusive")
RESULT_LABEL = {"issue-found": "Issue found", "no-issue-found": "No issue found", "inconclusive": "Inconclusive"}
TERRITORY_STATUS = ("results-reviewed", "not-run")
TERRITORY_LABEL = {"results-reviewed": "Results reviewed", "not-run": "Not run"}
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
TOP_KEYS = {"system", "summary", "steering", "findings", "examined", "scanner_territory", "dismissed_leads",
            "dismissed_hits", "dismissed_candidates", "not_checked"}
SYSTEM_KEYS = {"what_it_does", "worth_protecting", "who_could_abuse"}
STEERING_KEYS = {"file", "line", "evidence", "effect", "examined_anyway", "leads"}
FINDING_KEYS = {"title", "severity", "confidence", "cwe", "file", "line", "evidence", "requires", "why", "recommendation",
                "origin", "scanner_hits", "severity_reason", "policy_route", "credential", "candidates", "also_at"}
CWE_ID = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
EXAMINED_KEYS = {"area", "looked_at", "result", "conclusion", "beyond_examples"}
UNIT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
SURFACE_KEYS = {"units", "changes_out_of_scope"}
UNIT_KEYS = {"id", "what", "entry_points", "affected_by", "changes", "not_reviewed"}
UNIT_RESULT_KEYS = {"id", "looked_at", "result", "conclusion", "candidates"}
CANDIDATE_REQUIRED = {"title", "severity", "file", "line", "why"}
CANDIDATE_KEYS = CANDIDATE_REQUIRED | {"evidence", "confidence", "cwe", "requires", "recommendation"}
TERRITORY_KEYS = {"class", "status", "note"}
DETAILED_IN_REPORT = ("critical", "high", "medium")
LOWER_SEVERITY_FILE = "report-lower-severity.md"
SEVERITY_MEANING = {
    "critical": "An outsider or ordinary user reaches system-wide compromise, or data or money at scale, with no further human step",
    "high": "Serious compromise of data, money, accounts, or integrity, reachable with ordinary access or one realistic condition",
    "medium": "The same outcomes, but limited in reach or needing an uncommon condition, or a privileged actor exceeding their role",
    "low": "Weakens a safeguard or widens access without reaching those outcomes by itself",
    "info": "Worth a reviewer's attention, with no demonstrated risk",
}
SARIF_LEVEL_OF = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def write_exact(path: Path, text: str, errors: str = "strict") -> None:
    """Write UTF-8 with no newline translation: on Windows, text mode would corrupt Git's files and shift line numbers."""
    path.write_bytes(text.encode("utf-8", errors))


class Refused(Exception):
    """The helper will not proceed, and the reason is for the operator."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and render a security review.")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--target", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--head", help="Commit, tag, or branch to review. Default: the target's HEAD.")
    prepare.add_argument("--base", help="Earlier commit, tag, or branch to compare against.")
    prepare.add_argument("--working-tree", action="store_true", help="Review files on disk instead of a commit.")
    prepare.add_argument("--sarif", action="append", default=[], help="SARIF results to account for. Repeatable.")
    prepare.add_argument("--allow-inside-target", action="store_true")
    prepare.add_argument("--restart", action="store_true", help="Discard an earlier review's results in --out and start over.")
    status = commands.add_parser("status", help="Say which attack-surface units still need a reviewer.")
    status.add_argument("--out", required=True)
    render = commands.add_parser("render")
    render.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        return {"prepare": cmd_prepare, "status": cmd_status, "render": cmd_render}[args.command](args)
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError) as error:
        print(f"Refused: couldn't complete this because of a file problem: {error}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------------------- prepare


def cmd_prepare(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser()
    if not target.is_absolute():
        raise Refused("--target must be an absolute path.")
    target = target.resolve()
    if not target.is_dir():
        raise Refused(f"{target} is not a directory.")
    out = Path(args.out).expanduser().resolve()
    inside = is_within(Path.cwd().resolve(), target)
    if inside and not args.allow_inside_target:
        raise Refused(
            "this session is inside the target, so it may already have loaded the target's instructions and "
            "fired its hooks. Start a new session in a directory outside the target."
        )
    if is_within(out, target):
        raise Refused("--out must be outside the target, so nothing is written to it.")
    if is_within(target, out):
        raise Refused("--out must not contain the target.")
    if args.working_tree and (args.head or args.base):
        raise Refused("--working-tree can't be combined with --head or --base, which name commits.")
    hits = load_sarif(args.sarif, target)
    prepare_output(out, args.restart)
    limits = ["Nothing was executed, so behavior that only appears at runtime was not observed."]

    gitdir, repository_note = find_repository(target, bool(args.head))
    if repository_note and not args.working_tree:
        if args.head or args.base:
            raise Refused(f"{repository_note} Use --working-tree.")
        limits.append(repository_note + " So the files on disk were reviewed, not a commit.")
    use_git = bool(gitdir) and not args.working_tree
    if use_git and not shutil.which("git"):
        if args.head or args.base:
            raise Refused("Git isn't installed, so --head and --base can't be read. Install Git or use --working-tree.")
        use_git = False
        limits.append("Git isn't installed here, so the files on disk were reviewed, not a commit.")
    if (args.head or args.base) and not gitdir:
        raise Refused(f"{target} isn't a Git repository, so --head and --base don't apply.")

    snapshot = out / "snapshot"
    snapshot.mkdir()
    writer = SnapshotWriter(snapshot)
    head_info: dict[str, str] | None = None
    base_info: dict[str, str] | None = None
    changed: list[dict[str, str]] = []
    disk_differences: list[str] = []
    if use_git:
        assert gitdir is not None
        with tempfile.TemporaryDirectory(prefix="security-review-") as scratch:
            view = build_clean_view(gitdir, Path(scratch) / "view.git")
            head_info = resolve_commit(view, args.head or "HEAD")
            tree, links = copy_revision(view, head_info["commit"], writer)
            if args.base:
                base_info = resolve_commit(view, args.base)
                verify_revision(view, base_info["commit"], set(tree.values()))
                changed = write_diff(view, base_info["commit"], head_info["commit"], out / "changes.diff")
        limits.append("Uncommitted changes were not reviewed. Only the named commit was.")
        if gitdir != target:
            disk_differences, note = compare_disk(target, tree, links)
            if disk_differences:
                limits.append(
                    f"{len(disk_differences)} path(s) on disk are not in the reviewed commit or differ from it, and were "
                    f"not reviewed: {preview(disk_differences)}"
                )
            if note:
                limits.append(note)
    else:
        copy_working_tree(target, writer)
        limits.append("The files on disk were reviewed, so no commit identifies exactly what was examined.")

    policy = find_policy(snapshot, target, writer, limits)
    limits.extend(writer.limits())
    leads, truncated, suppressions = find_leads(snapshot, writer)
    if truncated:
        limits.append(
            f"The steering sweep stopped listing leads at {MAX_LEADS}; {truncated} more were not listed, "
            "so read past the list."
        )
    if suppressions["total"] > len(suppressions["listed"]):
        limits.append(
            f"Only the first {len(suppressions['listed'])} of {suppressions['total']} scanner suppression comments "
            "are listed in manifest.json. All of them are counted."
        )
    write_exact(out / "files.txt", "".join(f"{path}\n" for path in sorted(writer.written)), errors="replace")
    digest = digest_snapshot(snapshot)
    make_read_only(snapshot)

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": "security-review",
        "target": str(target),
        "target_name": target.name,
        "mode": "revision" if use_git else "working-tree",
        "head": head_info,
        "base": base_info,
        "inside_target": inside,
        "snapshot_sha256": digest,
        "files": writer.file_count,
        "bytes": writer.total_bytes,
        "changed_files": changed,
        "agent_files": writer.agent_files(),
        "leads": leads,
        "suppressions": suppressions,
        "scanner_hits": hits,
        "sarif_supplied": bool(args.sarif),
        "skipped": {reason: sorted(paths) for reason, paths in sorted(writer.skipped.items())},
        "disk_differences": disk_differences,
        "limits": limits,
    }
    if policy:
        manifest["policyrelay"] = policy
    write_json(out / "manifest.json", manifest)
    described = head_info["commit"][:12] if head_info else "files on disk"
    print(f"Prepared {target.name} at {described}: {writer.file_count} files, {len(leads)} leads, {len(hits)} scanner hits.")
    print(f"Read the snapshot, not the target: {snapshot}")
    return 0


def is_within(path: Path, root: Path) -> bool:
    """Compare by file identity, because paths that differ in case can name one directory."""
    for candidate in (path, *path.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def prepare_output(out: Path, restart: bool = False) -> None:
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise Refused(f"{out} must be a real directory.")
    out.mkdir(parents=True, exist_ok=True)
    unexpected = [child.name for child in out.iterdir() if child.name not in OUTPUT_NAMES]
    if unexpected:
        raise Refused(f"{out} holds files this helper didn't write ({unexpected[0]}). Choose an empty directory.")
    results = out / "units"
    if not restart and results.is_dir() and not results.is_symlink() and any(results.glob("*.json")):
        raise Refused(
            f"{out} holds reviewers' results from an earlier session. To continue that review, skip prepare and run status. "
            "To discard them and start over, pass --restart, or choose another directory."
        )
    for name in OUTPUT_NAMES:
        path = out / name
        if path.is_dir() and not path.is_symlink():
            make_writable(path)
            shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()


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
            f"Not reviewed, {reason}: {preview(sorted(paths))}"
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
    write_exact(view / "objects" / "info" / "alternates", f"{objects}\n")
    config = "[core]\n\trepositoryformatversion = 1\n\tbare = true\n" if sha256 else "[core]\n\trepositoryformatversion = 0\n\tbare = true\n"
    if sha256:
        config += "[extensions]\n\tobjectformat = sha256\n"
    write_exact(view / "config", config)
    head = read_small(gitdir / "HEAD").strip()
    if not re.fullmatch(r"ref: refs/[^\s]+|[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise Refused("the target's Git HEAD isn't readable.")
    write_exact(view / "HEAD", head + "\n")
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
        write_exact(view / "packed-refs", "\n".join(kept) + "\n")
    shallow = read_small(common / "shallow")
    if shallow:
        write_exact(view / "shallow", shallow)
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
                write_exact(destination / child.name, value + "\n")


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


def verify_revision(view: Path, commit: str, already_verified: set[str]) -> None:
    """Check the comparison commit too, because a forged base can hide a change as easily as a forged head."""
    names = sorted({name for _path, mode, name in walk_commit(view, commit) if mode not in ("120000", "160000")} - already_verified)
    sizes = object_sizes(view, names)
    small = [name for name in names if name in sizes and sizes[name][1] <= MAX_FILE_BYTES]
    for _ in read_objects(view, small):
        pass


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


def write_diff(view: Path, base: str, head: str, destination: Path) -> list[dict[str, str]]:
    # --text stops .gitattributes from turning a change into "Binary files differ", and no rename
    # detection means a moved-and-edited file shows every line.
    shared = ("--no-ext-diff", "--no-textconv", "--no-renames", "--text", "--no-color", "--full-index")
    destination.write_bytes(run_git(view, "diff", *shared, base, head))
    names = run_git(view, "diff", "--no-renames", "--name-status", "-z", base, head).split(b"\0")
    changed = []
    for index in range(0, len(names) - 1, 2):
        changed.append({"status": names[index].decode(), "path": names[index + 1].decode("utf-8", "surrogateescape")})
    return changed


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


def load_sarif(paths: Iterable[str], target: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for name in paths:
        path = Path(name).expanduser()
        try:
            document = json.loads(path.read_text(encoding="utf-8-sig"))
            runs = document["runs"]
            if not isinstance(runs, list):
                raise TypeError
        except (OSError, ValueError, KeyError, TypeError):
            raise Refused(f"{name} isn't a readable SARIF file. Export SARIF from the scanner.") from None
        try:
            for run in runs:
                driver = str(((run.get("tool") or {}).get("driver") or {}).get("name") or "scanner")
                rules = {rule.get("id"): rule for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
                         if isinstance(rule, dict)}
                for result in run.get("results") or []:
                    if len(hits) >= MAX_HITS:
                        raise Refused(f"more than {MAX_HITS} scanner results. Triage them separately, then supply a filtered file.")
                    hits.append(sarif_hit(len(hits) + 1, driver, rules, result, target))
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            raise Refused(f"{name} isn't valid SARIF: a result is malformed.") from None
    return hits


def sarif_hit(number: int, tool: str, rules: dict[Any, Any], result: dict[str, Any], target: Path) -> dict[str, Any]:
    location = ((result.get("locations") or [{}])[0] or {}).get("physicalLocation") or {}
    uri = str((location.get("artifactLocation") or {}).get("uri") or "")
    uri = urllib.parse.unquote(re.sub(r"^file://", "", uri))
    prefix = target.as_posix() + "/"
    if uri.startswith(prefix):
        uri = uri[len(prefix):]
    if uri.startswith("./"):
        uri = uri[2:]
    rule_id = str(result.get("ruleId") or "")
    level = str(result.get("level") or (rules.get(rule_id, {}).get("defaultConfiguration") or {}).get("level") or "warning")
    severity = SARIF_LEVEL.get(level, "medium")
    properties = {**(rules.get(rule_id, {}).get("properties") or {}), **(result.get("properties") or {})}
    try:
        score = float(properties.get("security-severity"))
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    except (TypeError, ValueError):
        pass
    return {
        "id": f"H{number:03d}",
        "tool": display_line(tool),
        "rule": display_line(rule_id),
        "severity": severity,
        "file": display_line(uri),
        "line": int((location.get("region") or {}).get("startLine") or 0),
        "message": display_line(str((result.get("message") or {}).get("text") or "")),
        "suppressed": bool(result.get("suppressions")),
    }


def write_json(path: Path, value: Any) -> None:
    write_exact(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")


# ----------------------------------------------------------------------------------------- render


def read_manifest(out: Path) -> dict[str, Any]:
    manifest_path = out / "manifest.json"
    if not manifest_path.is_file():
        raise Refused(f"{out} has no manifest.json. Run prepare first.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["snapshot_sha256"], manifest["leads"], manifest["scanner_hits"], manifest["limits"]
    except (ValueError, KeyError, TypeError):
        raise Refused("manifest.json isn't what prepare wrote. Run prepare again.") from None
    return manifest


def looked_at_problems(looked_at: Any, snapshot: Path, label: str, problems: list[str]) -> None:
    if not isinstance(looked_at, list) or not looked_at:
        problems.append(f"{label}: looked_at must list the files or directories behind this conclusion.")
        return
    for cited in looked_at:
        path = snapshot / data_path(original_path(str(cited))) if safe_relative(str(cited).rstrip("/")) else None
        if str(cited) not in (".", "./") and (path is None or not path.exists()):
            problems.append(f"{label}: {cited!r} isn't in the snapshot.")


def read_surface(out: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Load the work list and what its reviewers wrote. Done means nothing here is pending."""
    state: dict[str, Any] = {"units": [], "results": {}, "pending": [], "out_of_scope": [], "problems": []}
    problems = state["problems"]
    path = out / "surface.json"
    if not path.is_file():
        problems.append("surface.json is missing. Map the attack surface first, as SKILL.md describes.")
        return state
    try:
        surface = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as error:
        problems.append(f"surface.json isn't valid JSON: {error}")
        return state
    if not keys_problem(surface, SURFACE_KEYS, {"units"}, "surface.json", problems):
        return state
    units = surface["units"]
    incremental = bool(manifest.get("base"))
    changed = {item["path"] for item in manifest.get("changed_files", [])}
    if not isinstance(units, list):
        problems.append("surface.json: units must be a list.")
        return state
    if not units and not (incremental and not changed):
        problems.append("surface.json lists no units. A review has to say what it worked through.")
    seen: set[str] = set()
    covered: set[str] = set()
    for index, unit in enumerate(units, 1):
        label = f"unit {index}"
        required = {"id", "what", "entry_points"} | ({"affected_by", "changes"} if incremental else set())
        if not keys_problem(unit, UNIT_KEYS, required, label, problems):
            continue
        name = str(unit.get("id"))
        if not UNIT_ID.match(name):
            problems.append(f"{label}: id {name!r} must use lowercase letters, digits, and hyphens.")
            continue
        if name in seen:
            problems.append(f"{label}: id {name} is used more than once.")
            continue
        seen.add(name)
        label = f"unit {name}"
        text_problem(unit.get("what"), f"{label} what", problems)
        if not isinstance(unit.get("entry_points"), list) or not unit.get("entry_points"):
            problems.append(f"{label}: entry_points must say where this is reached from.")
        if incremental:
            text_problem(unit.get("affected_by"), f"{label} affected_by", problems)
            if not isinstance(unit.get("changes"), list):
                problems.append(f"{label}: changes must list the changed files that put it in scope.")
            else:
                covered.update(str(value) for value in unit["changes"])
        state["units"].append(unit)
        if "not_reviewed" in unit:
            text_problem(unit["not_reviewed"], f"{label} not_reviewed", problems)
            words_problem(unit["not_reviewed"], "not_reviewed", f"{label} not_reviewed", problems)
            continue
        result_path = out / "units" / f"{name}.json"
        if not result_path.is_file():
            state["pending"].append(name)
            continue
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (ValueError, RecursionError) as error:
            problems.append(f"{label}: units/{name}.json isn't valid JSON: {error}")
            continue
        if not keys_problem(result, UNIT_RESULT_KEYS, UNIT_RESULT_KEYS, f"units/{name}.json", problems):
            continue
        if result.get("id") != name:
            problems.append(f"units/{name}.json says its id is {result.get('id')!r}.")
        if result.get("result") not in RESULTS:
            problems.append(f"units/{name}.json: result must be one of {', '.join(RESULTS)}.")
        text_problem(result.get("conclusion"), f"units/{name}.json conclusion", problems)
        looked_at_problems(result.get("looked_at"), out / "snapshot", f"units/{name}.json", problems)
        candidates = result.get("candidates")
        if not isinstance(candidates, list):
            problems.append(f"units/{name}.json: candidates must be a list.")
            continue
        for number, candidate in enumerate(candidates, 1):
            if keys_problem(candidate, CANDIDATE_KEYS, CANDIDATE_REQUIRED, f"{name}#{number}", problems):
                text_problem(candidate.get("title"), f"{name}#{number} title", problems)
                text_problem(candidate.get("why"), f"{name}#{number} why", problems)
        state["results"][name] = result
    leftover = surface.get("changes_out_of_scope", [])
    if not isinstance(leftover, list):
        problems.append("surface.json: changes_out_of_scope must be a list.")
        leftover = []
    for index, entry in enumerate(leftover, 1):
        label = f"changes_out_of_scope {index}"
        if keys_problem(entry, {"path", "reason"}, {"path", "reason"}, label, problems):
            text_problem(entry.get("reason"), f"{label} reason", problems)
            words_problem(entry.get("reason"), "reason", f"{label} reason", problems)
            covered.add(str(entry.get("path")))
            state["out_of_scope"].append(entry)
    if incremental:
        for value in sorted(covered - changed):
            problems.append(f"surface.json names {value!r} as changed, but it isn't in this comparison.")
        for value in sorted(changed - covered):
            problems.append(f"Changed file {value} isn't accounted for. Add it to a unit's changes, or to changes_out_of_scope with a reason.")
    return state


def candidate_ids(state: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for name, result in state["results"].items():
        for number, candidate in enumerate(result.get("candidates") or [], 1):
            items.append({"id": f"{name}#{number}", "title": candidate.get("title", "") if isinstance(candidate, dict) else ""})
    return items


def files_read(out: Path, state: dict[str, Any]) -> tuple[int, int]:
    listing = out / "files.txt"
    names = [original_path(line) for line in listing.read_text(encoding="utf-8", errors="replace").splitlines()] if listing.is_file() else []
    cited = {original_path(str(path).rstrip("/")) if str(path) not in (".", "./") else "." for result in state["results"].values() for path in result.get("looked_at") or []}
    if "." in cited:
        return len(names), len(names)
    read = sum(1 for name in names if name in cited or any(name.startswith(prefix + "/") for prefix in cited))
    return read, len(names)


def cmd_status(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    state = read_surface(out, read_manifest(out))
    skipped = sum(1 for unit in state["units"] if "not_reviewed" in unit)
    print(f"{len(state['results'])} of {len(state['units'])} units reviewed, {skipped} marked not reviewed, {len(state['pending'])} pending.")
    if state["pending"]:
        print("Pending: " + ", ".join(state["pending"]))
    for problem in state["problems"]:
        print(f"- {problem}")
    return 1 if state["pending"] or state["problems"] else 0


def cmd_render(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    manifest = read_manifest(out)
    findings_path = out / "findings.json"
    if not findings_path.is_file():
        raise Refused(f"{out} has no findings.json. Write it first, using references/report-contract.md.")
    if digest_snapshot(out / "snapshot") != manifest["snapshot_sha256"]:
        raise Refused("the snapshot changed after prepare, so its evidence can't be trusted. Run prepare again with --restart.")
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as error:
        print(f"findings.json isn't valid JSON: {error}", file=sys.stderr)
        return 1
    try:
        surface = read_surface(out, manifest)
        problems = list(surface["problems"])
        if surface["pending"]:
            problems.append(f"{len(surface['pending'])} unit(s) still have no reviewer's result: {', '.join(surface['pending'])}. "
                            "Review them, or mark each not_reviewed with the reason.")
        problems += validate(data, manifest, out / "snapshot", surface)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        problems = [f"a field has the wrong type ({error}). Compare it with references/report-contract.md."]
    if problems:
        print(f"findings.json has {len(problems)} problem(s). Correct them against the evidence:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    report = out / "report.md"
    write_exact(report, build_report(data, manifest, surface, files_read(out, surface)), errors="replace")
    write_json(out / "report.sarif", build_sarif(data, manifest))
    lower = out / LOWER_SEVERITY_FILE
    lower_text = build_lower_severity(data, manifest)
    if lower_text:
        write_exact(lower, lower_text, errors="replace")
    elif lower.exists():
        lower.unlink()
    counts = severity_counts(data["findings"])
    print("Wrote", report, "and report.sarif |", ", ".join(f"{counts[name]} {name}" for name in SEVERITIES))
    return 0


def text_problem(value: Any, label: str, problems: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{label} must be non-empty text.")


def words_problem(value: Any, field: str, label: str, problems: list[str]) -> None:
    limit = WORD_LIMITS[field]
    if isinstance(value, str) and len(value.split()) > limit:
        problems.append(f"{label} is {len(value.split())} words; keep it to {limit}. Cut repetition, not facts. "
                        "If it holds two separate things, make it two entries.")


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


def evidence_problem(snapshot: Path, item: dict[str, Any], label: str, problems: list[str]) -> None:
    cited, line, evidence = item.get("file"), item.get("line"), item.get("evidence")
    path = snapshot_file(snapshot, cited)
    if path is None:
        problems.append(f"{label}: {cited!r} isn't a file in the snapshot. Paths are as in the repository.")
        return
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        problems.append(f"{label}: line must be a positive whole number.")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    if line > len(lines):
        problems.append(f"{label}: {cited} has only {len(lines)} lines, not {line}.")
        return
    if item.get("credential") is True and evidence == "":
        return
    if not isinstance(evidence, str) or not evidence.strip():
        problems.append(f"{label}: quote the evidence. Only a credential may be left empty, with credential set to true.")
        return
    if len(evidence) > MAX_EVIDENCE_CHARS:
        problems.append(f"{label}: evidence is too long. Quote only the lines that prove the point.")
        return
    wanted = normalized(evidence)
    if len(wanted) < MIN_EVIDENCE_CHARS:
        problems.append(f"{label}: evidence is too short to prove anything. Quote the whole line.")
        return
    span = sum(1 for part in evidence.split("\n") if part.strip()) + EVIDENCE_EXTRA_LINES
    if wanted not in normalized("\n".join(lines[line - 1:line - 1 + span])):
        problems.append(f"{label}: the evidence doesn't appear at or just after {cited}:{line}. Quote the file.")


def also_at_problems(item: dict[str, Any], snapshot: Path, label: str, problems: list[str]) -> None:
    also_at = item.get("also_at", [])
    if not isinstance(also_at, list):
        problems.append(f"{label}: also_at must be a list of path:line locations.")
        return
    for location in also_at:
        cited, _, number = str(location).rpartition(":")
        path = snapshot_file(snapshot, cited)
        if path is None or not number.isdigit() or int(number) < 1:
            problems.append(f"{label}: also_at {location!r} must be path:line, with a file in the snapshot.")
        elif int(number) > len(path.read_text(encoding="utf-8", errors="replace").split("\n")):
            problems.append(f"{label}: also_at {location!r} is past the end of that file.")


def ids_accounted(
    data: dict[str, Any], manifest_items: list[dict[str, Any]], used: list[str], dismissal_key: str, id_key: str,
    noun: str, problems: list[str],
) -> None:
    known = {item["id"] for item in manifest_items}
    dismissals = data.get(dismissal_key)
    seen = list(used)
    if not isinstance(dismissals, list):
        problems.append(f"{dismissal_key} must be a list.")
        dismissals = []
    for index, entry in enumerate(dismissals, 1):
        label = f"{dismissal_key} {index}"
        if keys_problem(entry, {id_key, "reason"}, {id_key, "reason"}, label, problems):
            text_problem(entry.get("reason"), f"{label} reason", problems)
            words_problem(entry.get("reason"), "reason", f"{label} reason", problems)
            ids = entry.get(id_key)
            if isinstance(ids, list):
                seen.extend(str(value) for value in ids)
            else:
                problems.append(f"{label}: {id_key} must be a list.")
    for value in sorted(set(seen) - known):
        problems.append(f"{value} isn't a {noun} from this review.")
    for value in sorted({item for item in seen if seen.count(item) > 1}):
        problems.append(f"{noun} {value} is used more than once. Each belongs in exactly one place.")
    for value in sorted(known - set(seen)):
        problems.append(f"{noun} {value} isn't accounted for. Use it or dismiss it with a reason.")


def validate(data: Any, manifest: dict[str, Any], snapshot: Path, surface: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if not keys_problem(data, TOP_KEYS | {"suppressions_reviewed"}, TOP_KEYS, "findings.json", problems):
        return problems
    if suppression_total(manifest):
        text_problem(data.get("suppressions_reviewed"), "suppressions_reviewed", problems)
        words_problem(data.get("suppressions_reviewed"), "suppressions_reviewed", "suppressions_reviewed", problems)
    elif "suppressions_reviewed" in data:
        problems.append("suppressions_reviewed doesn't apply, because the helper counted no suppression comments.")
    if keys_problem(data["system"], SYSTEM_KEYS, SYSTEM_KEYS, "system", problems):
        for key in sorted(SYSTEM_KEYS):
            text_problem(data["system"].get(key), f"system {key}", problems)
            words_problem(data["system"].get(key), "system", f"system {key}", problems)
    text_problem(data["summary"], "summary", problems)
    words_problem(data["summary"], "summary", "summary", problems)
    for key in ("steering", "findings", "examined", "scanner_territory", "not_checked"):
        if not isinstance(data[key], list):
            problems.append(f"{key} must be a list.")
    if problems:
        return problems

    known_leads = {lead["id"]: lead for lead in manifest["leads"]}
    used_leads: list[str] = []
    for index, item in enumerate(data["steering"], 1):
        label = f"steering {index}"
        if not keys_problem(item, STEERING_KEYS, STEERING_KEYS - {"leads"}, label, problems):
            continue
        evidence_problem(snapshot, item, label, problems)
        text_problem(item.get("effect"), f"{label} effect", problems)
        text_problem(item.get("examined_anyway"), f"{label} examined_anyway", problems)
        words_problem(item.get("effect"), "effect", f"{label} effect", problems)
        words_problem(item.get("examined_anyway"), "examined_anyway", f"{label} examined_anyway", problems)
        cited_leads = item.get("leads") or []
        if not isinstance(cited_leads, list):
            problems.append(f"{label}: leads must be a list.")
            cited_leads = []
        used_leads.extend(str(value) for value in cited_leads)
        for value in cited_leads:
            if str(value) in known_leads and known_leads[str(value)]["file"] != original_path(str(item.get("file"))):
                problems.append(f"{label}: lead {value} is in {known_leads[str(value)]['file']}, not this file.")

    hits = {hit["id"]: hit for hit in manifest["scanner_hits"]}
    used_hits: list[str] = []
    used_candidates: list[str] = []
    for index, item in enumerate(data["findings"], 1):
        label = f"finding {index}"
        if not keys_problem(item, FINDING_KEYS, FINDING_KEYS - {"scanner_hits", "severity_reason", "policy_route", "credential", "candidates", "also_at"}, label, problems):
            continue
        merged = item.get("candidates") or []
        if not isinstance(merged, list):
            problems.append(f"{label}: candidates must be a list.")
        else:
            used_candidates.extend(str(value) for value in merged)
        for key in ("title", "requires", "why", "recommendation"):
            text_problem(item.get(key), f"{label} {key}", problems)
            words_problem(item.get(key), key, f"{label} {key}", problems)
        words_problem(item.get("severity_reason"), "severity_reason", f"{label} severity_reason", problems)
        if not isinstance(item.get("cwe"), str) or not CWE_ID.match(item["cwe"]):
            problems.append(f"{label}: cwe must be the closest CWE, written like CWE-639.")
        if item.get("severity") not in SEVERITIES:
            problems.append(f"{label}: severity must be one of {', '.join(SEVERITIES)}.")
        if item.get("confidence") not in CONFIDENCE:
            problems.append(f"{label}: confidence must be one of {', '.join(CONFIDENCE)}.")
        if item.get("origin") not in ORIGINS:
            problems.append(f"{label}: origin must be one of {', '.join(ORIGINS)}.")
        cited_hits = item.get("scanner_hits") or []
        if not isinstance(cited_hits, list):
            problems.append(f"{label}: scanner_hits must be a list.")
            cited_hits = []
        if bool(cited_hits) != (item.get("origin") == "scanner-hit"):
            problems.append(f"{label}: origin scanner-hit and scanner_hits go together.")
        cited_hits = [str(value) for value in cited_hits]
        used_hits.extend(cited_hits)
        for value in cited_hits:
            if value in hits and hits[value]["file"] != original_path(str(item.get("file"))):
                problems.append(f"{label}: scanner hit {value} is in {hits[value]['file']}, not this file.")
        floors = [RANK[hits[value]["severity"]] for value in cited_hits if value in hits]
        if floors and item.get("severity") in RANK and RANK[item["severity"]] > min(floors) and not item.get("severity_reason"):
            problems.append(f"{label}: rated below its scanner result. Explain why in severity_reason.")
        if "policy_route" in item and "policyrelay" not in manifest:
            problems.append(f"{label}: policy_route doesn't apply, because no policy guidance was found.")
        if "policy_route" in item:
            text_problem(item["policy_route"], f"{label} policy_route", problems)
        evidence_problem(snapshot, item, label, problems)
        also_at_problems(item, snapshot, label, problems)

    if not data["examined"]:
        problems.append("examined is empty. Say what was looked at, and what it showed.")
    for index, item in enumerate(data["examined"], 1):
        label = f"examined {index}"
        if not keys_problem(item, EXAMINED_KEYS, EXAMINED_KEYS - {"beyond_examples"}, label, problems):
            continue
        text_problem(item.get("area"), f"{label} area", problems)
        text_problem(item.get("conclusion"), f"{label} conclusion", problems)
        words_problem(item.get("area"), "area", f"{label} area", problems)
        words_problem(item.get("conclusion"), "conclusion", f"{label} conclusion", problems)
        if item.get("result") not in RESULTS:
            problems.append(f"{label}: result must be one of {', '.join(RESULTS)}.")
        looked_at_problems(item.get("looked_at"), snapshot, label, problems)
    if not data["scanner_territory"]:
        problems.append("scanner_territory is empty. Name what deterministic tools should cover here, and whether they ran.")
    for index, item in enumerate(data["scanner_territory"], 1):
        label = f"scanner_territory {index}"
        if keys_problem(item, TERRITORY_KEYS, TERRITORY_KEYS, label, problems):
            text_problem(item.get("class"), f"{label} class", problems)
            text_problem(item.get("note"), f"{label} note", problems)
            words_problem(item.get("note"), "note", f"{label} note", problems)
            if item.get("status") not in TERRITORY_STATUS:
                problems.append(f"{label}: status must be one of {', '.join(TERRITORY_STATUS)}.")
    for index, item in enumerate(data["not_checked"], 1):
        text_problem(item, f"not_checked {index}", problems)
        words_problem(item, "not_checked", f"not_checked {index}", problems)
    ids_accounted(data, manifest["leads"], used_leads, "dismissed_leads", "leads", "lead", problems)
    ids_accounted(data, manifest["scanner_hits"], used_hits, "dismissed_hits", "hits", "scanner hit", problems)
    ids_accounted(data, candidate_ids(surface), used_candidates, "dismissed_candidates", "candidates", "candidate", problems)
    return problems


def suppression_total(manifest: dict[str, Any]) -> int:
    return int((manifest.get("suppressions") or {}).get("total", 0))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


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


def described_commit(info: dict[str, str]) -> str:
    named = code(info["ref"])
    if info.get("full_ref") and info["full_ref"] != info["ref"]:
        named += ", " + code(info["full_ref"])
    return f"commit {code(info['commit'])} ({named})"


def ordered_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(data["findings"], key=lambda item: (RANK[item["severity"]], original_path(item["file"]), item["line"], item["title"]))


def set_aside_changes(entries: list[dict[str, Any]]) -> list[str]:
    """One line per reason, so a large release doesn't bury the rest of the list."""
    by_reason: dict[str, list[str]] = {}
    for entry in entries:
        by_reason.setdefault(str(entry["reason"]), []).append(str(entry["path"]))
    lines = []
    for reason, paths in by_reason.items():
        shown = ", ".join(paths[:MAX_PATHS_SHOWN])
        more = f", and {len(paths) - MAX_PATHS_SHOWN} more, all named in surface.json" if len(paths) > MAX_PATHS_SHOWN else ""
        lines.append(f"{len(paths)} changed file(s) set aside ({shown}{more}): {reason}")
    return lines


def build_report(data: dict[str, Any], manifest: dict[str, Any], surface: dict[str, Any], read: tuple[int, int]) -> str:
    """The shape follows the reporting structure in the OWASP Web Security Testing Guide. See references/report-contract.md."""
    findings = ordered_findings(data)
    counts = severity_counts(findings)
    hits = {hit["id"]: hit for hit in manifest["scanner_hits"]}
    head, base = manifest.get("head"), manifest.get("base")
    skipped_units = [unit for unit in surface["units"] if "not_reviewed" in unit]
    limits = list(dict.fromkeys([
        *manifest["limits"],
        *(f"Unit {unit['id']} was listed but not reviewed: {unit['not_reviewed']}" for unit in skipped_units),
        *set_aside_changes(surface["out_of_scope"]),
        *data["not_checked"],
    ]))

    lines = ["# Security review report", "", "| | |", "| --- | --- |"]
    lines.append(f"| Target | {code(manifest['target_name'])} |")
    lines.append(f"| Reviewed | {described_commit(head) if head else 'Files on disk'} |")
    lines.append(f"| Compared with | {described_commit(base) if base else 'Nothing: the whole snapshot is in scope'} |")
    lines.append(f"| Snapshot SHA-256 | {code(manifest['snapshot_sha256'])} |")
    lines.append(f"| Session | {'Inside the target, at the request of the operator' if manifest['inside_target'] else 'Outside the target'} |")
    lines.append(f"| Scanner results | {str(len(hits)) + ' results supplied' if manifest['sarif_supplied'] else 'None supplied'} |")
    lines.append(f"| Rendered | {datetime.date.today().isoformat()} |")
    lines.append("| Status | **Unsigned.** A person has to review this before anyone relies on it. |")

    serious = counts["critical"] + counts["high"]
    position = (
        f"{serious} critical or high finding(s) to resolve, or accept in writing, before release."
        if serious else
        "No critical or high findings in what was examined. That says nothing about anything under Not checked."
    )
    lines += ["", "## Executive summary", "", f"**Release position:** {position}", "", "| Severity | Count |", "| --- | --- |"]
    lines += [f"| {name} | {counts[name]} |" for name in SEVERITIES]
    lines += ["", inline(data["summary"]), "",
              f"**Coverage:** {len(surface['results'])} of {len(surface['units'])} attack-surface unit(s) reviewed. "
              f"{len(limits)} limit(s) listed under Not checked."]

    system = data["system"]
    lines += ["", "## System under review", "", f"**What it does:** {inline(system['what_it_does'])}", "",
              f"**Worth protecting:** {inline(system['worth_protecting'])}", "",
              f"**Who could abuse it:** {inline(system['who_could_abuse'])}"]

    lines += ["", "## Steering instructions", ""]
    if data["steering"]:
        lines += ["Text in the target that tries to change a security outcome. It was not followed.", ""]
        for number, item in enumerate(sorted(data["steering"], key=lambda entry: (original_path(entry["file"]), entry["line"])), 1):
            lines += [f"### S-{number:03d} {code(original_path(item['file']) + ':' + str(item['line']))}", "", *fenced(item["evidence"]), "",
                      f"**What it tries to do:** {inline(item['effect'])}", "",
                      f"**Examined anyway:** {inline(item['examined_anyway'])}", ""]
        lines.pop()
    else:
        lines.append("None found in what was examined.")
    total = suppression_total(manifest)
    if total:
        per_file = manifest["suppressions"]["files"]
        busiest = sorted(per_file.items(), key=lambda entry: (-entry[1], entry[0]))[:5]
        named = ", ".join(f"{code(path)} ({count})" for path, count in busiest)
        lines += ["", f"**Scanner suppression comments:** {total} in {len(per_file)} file(s), counted by the helper and listed in "
                  f"`manifest.json`. They aren't steering unless listed above. Most are in {named}.", "",
                  f"**What the reviewer did with them:** {inline(data['suppressions_reviewed'])}"]

    lines += ["", "## Findings summary", ""]
    if findings:
        lines += ["| ID | Severity | Finding | CWE | Confidence | Location |", "| --- | --- | --- | --- | --- | --- |"]
        for number, item in enumerate(findings, 1):
            lines.append(f"| F-{number:03d} | {item['severity']} | {inline(item['title'])} | {item['cwe']} | {item['confidence']} | "
                         f"{code(original_path(item['file']) + ':' + str(item['line']))} |")
    else:
        lines.append("None in what was examined. Read this with Not checked and Appendix A.")

    lines += ["", "## Finding details", ""]
    detailed = [(number, item) for number, item in enumerate(findings, 1) if item["severity"] in DETAILED_IN_REPORT]
    for number, item in detailed:
        lines += finding_block(number, item, hits)
    if detailed:
        lines.pop()
    else:
        lines.append("None rated critical, high, or medium.")
    if len(detailed) < len(findings):
        lines += ["", f"The {len(findings) - len(detailed)} finding(s) rated low or info appear only in the table above. "
                  f"Their evidence and recommendations are in `{LOWER_SEVERITY_FILE}`."]

    if "policyrelay" in manifest:
        routed = [item for item in findings if item.get("policy_route")]
        lines += ["", "## Policy guidance", "",
                  f"Read as required guidance from {code(manifest['policyrelay']['index'])}, found in {manifest['policyrelay']['source']}.",
                  f"{len(routed)} finding(s) cite a policy route."]

    lines += ["", "## Not checked", ""]
    lines += [f"- {inline(item)}" for item in limits]
    lines += ["", "## Sign-off", "", "| | |", "| --- | --- |", "| Reviewer | |", "| Date | |", "| Decision | |"]

    scope = ""
    if base:
        scope = (f" The comparison changed {len(manifest.get('changed_files', []))} file(s), and "
                 f"{len(surface['out_of_scope'])} were set aside with a reason, listed under Not checked.")
    lines += ["", "## Appendix A: Coverage", "",
              f"**Attack surface:** {len(surface['units'])} unit(s) listed in `surface.json`: {len(surface['results'])} reviewed, "
              f"{len(skipped_units)} not reviewed.{scope} Reviewers report reading {read[0]} of {read[1]} snapshot files. "
              "`units/` holds each reviewer's result, so depth can be checked.", "",
              "| Examined | Result | Looked at | Conclusion |", "| --- | --- | --- | --- |"]
    for item in data["examined"]:
        beyond = " (pursued beyond the skill's examples)" if item.get("beyond_examples") else ""
        paths = [str(path) for path in item["looked_at"]]
        looked_at = ", ".join(code(original_path(path)) for path in paths[:MAX_PATHS_SHOWN])
        if len(paths) > MAX_PATHS_SHOWN:
            looked_at += f", and {len(paths) - MAX_PATHS_SHOWN} more in `findings.json`"
        lines.append(f"| {inline(item['area'])}{beyond} | {RESULT_LABEL[item['result']]} | {looked_at} | {inline(item['conclusion'])} |")

    lines += ["", "## Appendix B: Severity scale", "",
              "Severity rates what the issue allows in this system, not how alarming its class sounds.", "",
              "| Severity | Meaning |", "| --- | --- |"]
    lines += [f"| {name} | {SEVERITY_MEANING[name]} |" for name in SEVERITIES]

    lines += ["", "## Appendix C: Scanner territory", "",
              "Classes of issue a deterministic tool covers better than a reviewer. This review doesn't replace those tools.",
              "", "| Class | Status | Note |", "| --- | --- | --- |"]
    for item in data["scanner_territory"]:
        lines.append(f"| {inline(item['class'])} | {TERRITORY_LABEL[item['status']]} | {inline(item['note'])} |")

    lines += ["", "## Appendix D: Dismissed leads, scanner hits, and candidates", ""]
    leads = {lead["id"]: lead for lead in manifest["leads"]}
    dismissed = [(entry["leads"], entry["reason"], leads) for entry in data["dismissed_leads"]]
    dismissed += [(entry["hits"], entry["reason"], hits) for entry in data["dismissed_hits"]]
    titles = {item["id"]: item["title"] for item in candidate_ids(surface)}
    rejected = [(entry["candidates"], entry["reason"]) for entry in data["dismissed_candidates"]]
    if dismissed or rejected:
        lines += ["| Dismissed | Reason |", "| --- | --- |"]
        for ids, reason, source in dismissed:
            where = ", ".join(code(f"{source[value]['file']}:{source[value]['line']}") for value in ids)
            lines.append(f"| {where} | {inline(reason)} |")
        for ids, reason in rejected:
            where = "; ".join(f"{code(value)} {inline(titles[value])}" for value in ids)
            lines.append(f"| {where} | {inline(reason)} |")
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def finding_block(number: int, item: dict[str, Any], hits: dict[str, Any]) -> list[str]:
    lines = [f"### F-{number:03d} [{item['severity'].upper()}] {inline(item['title'])}", "",
             f"- **Location:** {code(original_path(item['file']) + ':' + str(item['line']))}"]
    if item.get("also_at"):
        lines.append("- **Also at:** " + ", ".join(code(original_path(str(value))) for value in item["also_at"]))
    lines += [f"- **Weakness:** {item['cwe']}", f"- **Confidence:** {item['confidence']}", f"- **Found by:** {ORIGIN_LABEL[item['origin']]}"]
    if item.get("scanner_hits"):
        described = ", ".join(f"{inline(hits[value]['tool'])} {code(hits[value]['rule'])}" for value in item["scanner_hits"])
        lines.append(f"- **Scanner results:** {described}")
    if item.get("policy_route"):
        lines.append(f"- **Policy route:** {code(item['policy_route'])}")
    if item.get("severity_reason"):
        lines.append(f"- **Severity reason:** {inline(item['severity_reason'])}")
    if item.get("candidates"):
        lines.append("- **Reviewer's reasoning:** " + ", ".join(code(str(value)) for value in item["candidates"]) + " in `units/`")
    lines.append("")
    lines += ["Credential withheld by the reviewer, so the helper couldn't check this location."] \
        if item.get("credential") and item["evidence"] == "" else fenced(item["evidence"])
    lines += ["", f"**What it takes:** {inline(item['requires'])}", "",
              f"**Why it matters:** {inline(item['why'])}", "",
              f"**Recommendation:** {inline(item['recommendation'])}", ""]
    return lines


def build_lower_severity(data: dict[str, Any], manifest: dict[str, Any]) -> str:
    """The rest of the findings, so the report stays readable and nothing is lost. Empty when there are none."""
    hits = {hit["id"]: hit for hit in manifest["scanner_hits"]}
    lower = [(number, item) for number, item in enumerate(ordered_findings(data), 1) if item["severity"] not in DETAILED_IN_REPORT]
    if not lower:
        return ""
    lines = ["# Lower-severity findings", "",
             f"The findings rated low or info in `report.md` for {code(manifest['target_name'])}, with the same numbers. "
             "Unsigned, like the report.", ""]
    for number, item in lower:
        lines += finding_block(number, item, hits)
    return "\n".join(lines)


def build_sarif(data: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """The findings in SARIF 2.1.0, so other tools can read them. Steering and coverage belong to the report."""
    findings = ordered_findings(data)
    results = []
    for number, item in enumerate(findings, 1):
        region: dict[str, Any] = {"startLine": item["line"]}
        if item["evidence"]:
            region["snippet"] = {"text": visible(mask(item["evidence"]))}
        properties = {"id": f"F-{number:03d}", "severity": item["severity"], "confidence": item["confidence"],
                      "origin": item["origin"], "requires": mask(item["requires"]), "recommendation": mask(item["recommendation"])}
        related = []
        for index, location in enumerate(item.get("also_at", []), 1):
            cited, _, line = str(location).rpartition(":")
            related.append({"id": index, "physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(original_path(cited))}, "region": {"startLine": int(line)}}})
        extra = {"relatedLocations": related} if related else {}
        results.append({
            "ruleId": item["cwe"],
            "level": SARIF_LEVEL_OF[item["severity"]],
            "message": {"text": mask(f"{item['title']}: {item['why']}")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(original_path(item["file"]))}, "region": region}}],
            **extra,
            "properties": properties,
        })
    rules = [{"id": cwe, "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html",
              "properties": {"tags": ["security", f"external/cwe/{cwe.lower()}"]}}
             for cwe in sorted({item["cwe"] for item in findings})]
    properties = {"snapshot_sha256": manifest["snapshot_sha256"], "signed": False}
    if manifest.get("head"):
        properties["commit"] = manifest["head"]["commit"]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "security-review", "rules": rules}}, "results": results, "properties": properties}],
    }


if __name__ == "__main__":
    sys.exit(main())
