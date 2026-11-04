#!/usr/bin/env python3
"""Read-only helper for the agent-config-integrity skill. Standard library only.

    integrity.py inventory --target PATH --out DIR [--home] [--allow-inside-target]
    integrity.py scan --out DIR --rules PATH [--scanner NAME]   (only when the operator asks)
    integrity.py render --out DIR

Nothing here executes, sources, or connects to anything found in the target, and nothing writes to
it. Exit codes: 0 success, 1 problems to correct or a failed scan, 2 refused or bad usage.
"""

from __future__ import annotations

import argparse
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
import unicodedata
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA = 1
MAX_FILE_BYTES = 2 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 900
MAX_HIDDEN_PER_FILE = 20
# Findings have to stay readable. Evidence and line references carry the detail.
WORD_LIMITS = {"summary": 75, "why": 60, "recommendation": 45, "severity_reason": 25}
MAX_NOT_CHECKED = 6
MAX_NOT_CHECKED_WORDS = 30
MAX_EVIDENCE_LINES = 12
# The report is what a person signs, so it can't depend on a file that nothing here has checked.
LOCAL_LINK = re.compile(r"\]\((?!https?://)")

# Where agents, IDEs, and MCP clients read configuration from. The rule pack's own path filters are
# added at scan time, so a newer pack does not need a change here.
LOCATIONS: dict[str, tuple[str, ...]] = {
    "instructions": (
        "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", "QWEN.md",
        "CONVENTIONS.md", ".cursorrules", ".windsurfrules", ".clinerules", ".clinerules/**",
        ".cursor/rules/**", ".windsurf/rules/**", ".devin/rules/**", ".roo/rules/**", ".roo/rules-*/**",
        ".kiro/steering/**", ".continue/rules/**", ".github/copilot-instructions.md",
        ".github/instructions/**",
    ),
    "skills-and-commands": (
        "SKILL.md", ".claude/agents/**", ".claude/commands/**", ".gemini/commands/**", ".cursor/commands/**",
        ".qwen/agents/**", ".qwen/commands/**", ".opencode/**", ".kilo/**", ".kilocode/**", ".kilocodemodes",
        "agents/**/*.md", "commands/**/*.md",
    ),
    "hooks-and-plugins": (
        "hooks/*.json", "hooks.json", ".claude/hooks/**", ".cursor/hooks.json", ".codex/hooks.json",
        ".windsurf/hooks.json", ".devin/hooks.json", ".devin/hooks.v1.json", ".github/hooks/*.json",
        ".copilot/hooks/*.json", ".kiro/hooks/*.json", ".cline/hooks/**", ".clinerules/hooks/**",
        ".cline/plugins/**", ".claude-plugin/**", "plugin.json", "monitors/monitors.json",
    ),
    "mcp": (
        ".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json", "managed-mcp.json",
        "claude_desktop_config.json", "cline_mcp_settings.json", "gemini-extension.json",
        ".continue/mcpServers/**", ".kiro/settings/mcp.json",
    ),
    "settings": (
        ".claude/settings.json", ".claude/settings.local.json", ".claude.json", "managed-settings.json",
        ".gemini/settings.json", ".qwen/settings.json", ".codex/config.toml", ".codex/rules/*.rules",
        ".cursor/cli.json", ".cursor/cli-config.json", ".cursor/permissions.json", ".cursor/worktrees.json",
        ".vscode/settings.json", ".vscode/tasks.json", "*.code-workspace", ".zed/settings.json",
        ".config/zed/settings.json", ".continue/**/*.yaml", ".continue/**/*.yml", ".continuerc.json",
        ".aider.conf.yml", ".aider.model.settings.yml", ".crush.json", "crush.json", ".crushrc", "crushrc",
        "opencode.json", "opencode.jsonc", "kilo.json", "kilo.jsonc", ".devin/config.json",
        ".devin/config.local.json", ".github/copilot/settings.json", ".github/copilot/settings.local.json",
        ".copilot/settings.json", ".devcontainer.json", "devcontainer.json", ".devcontainer/devcontainer.json",
        ".devcontainer/*/devcontainer.json", ".config/opencode/**", ".config/kilo/**",
    ),
    "scanner-ignore": (".semgrepignore", ".opengrepignore"),
    # Agents and MCP servers also get launched and deployed from here.
    "automation": (
        ".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", ".circleci/config.yml",
        "azure-pipelines.yml", "bitbucket-pipelines.yml", "Jenkinsfile", "Makefile", "GNUmakefile", "justfile",
        "compose*.yml", "compose*.yaml", "docker-compose*.yml", "docker-compose*.yaml",
    ),
}

# Never walked, because they hold installed copies rather than configuration anyone loads.
EXCLUDED_DIRECTORIES = {".git", "node_modules", ".venv", "venv", ".tox", "__pycache__"}
# User-level directories worth reading for --home. The home directory itself is never walked.
HOME_DIRECTORIES = (
    ".claude", ".cursor", ".codex", ".gemini", ".copilot", ".continue", ".kiro", ".qwen",
    ".config/opencode", ".config/kilo", ".config/zed",
)
HOME_FILES = (".claude.json", ".aider.conf.yml", ".crush.json", ".crushrc", ".mcp.json")
HOME_EXCLUDED = {
    "projects", "sessions", "history", "cache", "logs", "todos", "shell-snapshots", "file-history",
    "paste-cache", "statsig", "telemetry", "tmp", "extensions", "chats", "worktrees",
}
# Ignore files never reach the scanned copy, so a repository can't use them to hide anything.
SCAN_NEVER_COPY = {".semgrepignore", ".opengrepignore", ".gitignore", ".gitattributes"}
# Scanners skip these directory names by default, whatever the ignore files say, so the copy
# renames them. Only directory segments are renamed: `.env` the file keeps its name.
SCANNER_SKIPS = {"build", "dist", "vendor", "test", "tests", ".env", ".npm", ".yarn", ".semgrep", ".semgrep_logs"}

POLICYRELAY_INDEX = "security/PolicyRelay/index.md"
SEVERITIES = ("high", "medium", "low", "info")
CATEGORIES = ("steering", "execution", "autonomy", "reach", "exposure", "other")
CATEGORY_LABELS = {
    "steering": "Steering", "execution": "Execution", "autonomy": "Autonomy", "reach": "Reach",
    "exposure": "Exposure", "other": "Other",
}
SCANNER_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

SECRET_PATTERNS = [
    re.compile(pattern)
    for pattern in (
        r"\bsk-[A-Za-z0-9_-]{12,}",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}",
        r"\bgithub_pat_\w{20,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        r"\bAIza[0-9A-Za-z_-]{20,}",
        r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]*",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    )
]
SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?key|auth[_-]?token|token|secret|password|passwd|authorization)"
    r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?)(?!\$\{|\$[A-Za-z_]|<)([^\s\"',}]{6,})"
)
URL_CREDENTIAL = re.compile(r"(://[^/\s:@]+:)[^/\s@]+(@)")


class Refusal(Exception):
    """A request the helper will not carry out. Exit code 2."""


def glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a gitignore-style glob that may match at any depth, ignoring case."""
    index, out = 0, ""
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out += r"(?:[^/]+/)*"
            index += 3
        elif pattern.startswith("**", index):
            out += r".*"
            index += 2
        elif char == "*":
            out += r"[^/]*"
            index += 1
        elif char == "?":
            out += r"[^/]"
            index += 1
        elif char == "[" and "]" in pattern[index:]:
            end = pattern.index("]", index)
            out += pattern[index : end + 1]
            index = end + 1
        else:
            out += re.escape(char)
            index += 1
    return re.compile(r"(?:^|.*/)" + out + r"$", re.IGNORECASE)


COMPILED_LOCATIONS = [(kind, glob_regex(item)) for kind, items in LOCATIONS.items() for item in items]
CONFIG_ROOT_NAMES = {item.split("/")[0].lower() for items in LOCATIONS.values() for item in items if "/" in item}
CONFIG_ROOT_NAMES.add(".agents")


def location_kind(relative: str) -> str | None:
    # Only the root manifest: a monorepo has hundreds, and a search finds any that launch an agent.
    if relative.lower() == "package.json":
        return "automation"
    for kind, pattern in COMPILED_LOCATIONS:
        if pattern.match(relative):
            return kind
    return None


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def session_position(cwd: Path, target: Path) -> str:
    if is_inside(cwd, target):
        return "inside"
    if is_inside(target, cwd):
        return "parent"
    return "outside"


def read_regular(path: Path) -> bytes | None:
    """Read a regular file without following a symlink, or return None."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        return path.read_bytes()
    except OSError:
        return None


def hidden_characters(text: str) -> list[dict[str, Any]]:
    """Locate invisible format characters, which a reader or an agent's tools may not show."""
    found: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), 1):
        for char in line:
            if unicodedata.category(char) == "Cf" and char != "﻿":
                found.append({"line": number, "codepoint": f"U+{ord(char):04X}"})
                if len(found) >= MAX_HIDDEN_PER_FILE:
                    return found
    return found


def symlink_record(display: str, path: Path, root: Path) -> dict[str, Any]:
    try:
        points_to = os.readlink(path)
    except OSError:
        points_to = ""
    resolved = os.path.normpath(os.path.join(str(path.parent), points_to))
    return {"path": display, "points_to": points_to, "escapes_root": not is_inside(Path(resolved), root)}


def inside_config_directory(relative: str) -> bool:
    return any(part.startswith(".") and part.lower() in CONFIG_ROOT_NAMES for part in relative.split("/")[:-1])


def looks_like_config(relative: str, is_directory: bool, is_link: bool = False) -> bool:
    if location_kind(relative):
        return True
    # A link inside a config directory can bring anything into it, whatever the link is called.
    if is_link and inside_config_directory(relative):
        return True
    if not is_directory:
        return False
    if relative.split("/")[-1].lower() in CONFIG_ROOT_NAMES:
        return True
    return any(location_kind(f"{relative}/{probe}") for probe in ("x.md", "x.json", "x.yml", "settings.json", "config.toml"))


def walk(root: Path, excluded: set[str]) -> Iterator[tuple[str, Path, bool, bool]]:
    """Yield (relative path, path, is_symlink, is_directory) without following any symlink."""
    for current, directories, files in os.walk(root, followlinks=False):
        here = Path(current)
        kept = []
        for name in sorted(directories):
            path = here / name
            if path.is_symlink():
                yield path.relative_to(root).as_posix(), path, True, True
            elif name not in excluded:
                kept.append(name)
        directories[:] = kept
        for name in sorted(files):
            path = here / name
            yield path.relative_to(root).as_posix(), path, path.is_symlink(), False


def home_candidates(home: Path) -> Iterator[tuple[str, Path, bool, bool]]:
    for name in HOME_FILES:
        path = home / name
        if path.is_symlink() or path.is_file():
            yield name, path, path.is_symlink(), False
    for name in HOME_DIRECTORIES:
        base = home / name
        if base.is_symlink():
            # Linked user-level configuration is common, and it is still the user's own: read it.
            try:
                base = base.resolve(strict=True)
            except OSError:
                continue
        if not base.is_dir():
            continue
        for relative, path, is_link, is_directory in walk(base, EXCLUDED_DIRECTORIES | HOME_EXCLUDED):
            yield f"{name}/{relative}", path, is_link, is_directory


def inventory(target: Path | None, home: Path | None) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    excluded_seen: set[str] = set()

    def record(display: str, relative: str, path: Path, is_link: bool, is_directory: bool, root: Path) -> None:
        if not looks_like_config(relative, is_directory, is_link):
            return
        if is_link:
            links.append(symlink_record(display, path, root))
            return
        if is_directory:
            return
        kind = location_kind(relative)
        try:
            info = os.lstat(path)
        except OSError:
            skipped.append({"path": display, "reason": "unreadable"})
            return
        if not stat.S_ISREG(info.st_mode):
            skipped.append({"path": display, "reason": "not a regular file"})
            return
        if info.st_size > MAX_FILE_BYTES:
            skipped.append({"path": display, "reason": f"larger than {MAX_FILE_BYTES} bytes"})
            return
        data = read_regular(path)
        if data is None:
            skipped.append({"path": display, "reason": "unreadable"})
            return
        text = data.decode("utf-8", errors="replace")
        entry: dict[str, Any] = {
            "path": display,
            "kind": kind,
            "size": len(data),
            "lines": len(text.splitlines()),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        hidden = hidden_characters(text)
        if hidden:
            entry["hidden_characters"] = hidden
        files.append(entry)

    if target is not None:
        for relative, path, is_link, is_directory in walk(target, EXCLUDED_DIRECTORIES):
            record(relative, relative, path, is_link, is_directory, target)
        for current, directories, _ in os.walk(target, followlinks=False):
            excluded_seen.update(name for name in directories if name in EXCLUDED_DIRECTORIES)
            directories[:] = [name for name in directories if name not in EXCLUDED_DIRECTORIES]
    if home is not None:
        for relative, path, is_link, is_directory in home_candidates(home):
            record(f"~/{relative}", relative, path, is_link, is_directory, home)

    result: dict[str, Any] = {
        "files": sorted(files, key=lambda item: item["path"]),
        "unfollowed_symlinks": sorted(links, key=lambda item: item["path"]),
        "skipped": sorted(skipped, key=lambda item: item["path"]),
        "excluded_directories": sorted(excluded_seen),
    }
    if target is not None and (target / POLICYRELAY_INDEX).is_file():
        result["policyrelay"] = {"index": POLICYRELAY_INDEX}
    return result


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Refusal(f"{label} not found at {path}; run the earlier step first") from None
    except (OSError, ValueError) as error:
        raise Refusal(f"could not read {label} at {path}: {error}") from None


def command_inventory(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve() if args.target else None
    if target is None and not args.home:
        raise Refusal("name a target with --target, or pass --home")
    if target is not None and not target.is_dir():
        raise Refusal(f"target is not a directory: {target}")
    home = Path.home().resolve() if args.home else None
    cwd = Path.cwd().resolve()
    out = Path(args.out).expanduser().resolve()
    position = session_position(cwd, target) if target is not None else "not-applicable"
    if position == "inside" and not args.allow_inside_target:
        raise Refusal(
            "this session is inside the target, so it may already have loaded the target's instructions "
            "and fired its hooks. Start a new session in a directory outside the target and run this again."
        )
    if target is not None and is_inside(out, target):
        raise Refusal(f"the output directory must be outside the target: {out}")
    out.mkdir(parents=True, exist_ok=True)
    result = inventory(target, home)
    document = {
        "schema": SCHEMA,
        "assessed_at": utc_now(),
        "target": str(target) if target is not None else None,
        "target_name": target.name if target is not None else "user configuration",
        "session_position": position,
        "home": bool(args.home),
        **result,
    }
    write_json(out / "inventory.json", document)
    # Earlier results must not be mistaken for this run's.
    for stale in ("scan.json", "findings.json", "report.md"):
        (out / stale).unlink(missing_ok=True)
    print(f"OK inventory files={len(result['files'])} symlinks={len(result['unfollowed_symlinks'])} "
          f"skipped={len(result['skipped'])} position={position} out={out}")
    if position == "parent":
        print("WARNING session started in a parent of the target; some agents load nested instruction "
              "files on demand, so a sibling or unrelated directory is safer.")
    return 0


def pack_rule_files(rules_dir: Path) -> list[Path]:
    if rules_dir.is_file():
        return [rules_dir]
    return sorted(path for path in rules_dir.rglob("*") if path.suffix in {".yaml", ".yml"} and path.is_file())


def pack_includes(rules_dir: Path) -> tuple[list[str], int]:
    """Read path filters and count rule ids from the operator's pack, without a YAML dependency."""
    includes: set[str] = set()
    rule_count = 0
    for path in pack_rule_files(rules_dir):
        collecting = False
        indent = 0
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        if not any(line.startswith("rules:") for line in lines[:40]):
            continue
        for line in lines:
            stripped = line.strip()
            if re.match(r"-\s+id:\s*\S", stripped) and len(line) - len(line.lstrip()) <= 4:
                rule_count += 1
            if stripped == "include:":
                collecting, indent = True, len(line) - len(line.lstrip())
                continue
            if collecting:
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("- ") and len(line) - len(line.lstrip()) >= indent:
                    includes.add(stripped[2:].strip().strip("\"'"))
                else:
                    collecting = False
    return sorted(includes), rule_count


def pack_commit(pack_root: Path) -> str | None:
    """Read the pack's commit without running Git, or None if it is not a plain checkout."""
    try:
        head = (pack_root / ".git" / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head[:12]
        reference = head[5:]
        loose = pack_root / ".git" / reference
        if loose.is_file():
            return loose.read_text(encoding="utf-8").strip()[:12]
        for line in (pack_root / ".git" / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + reference):
                return line.split(" ")[0][:12]
    except OSError:
        pass
    return None


def resolve_rules(source: str, roots: Iterable[Path]) -> tuple[Path, Path]:
    """Return the rules to scan with and the directory that may hold their Git metadata."""
    given = Path(source).expanduser().resolve()
    for root in roots:
        if is_inside(given, root):
            raise Refusal(f"refusing rules from inside the target, which can't vouch for itself: {given}")
    if given.is_file():
        return given, given.parent
    # A cline-ai-rules checkout narrows to its agent-config rules; any other directory is used whole.
    for candidate in (given / "rules" / "agent-config", given):
        if candidate.is_dir() and pack_rule_files(candidate):
            return candidate, given
    raise Refusal(f"no rule files found at {given}")


def snapshot_name(relative: str) -> str:
    parts = relative.split("/")
    return "/".join([part + "__copy" if part.lower() in SCANNER_SKIPS else part for part in parts[:-1]] + parts[-1:])


def build_snapshot(document: dict[str, Any], includes: list[str], snapshot: Path) -> tuple[dict[str, str], int]:
    """Copy config files to a clean tree. Returns a map from copied path to reported path."""
    extra = [glob_regex(pattern) for pattern in includes]
    mapping: dict[str, str] = {}
    oversized = 0

    def copy(relative: str, display: str, path: Path, prefix: str) -> None:
        nonlocal oversized
        if path.name in SCAN_NEVER_COPY or not (location_kind(relative) or any(p.match(relative) for p in extra)):
            return
        try:
            if os.lstat(path).st_size > MAX_FILE_BYTES:
                oversized += 1
                return
        except OSError:
            return
        data = read_regular(path)
        if data is None:
            return
        name = prefix + snapshot_name(relative)
        destination = snapshot / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        mapping[name] = display

    if document.get("target"):
        target = Path(document["target"])
        for relative, path, is_link, is_directory in walk(target, EXCLUDED_DIRECTORIES):
            if not is_link and not is_directory:
                copy(relative, relative, path, "")
    if document.get("home"):
        for relative, path, is_link, is_directory in home_candidates(Path.home().resolve()):
            if not is_link and not is_directory:
                copy(relative, f"~/{relative}", path, "__user__/")
    return mapping, oversized


def scanner_command(binary: str, rules: Path, snapshot: Path) -> list[str]:
    command = [binary, "scan", "--config", str(rules), "--json", "--quiet", "--disable-nosem",
               "--no-git-ignore", "--disable-version-check", "--timeout", "30", "--max-target-bytes", "0",
               "--jobs", "2"]
    if Path(binary).stem.lower() == "semgrep":
        command.append("--metrics=off")
    return command + [str(snapshot)]


def scanner_environment(snapshot: Path) -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("SEMGREP_", "OPENGREP_", "GIT_"))}
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["GIT_CEILING_DIRECTORIES"] = str(snapshot.parent)
    return environment


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    text = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "[redacted]", text)
    return URL_CREDENTIAL.sub(lambda match: match.group(1) + "[redacted]" + match.group(2), text)


def visible(text: str) -> str:
    """Make invisible and control characters show up as escapes, keeping line breaks and tabs."""
    return "".join(
        f"\\u{{{ord(char):04X}}}" if unicodedata.category(char) in {"Cf", "Cc"} and char not in "\n\t" else char
        for char in text
    )


def is_secret_rule(rule: str) -> bool:
    return "secret" in rule.lower()


def normalize_hits(results: list[dict[str, Any]], snapshot: Path, mapping: dict[str, str]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, int], dict[str, Any]] = {}
    for result in results:
        try:
            relative = Path(result["path"]).resolve().relative_to(snapshot).as_posix()
        except ValueError:
            relative = str(result.get("path", ""))
        rule = str(result.get("check_id", "")).split(".")[-1]
        line = int(result.get("start", {}).get("line", 0))
        extra = result.get("extra", {})
        matched = str(extra.get("lines", ""))
        hit: dict[str, Any] = {
            "rule": rule,
            "file": mapping.get(relative, relative),
            "line": line,
            "scanner_severity": str(extra.get("severity", "")),
            "message": " ".join(str(extra.get("message", "")).split()),
            "suppressed_inline": bool(re.search(r"\bnosem(?:grep)?\b", matched)),
        }
        if not is_secret_rule(rule):
            hit["matched"] = visible(redact(matched))[:400]
        seen.setdefault((hit["file"], rule, line), hit)
    hits = [seen[key] for key in sorted(seen, key=lambda item: (item[0], item[2], item[1]))]
    for number, hit in enumerate(hits, 1):
        hit["id"] = f"H{number:03d}"
    return hits


def command_scan(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    document = load_json(out / "inventory.json", "inventory")
    roots = [Path(document["target"])] if document.get("target") else []
    rules, pack_root = resolve_rules(args.rules, roots)
    binary = shutil.which(args.scanner) if args.scanner else shutil.which("opengrep") or shutil.which("semgrep")
    if binary is None:
        raise Refusal(f"{args.scanner or 'neither opengrep nor semgrep'} is not installed, so the requested scan can't run")

    def finish(payload: dict[str, Any], code: int) -> int:
        write_json(out / "scan.json", {"schema": SCHEMA, "scanned_at": utc_now(), **payload})
        return code

    includes, rule_count = pack_includes(rules)
    scanner_name = Path(binary).stem
    temporary = Path(tempfile.mkdtemp(prefix="agent-config-integrity-")).resolve()
    snapshot = temporary / "copy"
    snapshot.mkdir()
    try:
        mapping, oversized = build_snapshot(document, includes, snapshot)
        base = {"scanner": scanner_name, "rule_count": rule_count, "pack_commit": pack_commit(pack_root),
                "files_scanned": len(mapping), "files_too_large": oversized}
        if not mapping:
            print("OK scan hits=0 files=0")
            return finish({"status": "completed", "hits": [], "errors": [], **base}, 0)
        try:
            completed = subprocess.run(
                scanner_command(binary, rules, snapshot), cwd=temporary, env=scanner_environment(snapshot),
                stdin=subprocess.DEVNULL, capture_output=True, timeout=SCAN_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"FAILED scan: {type(error).__name__}", file=sys.stderr)
            return finish({"status": "failed", "reason": type(error).__name__, "hits": [], **base}, 1)
        try:
            parsed = json.loads(completed.stdout.decode("utf-8", errors="replace"))
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict) or completed.returncode not in (0, 1):
            reason = f"scanner exited {completed.returncode} without usable output"
            print(f"FAILED scan: {reason}", file=sys.stderr)
            return finish({"status": "failed", "reason": reason, "hits": [], **base}, 1)
        hits = normalize_hits(parsed.get("results", []), snapshot, mapping)
        errors = [
            redact(" ".join(str(item.get("message", item.get("type", ""))).split())).replace(str(snapshot), "<copy>")[:300]
            for item in parsed.get("errors", [])
        ]
        print(f"OK scan hits={len(hits)} files={len(mapping)} rules={rule_count} scanner={scanner_name} errors={len(errors)}")
        return finish({"status": "completed", "hits": hits, "errors": errors, **base}, 0)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def resolve_display(document: dict[str, Any], display: str) -> Path | None:
    """Turn a reported path into a real one, refusing anything outside the assessed roots."""
    if display.startswith("~/"):
        if not document.get("home"):
            return None
        root = Path.home().resolve()
        relative = display[2:]
    elif document.get("target"):
        root = Path(document["target"])
        relative = display
    else:
        return None
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        return None
    return root / relative


def comparable(text: str) -> str:
    """Compare text the way a reader would, ignoring spacing and invisible characters."""
    kept = "".join(char for char in text if unicodedata.category(char) != "Cf")
    return " ".join(kept.split())


def validate_findings(document: dict[str, Any], scan: dict[str, Any], findings: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(findings, dict):
        return ["findings.json must be a JSON object"]
    hits = {hit["id"]: hit for hit in scan.get("hits", [])}
    known_files = {item["path"]: item for item in document.get("files", [])}
    claimed: dict[str, str] = {}

    def claim(hit: Any, owner: str) -> None:
        if hit not in hits:
            problems.append(f"{owner}: unknown scanner hit {hit!r}")
        elif hit in claimed:
            problems.append(f"{owner}: scanner hit {hit} is already accounted for by {claimed[hit]}")
        else:
            claimed[hit] = owner

    def check_length(owner: str, field: str, value: Any) -> None:
        limit = WORD_LIMITS[field]
        if isinstance(value, str) and len(value.split()) > limit:
            problems.append(f"{owner}{field} is {len(value.split())} words; keep it to {limit}")

    def check_standalone(owner: str, value: Any) -> None:
        if isinstance(value, str) and LOCAL_LINK.search(value):
            problems.append(f"{owner} links to another file; the report has to stand alone, so put what matters in it")

    if not isinstance(findings.get("summary"), str) or not findings["summary"].strip():
        problems.append("summary: required, one short paragraph")
    check_length("", "summary", findings.get("summary"))
    check_standalone("summary", findings.get("summary"))
    items = findings.get("findings")
    if not isinstance(items, list):
        problems.append("findings: required, a list (empty if nothing was found)")
        items = []
    for index, item in enumerate(items):
        owner = f"findings[{index}]"
        if not isinstance(item, dict):
            problems.append(f"{owner}: must be an object")
            continue
        for field in ("title", "file", "why", "recommendation"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                problems.append(f"{owner}: {field} is required")
        for field in ("why", "recommendation", "severity_reason"):
            check_length(f"{owner}: ", field, item.get(field))
        for field in ("title", "why", "recommendation", "severity_reason"):
            check_standalone(f"{owner}: {field}", item.get(field))
        if item.get("severity") not in SEVERITIES:
            problems.append(f"{owner}: severity must be one of {', '.join(SEVERITIES)}")
        if item.get("category") not in CATEGORIES:
            problems.append(f"{owner}: category must be one of {', '.join(CATEGORIES)}")
        finding_hits = item.get("hits", [])
        if not isinstance(finding_hits, list):
            problems.append(f"{owner}: hits must be a list")
            finding_hits = []
        for hit in finding_hits:
            claim(hit, owner)
        for hit in finding_hits:
            floor = SCANNER_SEVERITY.get(hits.get(hit, {}).get("scanner_severity", ""))
            if (floor and item.get("severity") in SEVERITIES
                    and SEVERITIES.index(item["severity"]) > SEVERITIES.index(floor)
                    and not str(item.get("severity_reason", "")).strip()):
                problems.append(f"{owner}: severity is below the rule's {floor} for {hit}, so severity_reason is required")
        check_location(document, item, owner, known_files, problems)
    dismissed = findings.get("dismissed", [])
    if not isinstance(dismissed, list):
        problems.append("dismissed: must be a list")
        dismissed = []
    for index, item in enumerate(dismissed):
        owner = f"dismissed[{index}]"
        if not isinstance(item, dict) or not str(item.get("reason", "")).strip():
            problems.append(f"{owner}: needs a hit and a reason")
            continue
        check_standalone(f"{owner}: reason", item.get("reason"))
        claim(item.get("hit"), owner)
    for hit in sorted(set(hits) - set(claimed)):
        problems.append(f"scanner hit {hit} ({hits[hit]['rule']} at {hits[hit]['file']}:{hits[hit]['line']}) "
                        "is not accounted for; put it in a finding or dismiss it with a reason")
    not_checked = findings.get("not_checked", [])
    if not isinstance(not_checked, list) or not all(isinstance(item, str) for item in not_checked):
        problems.append("not_checked: must be a list of strings")
    else:
        if len(not_checked) > MAX_NOT_CHECKED:
            problems.append(f"not_checked has {len(not_checked)} entries; keep it to the {MAX_NOT_CHECKED} gaps that matter most")
        for index, entry in enumerate(not_checked):
            if len(entry.split()) > MAX_NOT_CHECKED_WORDS:
                problems.append(f"not_checked[{index}] is {len(entry.split())} words; keep it to {MAX_NOT_CHECKED_WORDS}")
            check_standalone(f"not_checked[{index}]", entry)
    return problems


def check_location(document: dict[str, Any], item: dict[str, Any], owner: str, known_files: dict[str, Any],
                   problems: list[str]) -> None:
    display = item.get("file")
    if not isinstance(display, str) or not display.strip():
        return
    path = resolve_display(document, display)
    data = read_regular(path) if path is not None else None
    if data is None:
        problems.append(f"{owner}: file {display!r} is not a readable regular file in the assessed scope")
        return
    known = known_files.get(display)
    if known and hashlib.sha256(data).hexdigest() != known["sha256"]:
        problems.append(f"{owner}: {display} changed after the inventory; start again from the inventory step")
    lines = data.decode("utf-8", errors="replace").splitlines()
    line = item.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or not 1 <= line <= max(len(lines), 1):
        problems.append(f"{owner}: line must be a number within {display} (1 to {max(len(lines), 1)})")
        return
    evidence = item.get("evidence", "")
    secret = item.get("category") == "exposure" and evidence == ""
    if not isinstance(evidence, str) or (not evidence.strip() and not secret):
        problems.append(f"{owner}: evidence is required; only an exposure finding about a credential may leave it empty")
        return
    if not evidence.strip():
        return
    span = evidence.strip("\n").count("\n") + 1
    if span > MAX_EVIDENCE_LINES:
        problems.append(f"{owner}: evidence is {span} lines; quote at most {MAX_EVIDENCE_LINES}, only the ones that show the issue")
        return
    window = "\n".join(lines[max(line - 2, 0) : line - 1 + span + 1])
    if comparable(evidence) not in comparable(window):
        problems.append(f"{owner}: evidence does not appear at {display}:{line}; quote the file exactly and cite the right line")


def inline(text: Any) -> str:
    """One line of generated or reported text, safe for a Markdown table or sentence."""
    return " ".join(visible(redact(str(text))).split()).replace("|", "\\|")


def code_inline(text: Any) -> str:
    value = " ".join(visible(str(text)).split())
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{pad}{value}{pad}{fence}".replace("|", "\\|")


def code_block(text: str) -> list[str]:
    value = visible(redact(text)).strip("\n")
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * max(longest + 1, 3)
    return [fence + "text", value, fence]


def finding_order(item: dict[str, Any]) -> tuple[int, str, int, str]:
    return (SEVERITIES.index(item["severity"]), item["file"], item["line"], item["title"])


def scanner_line(scan: dict[str, Any]) -> str:
    status = scan.get("status")
    if status == "completed":
        commit = scan.get("pack_commit")
        pack = f"{scan.get('rule_count', 0)} rules" + (f" at commit `{commit}`" if commit else "")
        return f"Completed with {scan.get('scanner')}: {pack}, {scan.get('files_scanned', 0)} files, {len(scan.get('hits', []))} hits."
    if status == "failed":
        return f"**Requested scan failed: {inline(scan.get('reason'))}.** Do not read this report as a clean scan."
    return "None requested."


def position_line(position: str) -> str:
    return {
        "outside": "Outside the target.",
        "parent": "In a parent of the target. Nested instruction files may have been loaded automatically.",
        "inside": "**Inside the target, at the operator's direction.** Its instructions and hooks may have affected this assessment.",
    }.get(position, "Not applicable.")


def render_finding(number: int, item: dict[str, Any], hits: dict[str, Any]) -> list[str]:
    rules = sorted({hits[hit]["rule"] for hit in item.get("hits", [])})
    secret = any(is_secret_rule(rule) for rule in rules) or (item["category"] == "exposure" and not item.get("evidence"))
    detected = "Scanner, confirmed by judgment: " + ", ".join(f"`{rule}`" for rule in rules) if rules else "Judgment"
    lines = [
        f"### ACI-{number:03d}: {inline(item['title'])}",
        "",
        f"- **Severity:** {item['severity']}",
        f"- **Category:** {CATEGORY_LABELS[item['category']]}",
        f"- **Location:** {code_inline(item['file'] + ':' + str(item['line']))}",
        f"- **Detected by:** {detected}",
    ]
    if str(item.get("severity_reason", "")).strip():
        lines.append(f"- **Severity reason:** {inline(item['severity_reason'])}")
    lines += ["", "**Evidence**", ""]
    lines += ["(value withheld)"] if secret else code_block(item["evidence"])
    lines += ["", f"**Why it matters:** {inline(item['why'])}", "", f"**Recommended change:** {inline(item['recommendation'])}", ""]
    return lines


def render_report(document: dict[str, Any], scan: dict[str, Any], findings: dict[str, Any]) -> str:
    hits = {hit["id"]: hit for hit in scan.get("hits", [])}
    items = sorted(findings.get("findings", []), key=finding_order)
    numbered = list(enumerate(items, 1))
    counts = {severity: sum(item["severity"] == severity for item in items) for severity in SEVERITIES}
    lines = [
        "# Agent config integrity report",
        "",
        f"- **Target:** {code_inline(document.get('target_name'))}",
        f"- **Assessed:** {document.get('assessed_at')}",
        f"- **Session started:** {position_line(document.get('session_position', ''))}",
        f"- **User-level configuration:** {'Included' if document.get('home') else 'Not assessed'}",
        f"- **Scanner:** {scanner_line(scan)}",
        "- **Status:** Unsigned. Awaiting human review.",
        "",
        "## Summary",
        "",
        inline(findings.get("summary", "")),
        "",
        "| Severity | Findings |",
        "| --- | --- |",
    ]
    lines += [f"| {severity} | {counts[severity]} |" for severity in SEVERITIES]
    lines += ["", "## Steering instructions", ""]
    steering = [(number, item) for number, item in numbered if item["category"] == "steering"]
    if steering:
        lines += ["Text or settings in the repository that change what people are told about security. Review these first: they affect how far to trust anything an agent has said about this repository.", ""]
        lines += [f"- ACI-{number:03d}: {code_inline(item['file'] + ':' + str(item['line']))}, {inline(item['title'])}"
                  for number, item in steering]
    else:
        lines.append("None found.")
    lines += ["", "## Findings", ""]
    if numbered:
        for number, item in numbered:
            lines += render_finding(number, item, hits)
    else:
        lines += ["No findings.", ""]
    lines += ["## Dismissed scanner hits", ""]
    dismissed = sorted(findings.get("dismissed", []), key=lambda item: item["hit"])
    if dismissed:
        lines += ["| Rule | Location | Reason |", "| --- | --- | --- |"]
        for item in dismissed:
            hit = hits[item["hit"]]
            lines.append(f"| `{hit['rule']}` | {code_inline(hit['file'] + ':' + str(hit['line']))} | {inline(item['reason'])} |")
    else:
        lines.append("None.")
    lines += ["", "## Configuration assessed", ""]
    files = [item for item in document.get("files", []) if item["kind"] != "automation"]
    if files:
        lines += ["| File | Kind | Lines |", "| --- | --- | --- |"]
        lines += [f"| {code_inline(item['path'])} | {item['kind']} | {item['lines']} |" for item in files]
    else:
        lines.append("No agent configuration was found.")
    automation = len(document.get("files", [])) - len(files)
    if automation:
        lines += ["", f"The inventory also listed {automation} automation files, such as CI workflows and compose files, as "
                      "places to look for agents being launched. Their paths are in `inventory.json`."]
    if document.get("policyrelay"):
        lines += ["", f"PolicyRelay guidance was present at {code_inline(document['policyrelay']['index'])} and was applied as requirements."]
    lines += ["", "## Limits", ""]
    lines += [f"- {entry}" for entry in limits(document, scan, findings)]
    lines += [
        "", "## Sign-off", "",
        "This report came from an AI-assisted assessment and is not an approval. It takes effect when a person accepts it.",
        "", "- **Reviewer:**", "- **Date:**", "- **Decision:**", "",
    ]
    return "\n".join(lines)


def limits(document: dict[str, Any], scan: dict[str, Any], findings: dict[str, Any]) -> list[str]:
    entries = ["Covers configuration on disk only. Settings delivered by device management, a vendor's cloud "
               "console, or a SaaS product's own agent features are not visible here."]
    entries += [f"Symlink not followed: {code_inline(item['path'])} points to {code_inline(item['points_to'])}"
                + (" (outside the assessed directory)" if item.get("escapes_root") else "")
                for item in document.get("unfollowed_symlinks", [])]
    entries += [f"Not read: {code_inline(item['path'])}, {inline(item['reason'])}." for item in document.get("skipped", [])]
    if document.get("excluded_directories"):
        names = ", ".join(code_inline(name) for name in document["excluded_directories"])
        entries.append(f"Directories not walked: {names}.")
    if ".git" in document.get("excluded_directories", []):
        entries.append("Local Git configuration and Git hooks were not assessed. They can run commands when someone uses Git in this directory, so treat a repository received as an archive or shared folder with care.")
    if scan.get("files_too_large"):
        entries.append(f"{scan['files_too_large']} files were too large to scan.")
    entries += [f"Scanner error: {inline(item)}" for item in scan.get("errors", [])]
    entries += [inline(item) for item in findings.get("not_checked", [])]
    return entries


def command_render(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    document = load_json(out / "inventory.json", "inventory")
    # A scan runs only when the operator asks for one, so its absence is the normal case.
    scan = load_json(out / "scan.json", "scan") if (out / "scan.json").exists() else {}
    findings = load_json(out / "findings.json", "findings")
    problems = validate_findings(document, scan, findings)
    if problems:
        print(f"PROBLEMS {len(problems)}; report not written", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    (out / "report.md").write_text(render_report(document, scan, findings), encoding="utf-8")
    counts = {severity: sum(item["severity"] == severity for item in findings["findings"]) for severity in SEVERITIES}
    summary = " ".join(f"{severity}={count}" for severity, count in counts.items())
    print(f"OK report {summary} path={out / 'report.md'}")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Read-only helper for the agent-config-integrity skill.")
    commands = root.add_subparsers(dest="command", required=True)
    step = commands.add_parser("inventory", help="find agent configuration, from outside the target")
    step.add_argument("--target", help="absolute path to the repository")
    step.add_argument("--out", required=True, help="output directory, outside the target")
    step.add_argument("--home", action="store_true", help="also read user-level configuration")
    step.add_argument("--allow-inside-target", action="store_true",
                      help="only at the operator's direction; the report records it")
    step.set_defaults(handler=command_inventory)
    step = commands.add_parser("scan", help="run rules the operator named against a clean copy")
    step.add_argument("--out", required=True)
    step.add_argument("--rules", required=True, help="rule file, rule directory, or cline-ai-rules checkout")
    step.add_argument("--scanner", choices=("opengrep", "semgrep"), help="default: whichever is installed")
    step.set_defaults(handler=command_scan)
    step = commands.add_parser("render", help="check findings.json and write report.md")
    step.add_argument("--out", required=True)
    step.set_defaults(handler=command_render)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.handler(args)
    except Refusal as refusal:
        print(f"REFUSED {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
