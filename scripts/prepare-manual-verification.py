#!/usr/bin/env python3
"""Prepare and operate a disposable two-catalog manual-verification fixture.

This is development/test tooling, not an installation runtime dependency. It never launches an AI
product and refuses to prepare over an existing path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESULTS_TEMPLATE = REPOSITORY_ROOT / "docs" / "manual-results-template.md"
FIXTURE_SCHEMA = 1
MAX_METADATA_BYTES = 1024 * 1024


class FixtureError(RuntimeError):
    pass


def safe_absolute_path(value: str) -> Path:
    if any(character in value for character in "\n\r\t"):
        raise FixtureError("fixture root must not contain control characters")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise FixtureError("fixture root must be an absolute path")
    if path.is_symlink():
        raise FixtureError("fixture root must not be a symlink or reparse point")
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        raise FixtureError("fixture root must not be a filesystem root")
    return resolved


def run(
    command: list[str], *, env: dict[str, str], cwd: Path | None = None, expected: int = 0
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=cwd, env=env, text=True, capture_output=True, check=False, timeout=60
    )
    if result.returncode != expected:
        rendered = " ".join(shlex.quote(part) for part in command)
        raise FixtureError(
            f"command failed ({result.returncode}, expected {expected}): {rendered}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def git(env: dict[str, str], *arguments: str, cwd: Path | None = None) -> str:
    return run(["git", *arguments], env=env, cwd=cwd).stdout.strip()


def fixture_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "CODEX_HOME": str(home / ".codex"),
            "TEAM_SKILLS_STATE_ROOT": str(root / "state"),
            "TEAM_SKILLS_AGENTS_ROOT": str(home / ".agents" / "skills"),
            "TEAM_SKILLS_CLAUDE_ROOT": str(home / ".claude" / "skills"),
            "TEAM_SKILLS_CLAUDE_HOOKS_FILE": str(home / ".claude" / "settings.json"),
            "TEAM_SKILLS_CODEX_HOOKS_FILE": str(home / ".codex" / "hooks.json"),
            "TEAM_SKILLS_CURSOR_HOOKS_FILE": str(home / ".cursor" / "hooks.json"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(root / "empty-gitconfig"),
            "TEAM_SKILLS_THROTTLE_SECONDS": "0",
        }
    )
    return environment


def write_catalog(root: Path, label: str, marker: str, env: dict[str, str]) -> tuple[Path, Path]:
    work = root / "catalog-work" / label
    origin = root / "catalog-origins" / f"{label}.git"
    skill = work / "skills" / "common-skill"
    skill.mkdir(parents=True)
    (work / "catalog.json").write_text(
        json.dumps(
            {
                "$schema": "./schemas/catalog.schema.json",
                "schema_version": 1,
                "catalog_id": "manual-shared-catalog-id",
                "display_name": f"Manual {label.title()} Catalog",
                "skills_directory": "skills",
                "default_prefix": "",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (skill / "SKILL.md").write_text(
        "---\nname: common-skill\ndescription: Disposable manual fixture skill.\n---\n\n"
        f"# Fixture {label} {marker}\n",
        encoding="utf-8",
    )
    runtime = work / "scripts"
    runtime.mkdir()
    for runtime_name in ("team-skills.sh", "team-skills-json.awk", "team-skills.ps1"):
        shutil.copy2(REPOSITORY_ROOT / "scripts" / runtime_name, runtime)
    git(env, "init", "--initial-branch=main", str(work))
    git(env, "config", "user.name", "Team Skills Manual Fixture", cwd=work)
    git(env, "config", "user.email", "fixture@example.invalid", cwd=work)
    git(env, "add", ".", cwd=work)
    git(env, "commit", "-m", f"{label} {marker}", cwd=work)
    git(env, "init", "--bare", str(origin))
    git(env, "remote", "add", "origin", str(origin), cwd=work)
    git(env, "push", "-u", "origin", "main", cwd=work)
    git(env, "symbolic-ref", "HEAD", "refs/heads/main", cwd=origin)
    return work, origin


def runtime_command(action: str, *arguments: str) -> list[str]:
    if os.name == "nt":
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            raise FixtureError("Windows PowerShell was not found")
        return [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPOSITORY_ROOT / "scripts" / "team-skills.ps1"),
            action,
            *arguments,
        ]
    return ["sh", str(REPOSITORY_ROOT / "scripts" / "team-skills.sh"), action, *arguments]


def prefix_arguments(prefix: str) -> list[str]:
    return ["-Prefix" if os.name == "nt" else "--prefix", prefix]


def auto_update_argument() -> str:
    return "-SetupAutoUpdate" if os.name == "nt" else "--setup-auto-update"


def seed_foreign_files(root: Path) -> dict[str, Path]:
    home = root / "home"
    paths = {
        "claude": home / ".claude" / "settings.json",
        "codex": home / ".codex" / "hooks.json",
        "cursor": home / ".cursor" / "hooks.json",
    }
    values: dict[str, Any] = {
        "claude": {
            "permissions": {"allow": ["Read"]},
            "hooks": {"PreToolUse": [{"hooks": [{"command": "foreign-claude"}]}]},
        },
        "codex": {
            "description": "Keep this unrelated Codex configuration",
            "hooks": {
                "Other": [
                    {
                        "matcher": "startup",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "foreign-codex",
                                "async": True,
                            }
                        ],
                    }
                ]
            },
        },
        "cursor": {
            "version": 1,
            "hooks": {
                "sessionStart": [{"command": "foreign-cursor"}],
                "workspaceOpen": [{"command": "foreign-workspace"}],
            },
        },
    }
    before = root / "evidence" / "before"
    before.mkdir(parents=True)
    for product, path in paths.items():
        path.parent.mkdir(parents=True)
        text = json.dumps(values[product], indent=2) + "\n"
        path.write_text(text, encoding="utf-8")
        (before / f"{product}.json").write_text(text, encoding="utf-8")
    return paths


def shell_exports(environment: dict[str, str]) -> str:
    keys = sorted(key for key in environment if key.startswith("TEAM_SKILLS_"))
    keys.extend(["HOME", "CODEX_HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"])
    return "\n".join(f"export {key}={shlex.quote(environment[key])}" for key in keys) + "\n"


def powershell_exports(environment: dict[str, str]) -> str:
    keys = sorted(key for key in environment if key.startswith("TEAM_SKILLS_"))
    keys.extend(["USERPROFILE", "LOCALAPPDATA", "CODEX_HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"])
    lines = []
    for key in keys:
        escaped = environment[key].replace("'", "''")
        lines.append(f"$env:{key} = '{escaped}'")
    return "\n".join(lines) + "\n"


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise FixtureError(f"fixture ownership metadata has duplicate key {key!r}")
        value[key] = item
    return value


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"fixture ownership metadata {label} is invalid")
    return value


def require_owned_path(
    value: Any, expected: Path, label: str, *, directory: bool, allow_missing: bool = False
) -> Path:
    if not isinstance(value, str) or any(character in value for character in "\n\r\t"):
        raise FixtureError(f"fixture ownership metadata {label} is invalid")
    path = Path(value)
    if path != expected or not path.is_absolute() or path.is_symlink():
        raise FixtureError(f"fixture ownership metadata {label} is outside the owned fixture")
    if allow_missing and not path.exists():
        if path.resolve(strict=False) != expected:
            raise FixtureError(f"fixture ownership metadata {label} crosses an unsafe path")
        return path
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise FixtureError(f"fixture ownership metadata {label} is missing") from error
    if resolved != expected or (directory and not path.is_dir()) or (not directory and not path.is_file()):
        raise FixtureError(f"fixture ownership metadata {label} has an unsafe path type")
    return path


def expected_instance_digests(origin: Path) -> set[str]:
    encoded = str(origin).encode("utf-8")
    git_blob = b"blob " + str(len(encoded)).encode("ascii") + b"\0" + encoded
    return {hashlib.sha1(git_blob).hexdigest(), hashlib.sha256(encoded).hexdigest()}


def validate_fixture_metadata(
    root: Path, metadata: dict[str, Any], *, allow_missing_owned: bool = False
) -> None:
    if metadata.get("schema_version") != FIXTURE_SCHEMA or metadata.get("root") != str(root):
        raise FixtureError("fixture ownership metadata is invalid")
    catalogs = require_mapping(metadata.get("catalogs"), "catalogs")
    if set(catalogs) != {"first", "second"}:
        raise FixtureError("fixture ownership metadata catalogs are invalid")
    instances: set[Path] = set()
    for catalog in ("first", "second"):
        entry = require_mapping(catalogs[catalog], f"catalogs.{catalog}")
        work = require_owned_path(
            entry.get("work"), root / "catalog-work" / catalog, f"catalogs.{catalog}.work",
            directory=True, allow_missing=allow_missing_owned,
        )
        origin = require_owned_path(
            entry.get("origin"), root / "catalog-origins" / f"{catalog}.git",
            f"catalogs.{catalog}.origin", directory=True, allow_missing=allow_missing_owned,
        )
        instance_value = entry.get("instance")
        if not isinstance(instance_value, str):
            raise FixtureError(f"fixture ownership metadata catalogs.{catalog}.instance is invalid")
        instance = Path(instance_value)
        expected_parent = root / "state" / "catalogs"
        suffix = instance.name.removeprefix("manual-shared-catalog-id-")
        if (
            instance.parent != expected_parent
            or instance.is_symlink()
            or suffix not in expected_instance_digests(origin)
        ):
            raise FixtureError(
                f"fixture ownership metadata catalogs.{catalog}.instance is outside the owned fixture"
            )
        require_owned_path(
            instance_value, instance, f"catalogs.{catalog}.instance", directory=True,
            allow_missing=allow_missing_owned,
        )
        require_owned_path(
            str(instance / "repo" / ".git"), instance / "repo" / ".git",
            f"catalogs.{catalog}.instance Git metadata", directory=True,
            allow_missing=allow_missing_owned,
        )
        require_owned_path(
            str(work / ".git"), work / ".git", f"catalogs.{catalog}.work Git metadata",
            directory=True, allow_missing=allow_missing_owned,
        )
        instances.add(instance)
    if len(instances) != 2:
        raise FixtureError("fixture ownership metadata reuses a managed catalog instance")


def load_fixture(root: Path, *, allow_missing_owned: bool = False) -> dict[str, Any]:
    metadata_path = root / "fixture.json"
    if not metadata_path.is_file() or metadata_path.is_symlink():
        raise FixtureError(f"not a prepared fixture: {metadata_path}")
    if metadata_path.stat().st_size > MAX_METADATA_BYTES:
        raise FixtureError("fixture ownership metadata is too large")
    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
    )
    metadata = require_mapping(metadata, "root")
    validate_fixture_metadata(root, metadata, allow_missing_owned=allow_missing_owned)
    return metadata


def prepare(root: Path) -> None:
    if root.exists():
        raise FixtureError("refusing to prepare over an existing path")
    root.mkdir(parents=True)
    try:
        (root / "home").mkdir()
        (root / "empty-gitconfig").write_text("", encoding="utf-8")
        env = fixture_environment(root)
        hook_paths = seed_foreign_files(root)
        first_work, first_origin = write_catalog(root, "first", "v1", env)
        second_work, second_origin = write_catalog(root, "second", "v1", env)

        results = []
        for command in (
            runtime_command("install", str(first_origin), auto_update_argument()),
            runtime_command("install", str(first_origin), auto_update_argument()),
            runtime_command("install", str(second_origin), auto_update_argument()),
            runtime_command(
                "install", str(second_origin), *prefix_arguments("second"), auto_update_argument()
            ),
        ):
            results.append(run(command, env=env))
        collision = results[2]
        if "warning: catalog manual-shared-catalog-id skill common-skill skipped" not in collision.stderr:
            raise FixtureError("blank-prefix collision did not emit the expected warning")

        instances: dict[str, str] = {}
        state_catalogs = root / "state" / "catalogs"
        for instance in state_catalogs.iterdir():
            configured = git(env, "remote", "get-url", "origin", cwd=instance / "repo")
            instances[configured] = str(instance)
        if set(instances) != {str(first_origin), str(second_origin)}:
            raise FixtureError("prepared instances do not match the two local origins")

        after = root / "evidence" / "after-install"
        after.mkdir()
        for product, path in hook_paths.items():
            shutil.copy2(path, after / f"{product}.json")
        transcript = root / "evidence" / "install-transcript.txt"
        transcript.write_text(
            "\n".join(
                f"step {index}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                for index, result in enumerate(results, start=1)
            ),
            encoding="utf-8",
        )

        team_sha = git(env, "rev-parse", "HEAD", cwd=REPOSITORY_ROOT)
        metadata: dict[str, Any] = {
            "schema_version": FIXTURE_SCHEMA,
            "root": str(root),
            "prepared_at": datetime.now(timezone.utc).isoformat(),
            "team_skills_sha": team_sha,
            "runtime": "native-windows-powershell" if os.name == "nt" else "posix-shell",
            "catalogs": {
                "first": {
                    "work": str(first_work),
                    "origin": str(first_origin),
                    "instance": instances[str(first_origin)],
                    "marker": "v1",
                },
                "second": {
                    "work": str(second_work),
                    "origin": str(second_origin),
                    "instance": instances[str(second_origin)],
                    "marker": "v1",
                },
            },
            "paths": {
                "state": str(root / "state"),
                "agents_skills": str(root / "home" / ".agents" / "skills"),
                "claude_skills": str(root / "home" / ".claude" / "skills"),
                "claude_hooks": str(hook_paths["claude"]),
                "codex_hooks": str(hook_paths["codex"]),
                "cursor_hooks": str(hook_paths["cursor"]),
                "unreachable_origin": str(root / "missing-origins" / "catalog.git"),
            },
            "expected": {
                "unprefixed_marker": "# Fixture first v1",
                "prefixed_marker": "# Fixture second v1",
                "prefixed_name": "second-common-skill",
                "human_results": "PENDING",
            },
        }
        (root / "fixture.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        (root / "environment.sh").write_text(shell_exports(env), encoding="utf-8")
        (root / "environment.ps1").write_text(powershell_exports(env), encoding="utf-8")
        results_text = RESULTS_TEMPLATE.read_text(encoding="utf-8")
        results_text = results_text.replace("<TEAM_SKILLS_SHA>", team_sha).replace(
            "<DISPOSABLE_FIXTURE_ROOT>", str(root)
        )
        (root / "RESULTS.md").write_text(results_text, encoding="utf-8")
    except BaseException:
        # A failed preparation never leaves a path that looks like a completed fixture.
        (root / "fixture.json").unlink(missing_ok=True)
        raise

    print(f"Prepared disposable fixture: {root}")
    print(f"Team Skills SHA: {team_sha}")
    print("Human Claude Code, Codex, Cursor, and WSL results remain PENDING.")
    print(f"Follow docs/manual-verification.md and record results in {root / 'RESULTS.md'}")


def advance(root: Path, catalog: str, marker: str) -> None:
    metadata = load_fixture(root)
    if not marker or any(character in marker for character in "\n\r\t"):
        raise FixtureError("marker must be a nonblank single-line value")
    entry = metadata["catalogs"][catalog]
    work = Path(entry["work"])
    skill = work / "skills" / "common-skill" / "SKILL.md"
    current = f"# Fixture {catalog} {entry['marker']}"
    replacement = f"# Fixture {catalog} {marker}"
    text = skill.read_text(encoding="utf-8")
    if current not in text:
        raise FixtureError("fixture skill marker no longer matches ownership metadata")
    skill.write_text(text.replace(current, replacement, 1), encoding="utf-8")
    env = fixture_environment(root)
    git(env, "add", ".", cwd=work)
    git(env, "commit", "-m", f"{catalog} {marker}", cwd=work)
    git(env, "push", cwd=work)
    entry["marker"] = marker
    entry["head"] = git(env, "rev-parse", "HEAD", cwd=work)
    (root / "fixture.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Advanced {catalog} origin to {entry['head']} with marker {replacement}")


def set_origin(root: Path, catalog: str, mode: str) -> None:
    metadata = load_fixture(root)
    entry = metadata["catalogs"][catalog]
    instance = Path(entry["instance"])
    expected_parent = root / "state" / "catalogs"
    if instance.parent != expected_parent or not (instance / "repo" / ".git").is_dir():
        raise FixtureError("managed clone path is outside the owned fixture state")
    if mode == "restore":
        value = entry["origin"]
    else:
        missing_uri = Path(metadata["paths"]["unreachable_origin"]).as_uri()
        value = missing_uri.replace("file://", "file://manual-user:manual-secret@", 1)
    git(fixture_environment(root), "remote", "set-url", "origin", value, cwd=instance / "repo")
    print(f"Set {catalog} managed origin mode to {mode}.")
    if mode == "unreachable":
        print("The embedded credentials are inert fixture strings; logs must contain neither value.")


def show(root: Path) -> None:
    metadata = load_fixture(root)
    print(json.dumps(metadata, indent=2))


def cleanup_fixture(root: Path) -> None:
    # Product-check removal may already have deleted managed instances. Their exact metadata paths
    # must remain fixture-scoped, but cleanup does not require those owned children to still exist.
    load_fixture(root, allow_missing_owned=True)
    def remove_readonly(function: Any, path: str, _: Any) -> None:
        # Git for Windows creates read-only object files. Clear only that leaf's write bit after
        # rmtree has already selected it beneath the validated fixture root, then retry once.
        os.chmod(path, stat.S_IWRITE)
        function(path)

    shutil.rmtree(root, onerror=remove_readonly)
    print(f"Removed validated disposable fixture only: {root}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    prepare_parser = subparsers.add_parser("prepare", help="create and install a new fixture")
    prepare_parser.add_argument("root", help="new absolute fixture path")
    advance_parser = subparsers.add_parser("advance", help="commit and push a valid catalog change")
    advance_parser.add_argument("root", help="prepared absolute fixture path")
    advance_parser.add_argument("catalog", choices=("first", "second"))
    advance_parser.add_argument("marker", help="single-line content marker, for example v2")
    origin_parser = subparsers.add_parser("origin", help="make an origin unreachable or restore it")
    origin_parser.add_argument("root", help="prepared absolute fixture path")
    origin_parser.add_argument("catalog", choices=("first", "second"))
    origin_parser.add_argument("mode", choices=("unreachable", "restore"))
    show_parser = subparsers.add_parser("show", help="print fixture paths and expected values")
    show_parser.add_argument("root", help="prepared absolute fixture path")
    cleanup_parser = subparsers.add_parser(
        "cleanup", help="validate ownership and remove only the prepared fixture root"
    )
    cleanup_parser.add_argument("root", help="prepared absolute fixture path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = safe_absolute_path(args.root)
        if args.action == "prepare":
            prepare(root)
        elif args.action == "advance":
            advance(root, args.catalog, args.marker)
        elif args.action == "origin":
            set_origin(root, args.catalog, args.mode)
        elif args.action == "show":
            show(root)
        else:
            cleanup_fixture(root)
    except (FixtureError, OSError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
