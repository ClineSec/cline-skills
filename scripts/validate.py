#!/usr/bin/env python3
"""Validate the Team Skills catalog contract and every canonical skill."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):(?:[ \t]*(.*))?$")
PORTABLE_KEYS = {"name", "description", "license", "compatibility", "metadata"}
CATALOG_KEYS = {
    "$schema",
    "schema_version",
    "catalog_id",
    "display_name",
    "skills_directory",
    "default_prefix",
}
RUNTIME_FILES = ("team-skills.sh", "team-skills-json.awk", "team-skills.ps1")


@dataclass(frozen=True)
class SkillProperties:
    name: str
    description: str
    keys: frozenset[str]


def decode_scalar(raw: str, location: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError(f"{location}: value must be a single-line scalar")
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{location}: invalid quoted scalar: {exc.msg}") from exc
        if not isinstance(decoded, str):
            raise ValueError(f"{location}: scalar must be a string")
        return decoded
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise ValueError(f"{location}: unterminated single-quoted scalar")
        return value[1:-1].replace("''", "'")
    if value[0] in "[{|>&*!":
        raise ValueError(f"{location}: use a plain or quoted single-line scalar")
    return value


def read_skill(skill_dir: Path) -> SkillProperties:
    skill_file = skill_dir / "SKILL.md"
    try:
        text = skill_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"{skill_file}: cannot read UTF-8 content: {exc}") from exc
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError(f"{skill_file}: first line must be exactly '---'")
    try:
        closing = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError(f"{skill_file}: missing closing '---' frontmatter marker") from exc

    values: dict[str, str] = {}
    keys: set[str] = set()
    active_key: str | None = None
    for line_number, line in enumerate(lines[1:closing], start=2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            if active_key != "metadata":
                raise ValueError(
                    f"{skill_file}:{line_number}: multiline values are not portable in this catalog"
                )
            nested = KEY_RE.match(line.strip())
            if not nested or not nested.group(2):
                raise ValueError(f"{skill_file}:{line_number}: invalid metadata entry")
            decode_scalar(nested.group(2), f"{skill_file}:{line_number}")
            continue
        match = KEY_RE.match(line)
        if not match:
            raise ValueError(f"{skill_file}:{line_number}: invalid frontmatter entry")
        key, raw_value = match.groups()
        if key in keys:
            raise ValueError(f"{skill_file}:{line_number}: duplicate frontmatter key {key!r}")
        keys.add(key)
        active_key = key
        if key not in PORTABLE_KEYS:
            raise ValueError(f"{skill_file}:{line_number}: nonportable frontmatter key {key!r}")
        if key == "metadata":
            if raw_value and raw_value.strip() not in ("{}",):
                raise ValueError(f"{skill_file}:{line_number}: metadata must be a mapping")
        else:
            values[key] = decode_scalar(raw_value or "", f"{skill_file}:{line_number}")

    missing = {"name", "description"} - keys
    if missing:
        raise ValueError(f"{skill_file}: missing required keys: {', '.join(sorted(missing))}")
    if not any(line.strip() for line in lines[closing + 1 :]):
        raise ValueError(f"{skill_file}: Markdown body must not be empty")

    name = values["name"]
    description = values["description"]
    if len(name) > 64 or not NAME_RE.fullmatch(name):
        raise ValueError(f"{skill_file}: invalid portable skill name {name!r}")
    if name != skill_dir.name:
        raise ValueError(
            f"{skill_file}: frontmatter name {name!r} must match parent {skill_dir.name!r}"
        )
    if not description.strip() or len(description) > 1024:
        raise ValueError(f"{skill_file}: description must contain 1-1024 characters")
    compatibility = values.get("compatibility")
    if compatibility is not None and (not compatibility or len(compatibility) > 500):
        raise ValueError(f"{skill_file}: compatibility must contain 1-500 characters")
    return SkillProperties(name=name, description=description, keys=frozenset(keys))


def effective_skill_name(prefix: str, skill_name: str) -> str:
    if prefix and not NAME_RE.fullmatch(prefix):
        raise ValueError(f"invalid prefix {prefix!r}")
    if not NAME_RE.fullmatch(skill_name):
        raise ValueError(f"invalid skill name {skill_name!r}")
    effective = f"{prefix}-{skill_name}" if prefix else skill_name
    if len(effective) > 64:
        raise ValueError(f"effective skill name exceeds 64 characters: {effective!r}")
    return effective


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def validate_catalog(root: Path) -> tuple[list[str], int, str]:
    errors: list[str] = []
    manifest_path = root / "catalog.json"
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return [f"{manifest_path}: cannot read valid UTF-8 JSON: {exc}"], 0, "unknown"
    if not isinstance(manifest, dict):
        return [f"{manifest_path}: top level must be an object"], 0, "unknown"

    scripts_root = root / "scripts"
    if scripts_root.is_symlink() or not scripts_root.is_dir():
        errors.append(f"{scripts_root}: must be a regular directory")
    else:
        for runtime_name in RUNTIME_FILES:
            runtime_path = scripts_root / runtime_name
            if runtime_path.is_symlink() or not runtime_path.is_file():
                errors.append(f"{runtime_path}: required lifecycle runtime must be a regular file")
        shell_runtime = scripts_root / "team-skills.sh"
        if shell_runtime.is_file() and not shell_runtime.is_symlink() and not os.access(shell_runtime, os.X_OK):
            errors.append(f"{shell_runtime}: POSIX lifecycle runtime must be executable")

    unknown = set(manifest) - CATALOG_KEYS
    missing = CATALOG_KEYS - set(manifest)
    if unknown:
        errors.append(f"{manifest_path}: unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        errors.append(f"{manifest_path}: missing fields: {', '.join(sorted(missing))}")
    if manifest.get("$schema") != "./schemas/catalog.schema.json":
        errors.append(f"{manifest_path}: $schema must reference ./schemas/catalog.schema.json")
    if manifest.get("schema_version") != 1 or isinstance(manifest.get("schema_version"), bool):
        errors.append(f"{manifest_path}: schema_version must be integer 1")
    catalog_id = manifest.get("catalog_id")
    if not isinstance(catalog_id, str) or len(catalog_id) > 64 or not NAME_RE.fullmatch(catalog_id):
        errors.append(f"{manifest_path}: catalog_id must be a portable kebab-case name")
        catalog_id = "unknown"
    display_name = manifest.get("display_name")
    if not isinstance(display_name, str) or not display_name or len(display_name) > 128:
        errors.append(f"{manifest_path}: display_name must contain 1-128 characters")
    if manifest.get("skills_directory") != "skills":
        errors.append(f"{manifest_path}: skills_directory must be 'skills' in schema v1")
    prefix = manifest.get("default_prefix")
    if not isinstance(prefix, str) or (prefix and not NAME_RE.fullmatch(prefix)) or len(prefix) > 62:
        errors.append(f"{manifest_path}: default_prefix must be blank or portable kebab-case")
        prefix = ""

    skills_root = root / "skills"
    if skills_root.is_symlink() or not skills_root.is_dir():
        errors.append(f"{skills_root}: must be a regular directory")
        return errors, 0, str(catalog_id)

    skill_count = 0
    for path in sorted(skills_root.rglob("*")):
        if path.is_symlink():
            errors.append(f"{path}: canonical catalog content must not be a symlink")
    for skill_dir in sorted(skills_root.iterdir()):
        if skill_dir.name.startswith("."):
            errors.append(f"{skill_dir}: hidden entries are not canonical skills")
            continue
        if not skill_dir.is_dir():
            errors.append(f"{skill_dir}: every immediate child of skills/ must be a directory")
            continue
        skill_count += 1
        try:
            properties = read_skill(skill_dir)
            effective_skill_name(prefix, properties.name)
        except ValueError as exc:
            errors.append(str(exc))
    return errors, skill_count, str(catalog_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="catalog root (defaults to this repository)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    errors, count, catalog_id = validate_catalog(args.root.resolve())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"Validation failed: {len(errors)} error(s).", file=sys.stderr)
        return 1
    print(f"Validated catalog {catalog_id}: {count} skill(s), 0 errors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
