#!/usr/bin/env python3
"""Create a complete portable skill in a skills catalog."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path


NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RESOURCE_NAMES = {"scripts", "references", "assets"}


class CreatorError(ValueError):
    """A safe, user-correctable creator failure."""


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def find_catalog_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / "catalog.json").is_file():
            return candidate
    raise CreatorError("no catalog.json found; pass --catalog-root explicitly")


def load_catalog(root: Path) -> dict[str, object]:
    manifest_path = root / "catalog.json"
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
        )
    except FileNotFoundError as exc:
        raise CreatorError(f"catalog manifest not found: {manifest_path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise CreatorError(f"cannot read catalog manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise CreatorError("the creator supports only catalog schema_version 1")
    if manifest.get("skills_directory") != "skills":
        raise CreatorError("catalog schema v1 requires skills_directory to be 'skills'")
    return manifest


def validate_inputs(name: str, description: str, body: str) -> None:
    if len(name) > 64 or not NAME_RE.fullmatch(name):
        raise CreatorError(
            "name must be at most 64 lowercase ASCII letters, digits, or single hyphens"
        )
    if not description.strip() or len(description) > 1024 or "\n" in description:
        raise CreatorError("description must be a nonempty single line of at most 1024 characters")
    if not body.strip():
        raise CreatorError("body file must contain finished Markdown instructions")
    if body.startswith("---"):
        raise CreatorError("body file must not contain YAML frontmatter")


def parse_resources(raw: str) -> list[str]:
    if not raw:
        return []
    resources = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = sorted(set(resources) - RESOURCE_NAMES)
    if unknown:
        raise CreatorError(f"unsupported resource directories: {', '.join(unknown)}")
    return sorted(set(resources))


def create_skill(
    root: Path, name: str, description: str, body: str, resources: list[str]
) -> Path:
    load_catalog(root)
    validate_inputs(name, description, body)

    skills_root = root / "skills"
    if skills_root.is_symlink() or (skills_root.exists() and not skills_root.is_dir()):
        raise CreatorError(f"skills root is not a regular directory: {skills_root}")
    skills_root.mkdir(parents=True, exist_ok=True)

    target = skills_root / name
    if target.exists() or target.is_symlink():
        raise CreatorError(f"refusing to overwrite existing path: {target}")

    temporary = Path(tempfile.mkdtemp(prefix=f".{name}.", dir=skills_root))
    try:
        frontmatter = f"---\nname: {name}\ndescription: {json.dumps(description)}\n---\n\n"
        normalized_body = body.rstrip() + "\n"
        (temporary / "SKILL.md").write_text(frontmatter + normalized_body, encoding="utf-8")
        for resource in resources:
            (temporary / resource).mkdir()
        temporary.rename(target)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="portable kebab-case skill name")
    parser.add_argument("--description", required=True, help="single-line activation description")
    parser.add_argument("--body-file", required=True, type=Path, help="finished Markdown body")
    parser.add_argument(
        "--catalog-root",
        type=Path,
        help="catalog root; defaults to the nearest catalog.json above the current directory",
    )
    parser.add_argument(
        "--resources",
        default="",
        help="comma-separated subset of scripts,references,assets",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = args.catalog_root.resolve() if args.catalog_root else find_catalog_root(Path.cwd())
        try:
            body = args.body_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CreatorError(f"cannot read body file {args.body_file}: {exc}") from exc
        target = create_skill(
            root,
            args.name,
            args.description,
            body,
            parse_resources(args.resources),
        )
    except CreatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"created {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
