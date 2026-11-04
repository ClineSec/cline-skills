"""Strict, source-agnostic transformation into PolicyRelay contract 1.0."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping


SUPPORTED_VERSION = "1.0"
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
NORMATIVE_RE = re.compile(r"\b(?:MUST(?: NOT)?|SHOULD(?: NOT)?|MAY)\b")
TITLE_RE = re.compile(r"^[^\s#<>&\[\]`*_\\][^\r\n#<>&\[\]`*_\\]{0,119}$")
FORCES = {"MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY"}
INCOMPATIBLE_FORCE_PAIRS = {
    frozenset(("MUST", "MUST NOT")),
    frozenset(("MUST", "SHOULD NOT")),
    frozenset(("SHOULD", "MUST NOT")),
    frozenset(("SHOULD", "SHOULD NOT")),
    frozenset(("MAY", "MUST NOT")),
}
PROVENANCE_FIELDS = (
    "sourceId",
    "sourceTitle",
    "sourceRevision",
    "sourceLocator",
    "distilledAt",
)
TOP_FIELDS = {"contractVersion", "bundleId", "routes"}
ROUTE_FIELDS = {
    "task",
    "title",
    "summary",
    "applicability",
    "normativeRequirements",
    "exceptionsAndEscalation",
    "provenance",
}


class DistillationError(ValueError):
    """The normalized input cannot be transformed without guessing."""


class _DuplicateKeyError(ValueError):
    pass


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_input(source: Path | str) -> dict[str, Any]:
    """Load local JSON as data, rejecting invalid UTF-8 and duplicate keys."""
    source_path = Path(source)
    try:
        raw = source_path.read_text(encoding="utf-8")
        value = json.loads(raw, object_pairs_hook=_object_without_duplicates)
    except UnicodeDecodeError as exc:
        raise DistillationError("input is not valid UTF-8") from exc
    except (json.JSONDecodeError, _DuplicateKeyError) as exc:
        raise DistillationError(f"input is not unambiguous JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise DistillationError("input root must be an object")
    return value


def _exact_fields(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        raise DistillationError(f"{location} missing required fields: {', '.join(missing)}")
    if unknown:
        raise DistillationError(f"{location} has unsupported fields: {', '.join(unknown)}")


def _identifier(value: Any, location: str, *, max_length: int | None = None) -> str:
    if not isinstance(value, str) or not KEBAB_RE.fullmatch(value):
        raise DistillationError(f"{location} must be lowercase kebab case")
    if max_length is not None and len(value) > max_length:
        raise DistillationError(f"{location} exceeds {max_length} characters")
    return value


def _text(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise DistillationError(f"{location} must be a string")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise DistillationError(f"{location} contains unsupported control characters")
    normalized = " ".join(value.split())
    if not normalized:
        raise DistillationError(f"{location} must not be empty")
    return normalized


def _title(value: Any, location: str) -> str:
    normalized = _text(value, location)
    if not TITLE_RE.fullmatch(normalized):
        raise DistillationError(f"{location} contains unsupported Markdown structural characters")
    return normalized


def _date(value: Any, location: str) -> str:
    normalized = _text(value, location)
    try:
        parsed = dt.date.fromisoformat(normalized)
    except ValueError as exc:
        raise DistillationError(f"{location} must be a real YYYY-MM-DD date") from exc
    if parsed.isoformat() != normalized:
        raise DistillationError(f"{location} must use YYYY-MM-DD format")
    return normalized


def _source_ids(value: Any, known: set[str], location: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise DistillationError(f"{location} must be a non-empty array")
    result = [_identifier(item, f"{location}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise DistillationError(f"{location} contains duplicate source identifiers")
    missing = sorted(set(result) - known)
    if missing:
        raise DistillationError(f"{location} references undeclared provenance: {', '.join(missing)}")
    return sorted(result)


def _provenance(value: Any, location: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise DistillationError(f"{location} must be a non-empty array")
    records: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item_location = f"{location}[{index}]"
        if not isinstance(raw, dict):
            raise DistillationError(f"{item_location} must be an object")
        _exact_fields(raw, set(PROVENANCE_FIELDS), item_location)
        record = {
            "sourceId": _identifier(raw["sourceId"], f"{item_location}.sourceId"),
            "sourceTitle": _text(raw["sourceTitle"], f"{item_location}.sourceTitle"),
            "sourceRevision": _text(raw["sourceRevision"], f"{item_location}.sourceRevision"),
            "sourceLocator": _text(raw["sourceLocator"], f"{item_location}.sourceLocator"),
            "distilledAt": _date(raw["distilledAt"], f"{item_location}.distilledAt"),
        }
        records.append(record)
    records.sort(key=lambda item: item["sourceId"])
    source_ids = [item["sourceId"] for item in records]
    if len(source_ids) != len(set(source_ids)):
        raise DistillationError(f"{location} contains duplicate sourceId values")
    return records


def _statements(value: Any, known: set[str], location: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise DistillationError(f"{location} must be a non-empty array")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_location = f"{location}[{index}]"
        if not isinstance(raw, dict):
            raise DistillationError(f"{item_location} must be an object")
        _exact_fields(raw, {"text", "sourceIds"}, item_location)
        result.append(
            {
                "text": _text(raw["text"], f"{item_location}.text"),
                "sourceIds": _source_ids(raw["sourceIds"], known, f"{item_location}.sourceIds"),
            }
        )
    result.sort(key=lambda item: (item["text"].casefold(), item["sourceIds"]))
    keys = [(item["text"].casefold(), tuple(item["sourceIds"])) for item in result]
    if len(keys) != len(set(keys)):
        raise DistillationError(f"{location} contains duplicate statements")
    return result


def _requirements(value: Any, known: set[str], location: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise DistillationError(f"{location} must be a non-empty array")
    result: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        item_location = f"{location}[{index}]"
        if not isinstance(raw, dict):
            raise DistillationError(f"{item_location} must be an object")
        _exact_fields(raw, {"force", "text", "sourceIds"}, item_location)
        force = raw["force"]
        if not isinstance(force, str) or force not in FORCES:
            raise DistillationError(f"{item_location}.force is unsupported")
        statement = _text(raw["text"], f"{item_location}.text")
        if NORMATIVE_RE.search(statement):
            raise DistillationError(
                f"{item_location}.text embeds normative force; use the force field only"
            )
        result.append(
            {
                "force": force,
                "text": statement,
                "sourceIds": _source_ids(raw["sourceIds"], known, f"{item_location}.sourceIds"),
            }
        )
    result.sort(key=lambda item: (item["text"].casefold(), item["force"], item["sourceIds"]))
    exact = [(item["force"], item["text"].casefold(), tuple(item["sourceIds"])) for item in result]
    if len(exact) != len(set(exact)):
        raise DistillationError(f"{location} contains duplicate requirements")

    forces_by_text: dict[str, set[str]] = {}
    for item in result:
        forces_by_text.setdefault(item["text"].casefold(), set()).add(item["force"])
    for forces in forces_by_text.values():
        if any(pair <= forces for pair in INCOMPATIBLE_FORCE_PAIRS):
            raise DistillationError(f"{location} has contradictory force for one statement")
    return result


def _canonicalize(logical_input: dict[str, Any]) -> dict[str, Any]:
    _exact_fields(logical_input, TOP_FIELDS, "input")
    version = logical_input["contractVersion"]
    if version != SUPPORTED_VERSION:
        raise DistillationError("unsupported contractVersion; supported: '1.0'")
    bundle_id = _identifier(logical_input["bundleId"], "input.bundleId", max_length=80)
    raw_routes = logical_input["routes"]
    if not isinstance(raw_routes, list) or not raw_routes:
        raise DistillationError("input.routes must be a non-empty array")

    routes: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_routes):
        location = f"input.routes[{index}]"
        if not isinstance(raw, dict):
            raise DistillationError(f"{location} must be an object")
        _exact_fields(raw, ROUTE_FIELDS, location)
        provenance = _provenance(raw["provenance"], f"{location}.provenance")
        known = {record["sourceId"] for record in provenance}
        applicability = _statements(raw["applicability"], known, f"{location}.applicability")
        requirements = _requirements(
            raw["normativeRequirements"], known, f"{location}.normativeRequirements"
        )
        exceptions = _statements(
            raw["exceptionsAndEscalation"], known, f"{location}.exceptionsAndEscalation"
        )
        used = {
            source_id
            for section in (applicability, requirements, exceptions)
            for item in section
            for source_id in item["sourceIds"]
        }
        unused = sorted(known - used)
        if unused:
            raise DistillationError(
                f"{location}.provenance has records not used by route text: {', '.join(unused)}"
            )
        summary = _text(raw["summary"], f"{location}.summary")
        if NORMATIVE_RE.search(summary):
            raise DistillationError(f"{location}.summary must not contain normative guidance")
        routes.append(
            {
                "task": _identifier(raw["task"], f"{location}.task"),
                "title": _title(raw["title"], f"{location}.title"),
                "summary": summary,
                "applicability": applicability,
                "normativeRequirements": requirements,
                "exceptionsAndEscalation": exceptions,
                "provenance": provenance,
            }
        )
    routes.sort(key=lambda route: route["task"])
    tasks = [route["task"] for route in routes]
    if len(tasks) != len(set(tasks)):
        raise DistillationError("input.routes contains duplicate or ambiguous task routes")
    return {"contractVersion": version, "bundleId": bundle_id, "routes": routes}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _markdown_text(value: str) -> str:
    """Render untrusted plain text without creating Markdown/HTML structure."""
    value = value.replace("&", "&amp;")
    value = value.replace("[", "&lbrack;").replace("]", "&rbrack;")
    value = value.replace("<", "&lt;").replace(">", "&gt;")
    value = value.replace("\\", "\\\\").replace("`", "\\`")
    value = value.replace("*", "\\*").replace("_", "\\_").replace("#", "\\#")
    return value


def _source_suffix(source_ids: list[str]) -> str:
    rendered = ", ".join(f"`{source_id}`" for source_id in source_ids)
    return f" Sources: {rendered}."


def _guidance(route: dict[str, Any]) -> bytes:
    metadata = {
        "task": route["task"],
        "title": route["title"],
        "provenance": route["provenance"],
    }
    chunks = ["---\n", json.dumps(metadata, ensure_ascii=False, indent=2), "\n---\n\n"]
    chunks.append(f"# {route['title']}\n\n")
    chunks.append("## Applicability\n\n")
    for item in route["applicability"]:
        chunks.append(f"- {_markdown_text(item['text'])}{_source_suffix(item['sourceIds'])}\n")
    chunks.append("\n## Normative guidance\n\n")
    for item in route["normativeRequirements"]:
        chunks.append(
            f"- {item['force']} {_markdown_text(item['text'])}{_source_suffix(item['sourceIds'])}\n"
        )
    chunks.append("\n## Exceptions and escalation\n\n")
    for item in route["exceptionsAndEscalation"]:
        chunks.append(f"- {_markdown_text(item['text'])}{_source_suffix(item['sourceIds'])}\n")
    chunks.append("\n## Source provenance\n\n")
    for record in route["provenance"]:
        chunks.append(
            f"- `{record['sourceId']}` is identified by its exact revision and locator in the metadata provenance record.\n"
        )
    return "".join(chunks).encode("utf-8")


def distill(logical_input: dict[str, Any]) -> dict[str, bytes]:
    """Validate, canonicalize, and return every bundle file as deterministic bytes."""
    canonical = _canonicalize(logical_input)
    digest = hashlib.sha256(_canonical_json(canonical)).hexdigest()[:24]
    revision = f"sha256-{digest}"
    manifest_routes = [
        {"task": route["task"], "entrypoint": f"guidance/{route['task']}.md"}
        for route in canonical["routes"]
    ]
    manifest = {
        "contractVersion": SUPPORTED_VERSION,
        "bundleId": canonical["bundleId"],
        "bundleRevision": revision,
        "payloadRoot": "payload",
        "routes": manifest_routes,
    }
    index_lines = [
        "# PolicyRelay guidance",
        "",
        "Choose the route matching the task and load only that document.",
        "",
    ]
    for route in canonical["routes"]:
        index_lines.append(
            f"- [{route['task']}](guidance/{route['task']}.md) — {_markdown_text(route['summary'])}"
        )
    index_bytes = ("\n".join(index_lines) + "\n").encode("utf-8")
    if len(index_bytes) > 1200 or sum(bool(line.strip()) for line in index_lines) > 25:
        raise DistillationError("generated progressive-disclosure index exceeds contract 1.0 bounds")

    files = {
        "manifest.json": (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        "payload/index.md": index_bytes,
    }
    for route in canonical["routes"]:
        files[f"payload/guidance/{route['task']}.md"] = _guidance(route)
    return dict(sorted(files.items()))


def write_bundle(files: Mapping[str, bytes], output: Path | str) -> None:
    """Atomically create a new bundle directory; never merge into existing output."""
    destination = Path(output)
    if os.path.lexists(destination):
        raise DistillationError(f"output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".policyrelay-distiller-", dir=destination.parent))
    candidate = temporary / "bundle"
    try:
        for relative, content in sorted(files.items()):
            target = candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        candidate.rename(destination)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
