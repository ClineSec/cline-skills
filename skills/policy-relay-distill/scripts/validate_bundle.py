#!/usr/bin/env python3
"""Deterministic, dependency-free validator for PolicyRelay bundle contract 1.0."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Union


SUPPORTED_VERSIONS = {"1.0"}
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\n]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$", re.MULTILINE)
NORMATIVE_RE = re.compile(r"\b(?:MUST(?: NOT)?|SHOULD(?: NOT)?|MAY)\b")
GUIDANCE_SECTIONS = [
    "Applicability",
    "Normative guidance",
    "Exceptions and escalation",
    "Source provenance",
]
MANIFEST_FIELDS = {
    "contractVersion",
    "bundleId",
    "bundleRevision",
    "payloadRoot",
    "routes",
}
GUIDANCE_FIELDS = {"task", "title", "provenance"}
PROVENANCE_FIELDS = {
    "sourceId",
    "sourceTitle",
    "sourceRevision",
    "sourceLocator",
    "distilledAt",
}
MAX_DIAGNOSTIC_LINE_CHARS = 512
MAX_CLI_DIAGNOSTIC_CHARS = 4096
ROUTE_LOCATION_RE = re.compile(r"^manifest\.json#/routes/[0-9]+$")
SAFE_DIAGNOSTIC_LOCATIONS = {
    ".",
    "manifest.json",
    "payload",
    "payload/index.md",
    "payload/guidance",
}
DIAGNOSTIC_MESSAGES = {
    "bundle-id": "bundleId has an invalid shape",
    "bundle-missing": "bundle path must be an existing directory",
    "bundle-revision": "bundleRevision has an invalid shape",
    "embedded-content": "embedded content is not supported",
    "file-type": "entry has an invalid filesystem type",
    "guidance-heading": "guidance heading does not match its title",
    "guidance-local-link": "guidance entrypoints must be self-contained",
    "guidance-metadata": "guidance metadata has an invalid shape",
    "guidance-missing": "guidance directory is missing",
    "guidance-name": "guidance filename has an invalid shape",
    "guidance-normative": "normative guidance keyword is missing",
    "guidance-section-empty": "a required guidance section is empty",
    "guidance-sections": "guidance sections do not match the required sequence",
    "guidance-task": "guidance task does not match its declared route",
    "guidance-title": "guidance title has an invalid shape",
    "guidance-unexpected": "guidance file is not declared by a route",
    "index-heading": "index must contain exactly one H1",
    "index-route-ambiguous": "index contains an undeclared, mismatched, or duplicate route",
    "index-route-missing": "index is missing a declared route",
    "index-size": "index exceeds a contract size limit",
    "json": "file is not valid JSON",
    "link-broken": "local link target does not exist",
    "link-escape": "local link escapes the payload root",
    "link-scheme": "link uses an unsupported scheme",
    "link-syntax": "link uses unsupported syntax",
    "link-target": "link target has an invalid shape",
    "manifest-field-missing": "required manifest field is missing",
    "manifest-field-unknown": "manifest contains an unknown field",
    "manifest-shape": "manifest must be a JSON object",
    "payload-entry-unexpected": "payload root contains an unexpected entry",
    "payload-root": "payloadRoot does not name the required payload root",
    "provenance-malformed": "source provenance has an invalid shape",
    "provenance-reference": "source provenance is not referenced by the guidance body",
    "read": "file could not be read",
    "root-entry-missing": "required bundle-root entry is missing",
    "root-entry-unexpected": "bundle root contains an unexpected entry",
    "root-index-missing": "payload root index is missing",
    "route-ambiguous": "task or entrypoint is declared more than once",
    "route-missing": "at least one task route is required",
    "route-path": "route entrypoint has an invalid shape",
    "route-shape": "route has an invalid shape",
    "route-target-missing": "declared route target is missing",
    "route-task": "route task has an invalid shape",
    "routes-shape": "routes must be an array",
    "symlink-forbidden": "symbolic links are forbidden",
    "unsupported-version": "contract version is not supported",
    "utf8": "file is not valid UTF-8",
}


def _diagnostic_location(path: str) -> str:
    """Return a useful contract-owned location without exposing candidate path data."""

    if path in SAFE_DIAGNOSTIC_LOCATIONS or ROUTE_LOCATION_RE.fullmatch(path):
        return path
    if path.startswith("manifest.json#"):
        return "manifest.json"
    if path.startswith("payload/guidance/"):
        return "payload/guidance"
    if path.startswith("payload/"):
        return "payload"
    return "."


class DuplicateKeyError(ValueError):
    """Raised when JSON contains duplicate object keys."""


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


@dataclass(frozen=True, order=True)
class ValidationError:
    path: str
    code: str
    message: str

    def render(self) -> str:
        rendered = f"ERROR {self.code} [{self.path}]: {self.message}"
        if len(rendered) > MAX_DIAGNOSTIC_LINE_CHARS:
            return "ERROR diagnostic-overflow [.]: diagnostic detail omitted"
        return rendered


class BundleValidator:
    """Accumulates stable, sorted diagnostics without evaluating bundle content."""

    def __init__(self, bundle: Path):
        self.bundle = bundle
        self.errors: list[ValidationError] = []
        self.manifest: dict[str, Any] | None = None
        self.routes: list[tuple[str, str]] = []
        self.text_files: dict[str, str] = {}

    def error(self, code: str, path: str, message: str) -> None:
        # Candidate-controlled values may still be passed by validation call sites, but they
        # never cross this rendering boundary. Codes select fixed messages and locations are
        # reduced to contract-owned paths or stable route-array indexes.
        del message
        self.errors.append(
            ValidationError(_diagnostic_location(path), code, DIAGNOSTIC_MESSAGES[code])
        )

    def validate(self) -> list[ValidationError]:
        if self.bundle.is_symlink():
            self.error("symlink-forbidden", ".", "bundle root must not be a symbolic link")
            return sorted(set(self.errors))
        if not self.bundle.is_dir():
            self.error("bundle-missing", ".", "bundle path must be an existing directory")
            return sorted(set(self.errors))

        self._validate_tree_types()
        self._validate_root_layout()
        self._load_manifest()
        if self.manifest is not None:
            self._validate_manifest()
        self._load_contract_text()
        self._validate_payload_layout()
        self._validate_links()
        self._validate_index()
        self._validate_guidance()
        return sorted(set(self.errors))

    def _relative(self, path: Path) -> str:
        try:
            return path.relative_to(self.bundle).as_posix()
        except ValueError:
            return "."

    def _validate_tree_types(self) -> None:
        for current, directory_names, file_names in os.walk(
            self.bundle, topdown=True, followlinks=False
        ):
            current_path = Path(current)
            for name in sorted(directory_names):
                candidate = current_path / name
                if candidate.is_symlink():
                    self.error(
                        "symlink-forbidden",
                        self._relative(candidate),
                        "directories must be real directories",
                    )
            for name in sorted(file_names):
                candidate = current_path / name
                relative = self._relative(candidate)
                if candidate.is_symlink():
                    self.error("symlink-forbidden", relative, "files must be regular files")
                elif not candidate.is_file():
                    self.error("file-type", relative, "payload entries must be regular files")

    def _validate_root_layout(self) -> None:
        actual = {child.name for child in self.bundle.iterdir()}
        expected = {"manifest.json", "payload"}
        for name in sorted(expected - actual):
            self.error("root-entry-missing", name, "required bundle-root entry is missing")
        for name in sorted(actual - expected):
            self.error("root-entry-unexpected", name, "unexpected bundle-root entry")
        manifest_path = self.bundle / "manifest.json"
        if manifest_path.exists() and not manifest_path.is_file():
            self.error("file-type", "manifest.json", "manifest must be a regular file")
        payload = self.bundle / "payload"
        if payload.exists() and not payload.is_dir():
            self.error("file-type", "payload", "payload must be a directory")

    def _load_json(self, path: Path, relative: str) -> Any | None:
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            self.error("utf8", relative, "file is not valid UTF-8")
            return None
        except OSError as exc:
            self.error("read", relative, f"cannot read file: {exc.strerror or exc}")
            return None
        try:
            return json.loads(raw, object_pairs_hook=_object_without_duplicates)
        except (json.JSONDecodeError, DuplicateKeyError) as exc:
            self.error("json", relative, f"invalid JSON: {exc}")
            return None

    def _load_manifest(self) -> None:
        path = self.bundle / "manifest.json"
        if path.is_file() and not path.is_symlink():
            value = self._load_json(path, "manifest.json")
            if value is not None:
                if isinstance(value, dict):
                    self.manifest = value
                else:
                    self.error("manifest-shape", "manifest.json", "manifest must be a JSON object")

    def _validate_manifest(self) -> None:
        assert self.manifest is not None
        fields = set(self.manifest)
        for field in sorted(MANIFEST_FIELDS - fields):
            self.error("manifest-field-missing", "manifest.json", f"missing field {field!r}")
        for field in sorted(fields - MANIFEST_FIELDS):
            self.error("manifest-field-unknown", "manifest.json", f"unknown field {field!r}")

        version = self.manifest.get("contractVersion")
        if version not in SUPPORTED_VERSIONS:
            self.error(
                "unsupported-version",
                "manifest.json",
                f"supported versions are {sorted(SUPPORTED_VERSIONS)!r}",
            )
        bundle_id = self.manifest.get("bundleId")
        if not isinstance(bundle_id, str) or not KEBAB_RE.fullmatch(bundle_id) or len(bundle_id) > 80:
            self.error("bundle-id", "manifest.json", "bundleId must be 1-80 lowercase-kebab characters")
        revision = self.manifest.get("bundleRevision")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            self.error("bundle-revision", "manifest.json", "bundleRevision has an invalid shape")
        if self.manifest.get("payloadRoot") != "payload":
            self.error("payload-root", "manifest.json", "payloadRoot must be exactly 'payload'")

        raw_routes = self.manifest.get("routes")
        if not isinstance(raw_routes, list):
            self.error("routes-shape", "manifest.json", "routes must be an array")
            return
        if not raw_routes:
            self.error("route-missing", "manifest.json", "at least one task route is required")

        seen_tasks: set[str] = set()
        seen_entrypoints: set[str] = set()
        for index, route in enumerate(raw_routes):
            route_path = f"manifest.json#/routes/{index}"
            if not isinstance(route, dict):
                self.error("route-shape", route_path, "route must be an object")
                continue
            fields = set(route)
            if fields != {"task", "entrypoint"}:
                self.error("route-shape", route_path, "route fields must be exactly task and entrypoint")
            task = route.get("task")
            entrypoint = route.get("entrypoint")
            if not isinstance(task, str) or not KEBAB_RE.fullmatch(task):
                self.error("route-task", route_path, "task must be lowercase kebab case")
                continue
            if not isinstance(entrypoint, str) or not self._valid_relative_path(entrypoint):
                self.error("route-path", route_path, "entrypoint must be a normalized relative path")
                continue
            expected = f"guidance/{task}.md"
            if entrypoint != expected:
                self.error("route-path", route_path, f"entrypoint must be exactly {expected!r}")
            if task in seen_tasks:
                self.error("route-ambiguous", route_path, f"task {task!r} is declared more than once")
            if entrypoint in seen_entrypoints:
                self.error(
                    "route-ambiguous", route_path, f"entrypoint {entrypoint!r} is used more than once"
                )
            seen_tasks.add(task)
            seen_entrypoints.add(entrypoint)
            self.routes.append((task, entrypoint))

    @staticmethod
    def _valid_relative_path(value: str) -> bool:
        if not value or "\\" in value or "%" in value or "?" in value or "#" in value:
            return False
        pure = PurePosixPath(value)
        return (
            not pure.is_absolute()
            and all(part not in {"", ".", ".."} for part in pure.parts)
            and pure.as_posix() == value
        )

    def _load_contract_text(self) -> None:
        payload = self.bundle / "payload"
        if not payload.is_dir() or payload.is_symlink():
            return
        candidates = [payload / "index.md"]
        guidance = payload / "guidance"
        if guidance.is_dir() and not guidance.is_symlink():
            candidates.extend(sorted(guidance.iterdir(), key=lambda item: item.name))
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            relative = self._relative(path)
            try:
                self.text_files[relative] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                self.error("utf8", relative, "file is not valid UTF-8")
            except OSError as exc:
                self.error("read", relative, f"cannot read file: {exc.strerror or exc}")

    def _validate_payload_layout(self) -> None:
        payload = self.bundle / "payload"
        if not payload.is_dir() or payload.is_symlink():
            return
        actual = {child.name for child in payload.iterdir()}
        expected = {"index.md", "guidance"}
        if "index.md" not in actual:
            self.error("root-index-missing", "payload/index.md", "payload root requires index.md")
        elif not (payload / "index.md").is_file() or (payload / "index.md").is_symlink():
            self.error("file-type", "payload/index.md", "root index must be a regular file")
        for name in sorted(actual - expected):
            self.error("payload-entry-unexpected", f"payload/{name}", "unexpected payload-root entry")
        guidance = payload / "guidance"
        if not guidance.is_dir() or guidance.is_symlink():
            if not guidance.exists():
                self.error("guidance-missing", "payload/guidance", "guidance directory is missing")
            return

        actual_files = {child.name for child in guidance.iterdir()}
        expected_files = {PurePosixPath(entrypoint).name for _, entrypoint in self.routes}
        for name in sorted(expected_files - actual_files):
            self.error("route-target-missing", f"payload/guidance/{name}", "declared route target is missing")
        for name in sorted(actual_files - expected_files):
            self.error("guidance-unexpected", f"payload/guidance/{name}", "undeclared guidance file")
        for name in sorted(actual_files):
            child = guidance / name
            if not child.is_file() or child.is_symlink():
                self.error("file-type", f"payload/guidance/{name}", "guidance entry must be a regular file")
            stem = name[:-3] if name.endswith(".md") else ""
            if not stem or not KEBAB_RE.fullmatch(stem):
                self.error("guidance-name", f"payload/guidance/{name}", "guidance name must be <task>.md")

    def _inline_links(self, text: str, relative: str) -> list[tuple[str, str]]:
        if re.search(r"!\[[^\]]*\]\(", text):
            self.error("link-syntax", relative, "images are not supported")
        if re.search(r"^\s*\[[^\]]+\]:\s*\S+", text, re.MULTILINE):
            self.error("link-syntax", relative, "reference-style links are not supported")
        if re.search(r"<[A-Za-z/][^>]*>", text):
            self.error("embedded-content", relative, "raw HTML or embedded content is not supported")
        return [(match.group(1), match.group(2)) for match in LINK_RE.finditer(text)]

    def _validate_links(self) -> None:
        for relative, text in sorted(self.text_files.items()):
            for _, raw_target in self._inline_links(text, relative):
                if raw_target != raw_target.strip() or any(char.isspace() for char in raw_target):
                    self.error("link-target", relative, "link targets must not contain whitespace or titles")
                    continue
                if raw_target.startswith("https://"):
                    continue
                if ":" in raw_target.split("/", 1)[0]:
                    self.error("link-scheme", relative, "only HTTPS external links are supported")
                    continue
                if raw_target.startswith("/"):
                    self.error("link-escape", relative, "absolute local links are forbidden")
                    continue
                if not self._valid_relative_path(raw_target):
                    code = "link-escape" if ".." in PurePosixPath(raw_target).parts else "link-target"
                    self.error(code, relative, "local link must be normalized and remain inside payload")
                    continue
                candidate = posixpath.normpath(
                    posixpath.join(posixpath.dirname(relative), raw_target)
                )
                if not candidate.startswith("payload/"):
                    self.error("link-escape", relative, "local link escapes the payload root")
                    continue
                if candidate not in self.text_files:
                    self.error("link-broken", relative, f"local target {raw_target!r} does not exist")
                if relative.startswith("payload/guidance/"):
                    self.error("guidance-local-link", relative, "guidance entrypoints must be self-contained")

    def _validate_index(self) -> None:
        relative = "payload/index.md"
        text = self.text_files.get(relative)
        if text is None:
            return
        if len(text.encode("utf-8")) > 1200:
            self.error("index-size", relative, "index exceeds 1,200 UTF-8 bytes")
        if sum(1 for line in text.splitlines() if line.strip()) > 25:
            self.error("index-size", relative, "index exceeds 25 non-blank lines")
        headings = [(len(markers), title) for markers, title in HEADING_RE.findall(text)]
        if sum(1 for level, _ in headings if level == 1) != 1:
            self.error("index-heading", relative, "index must contain exactly one H1")

        links = self._inline_links(text, relative)
        expected = {(task, entrypoint) for task, entrypoint in self.routes}
        actual = set(links)
        if len(links) != len(actual):
            self.error("index-route-ambiguous", relative, "index contains a duplicate route link")
        for link in sorted(expected - actual):
            self.error("index-route-missing", relative, f"missing exact route link {link!r}")
        for link in sorted(actual - expected):
            self.error("index-route-ambiguous", relative, f"undeclared or mismatched link {link!r}")

    def _parse_front_matter(self, relative: str, text: str) -> tuple[dict[str, Any] | None, str]:
        if not text.startswith("---\n"):
            self.error("guidance-metadata", relative, "file must start with a --- delimiter")
            return None, text
        closing = text.find("\n---\n", 4)
        if closing < 0:
            self.error("guidance-metadata", relative, "closing --- delimiter is missing")
            return None, text
        raw = text[4:closing]
        try:
            value = json.loads(raw, object_pairs_hook=_object_without_duplicates)
        except (json.JSONDecodeError, DuplicateKeyError) as exc:
            self.error("provenance-malformed", relative, f"metadata is invalid JSON: {exc}")
            return None, text[closing + 5 :]
        if not isinstance(value, dict):
            self.error("guidance-metadata", relative, "metadata must be a JSON object")
            return None, text[closing + 5 :]
        return value, text[closing + 5 :]

    def _validate_guidance(self) -> None:
        route_by_file = {f"payload/{entrypoint}": task for task, entrypoint in self.routes}
        for relative, expected_task in sorted(route_by_file.items()):
            text = self.text_files.get(relative)
            if text is None:
                continue
            metadata, body = self._parse_front_matter(relative, text)
            if metadata is None:
                continue
            fields = set(metadata)
            if fields != GUIDANCE_FIELDS:
                self.error("guidance-metadata", relative, "metadata fields must be exactly task, title, provenance")
            task = metadata.get("task")
            title = metadata.get("title")
            if task != expected_task:
                self.error("guidance-task", relative, f"metadata task must be {expected_task!r}")
            if not isinstance(title, str) or not title.strip():
                self.error("guidance-title", relative, "title must be a non-empty string")

            source_ids = self._validate_provenance(relative, metadata.get("provenance"))
            headings = [(len(markers), heading) for markers, heading in HEADING_RE.findall(body)]
            h1 = [heading for level, heading in headings if level == 1]
            h2 = [heading for level, heading in headings if level == 2]
            if not isinstance(title, str) or h1 != [title]:
                self.error("guidance-heading", relative, "body must have exactly one H1 equal to title")
            if h2 != GUIDANCE_SECTIONS:
                self.error("guidance-sections", relative, f"H2 sections must be exactly {GUIDANCE_SECTIONS!r}")
                continue

            sections = self._section_bodies(body)
            for section in GUIDANCE_SECTIONS:
                if not sections.get(section, "").strip():
                    self.error("guidance-section-empty", relative, f"section {section!r} is empty")
            if not NORMATIVE_RE.search(sections.get("Normative guidance", "")):
                self.error("guidance-normative", relative, "normative section needs an uppercase keyword")
            provenance_body = sections.get("Source provenance", "")
            for source_id in source_ids:
                if source_id not in provenance_body:
                    self.error("provenance-reference", relative, f"sourceId {source_id!r} is not named in the body")

    def _validate_provenance(self, relative: str, value: Any) -> list[str]:
        if not isinstance(value, list) or not value:
            self.error("provenance-malformed", relative, "provenance must be a non-empty array")
            return []
        source_ids: list[str] = []
        for index, record in enumerate(value):
            if not isinstance(record, dict) or set(record) != PROVENANCE_FIELDS:
                self.error(
                    "provenance-malformed",
                    relative,
                    f"provenance record {index} must contain exactly the five required fields",
                )
                continue
            for field in sorted(PROVENANCE_FIELDS):
                field_value = record.get(field)
                if not isinstance(field_value, str) or not field_value.strip():
                    self.error("provenance-malformed", relative, f"record {index} field {field!r} is empty")
            source_id = record.get("sourceId")
            if isinstance(source_id, str):
                source_ids.append(source_id)
                if not KEBAB_RE.fullmatch(source_id):
                    self.error("provenance-malformed", relative, f"record {index} sourceId is not kebab case")
            distilled_at = record.get("distilledAt")
            if isinstance(distilled_at, str):
                try:
                    if not DATE_RE.fullmatch(distilled_at):
                        raise ValueError
                    dt.date.fromisoformat(distilled_at)
                except ValueError:
                    self.error("provenance-malformed", relative, f"record {index} distilledAt is not a date")
        if len(source_ids) != len(set(source_ids)):
            self.error("provenance-malformed", relative, "sourceId values must be unique within a document")
        return source_ids

    @staticmethod
    def _section_bodies(body: str) -> dict[str, str]:
        matches = list(re.finditer(r"^##[ \t]+(.+?)[ \t]*$", body, re.MULTILINE))
        result: dict[str, str] = {}
        for index, match in enumerate(matches):
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
            result[match.group(1)] = body[start:end]
        return result


def validate_bundle(bundle: Union[Path, str]) -> list[ValidationError]:
    """Return deterministic validation errors; an empty list means accepted."""

    return BundleValidator(Path(bundle)).validate()


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="candidate bundle directory")
    return parser.parse_args(argv)


def _render_cli_errors(errors: list[ValidationError]) -> str:
    """Render a deterministic diagnostic prefix within the CLI-wide character budget."""

    summary = f"INVALID errors={len(errors)}"
    rendered: list[str] = []
    omitted = False
    for error in errors:
        line = error.render()
        candidate = "\n".join([*rendered, line, summary]) + "\n"
        if len(candidate) > MAX_CLI_DIAGNOSTIC_CHARS:
            omitted = True
            break
        rendered.append(line)

    if omitted:
        omission = "ERROR diagnostic-limit [.]: additional diagnostics omitted"
        while rendered:
            candidate = "\n".join([*rendered, omission, summary]) + "\n"
            if len(candidate) <= MAX_CLI_DIAGNOSTIC_CHARS:
                break
            rendered.pop()
        if len("\n".join([*rendered, omission, summary]) + "\n") <= MAX_CLI_DIAGNOSTIC_CHARS:
            rendered.append(omission)

    output = "\n".join([*rendered, summary]) + "\n"
    if len(output) > MAX_CLI_DIAGNOSTIC_CHARS:
        # The fixed summary is currently far below the limit; keep this guard fail-closed if
        # its format ever changes.
        output = "INVALID errors=diagnostic-limit\n"
    return output


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    errors = validate_bundle(args.bundle)
    if errors:
        sys.stderr.write(_render_cli_errors(errors))
        return 1

    manifest = json.loads((args.bundle / "manifest.json").read_text(encoding="utf-8"))
    print(
        "VALID "
        f"contractVersion={manifest['contractVersion']} "
        f"routes={len(manifest['routes'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
