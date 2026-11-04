"""Contract 1.0 validator, kept in parity with the policy-relay-distill validator.

This module deliberately has no schema, Markdown, or network dependencies.  Bundle
text is parsed as inert data.  Public diagnostics contain only stable codes and
bundle-relative paths; untrusted text is never returned to the caller.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SUPPORTED_VERSIONS = {"1.0"}
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^)\n]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t]*$", re.MULTILINE)
NORMATIVE_RE = re.compile(r"\b(?:MUST(?: NOT)?|SHOULD(?: NOT)?|MAY)\b")
SECTIONS = ["Applicability", "Normative guidance", "Exceptions and escalation", "Source provenance"]
MANIFEST_FIELDS = {"contractVersion", "bundleId", "bundleRevision", "payloadRoot", "routes"}
GUIDANCE_FIELDS = {"task", "title", "provenance"}
PROVENANCE_FIELDS = {"sourceId", "sourceTitle", "sourceRevision", "sourceLocator", "distilledAt"}


class DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError
        result[key] = value
    return result


@dataclass(frozen=True, order=True)
class ValidationIssue:
    path: str
    code: str


def _diagnostic_path(path: str) -> str:
    """Keep location useful without returning an attacker-chosen name."""
    fixed = {".", "manifest.json", "payload", "payload/index.md", "payload/guidance"}
    if path in fixed:
        return path
    if re.fullmatch(r"manifest\.json#/routes/[0-9]{1,8}", path):
        return path
    if path.startswith("payload/guidance/"):
        return "payload/guidance/<entry>"
    if path.startswith("payload/"):
        return "payload/<entry>"
    return "<bundle-entry>"


def _safe_path(path: str) -> bool:
    if not path or "\\" in path or "%" in path or "?" in path or "#" in path:
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and all(p not in {"", ".", ".."} for p in pure.parts) and pure.as_posix() == path


class Validator:
    def __init__(self, bundle: Path):
        self.bundle = bundle
        self.issues: list[ValidationIssue] = []
        self.manifest: dict[str, Any] | None = None
        self.routes: list[tuple[str, str]] = []
        self.text: dict[str, str] = {}

    def add(self, code: str, path: str) -> None:
        self.issues.append(ValidationIssue(_diagnostic_path(path), code))

    def validate(self) -> list[ValidationIssue]:
        if self.bundle.is_symlink():
            self.add("symlink-forbidden", ".")
            return sorted(set(self.issues))
        if not self.bundle.is_dir():
            self.add("bundle-missing", ".")
            return sorted(set(self.issues))
        self._tree_types()
        self._root_layout()
        self._manifest()
        self._load_text()
        self._payload_layout()
        self._links()
        self._index()
        self._guidance()
        return sorted(set(self.issues))

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.bundle).as_posix()
        except ValueError:
            return "."

    def _tree_types(self) -> None:
        try:
            for current, dirs, files in os.walk(self.bundle, topdown=True, followlinks=False):
                base = Path(current)
                for name in sorted(dirs):
                    if (base / name).is_symlink():
                        self.add("symlink-forbidden", self.rel(base / name))
                for name in sorted(files):
                    item = base / name
                    if item.is_symlink():
                        self.add("symlink-forbidden", self.rel(item))
                    elif not item.is_file():
                        self.add("file-type", self.rel(item))
        except OSError:
            self.add("read", ".")

    def _root_layout(self) -> None:
        try:
            actual = {p.name for p in self.bundle.iterdir()}
        except OSError:
            self.add("read", ".")
            return
        expected = {"manifest.json", "payload"}
        for name in sorted(expected - actual):
            self.add("root-entry-missing", name)
        for name in sorted(actual - expected):
            self.add("root-entry-unexpected", name)
        manifest = self.bundle / "manifest.json"
        if manifest.exists() and (not manifest.is_file() or manifest.is_symlink()):
            self.add("file-type", "manifest.json")
        payload = self.bundle / "payload"
        if payload.exists() and (not payload.is_dir() or payload.is_symlink()):
            self.add("file-type", "payload")

    def _json(self, path: Path, relative: str) -> Any | None:
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            self.add("utf8", relative)
            return None
        except OSError:
            self.add("read", relative)
            return None
        try:
            return json.loads(raw, object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, DuplicateKeyError):
            self.add("json", relative)
            return None

    def _manifest(self) -> None:
        path = self.bundle / "manifest.json"
        if not path.is_file() or path.is_symlink():
            return
        value = self._json(path, "manifest.json")
        if not isinstance(value, dict):
            if value is not None:
                self.add("manifest-shape", "manifest.json")
            return
        self.manifest = value
        fields = set(value)
        for _ in MANIFEST_FIELDS - fields:
            self.add("manifest-field-missing", "manifest.json")
        for _ in fields - MANIFEST_FIELDS:
            self.add("manifest-field-unknown", "manifest.json")
        if value.get("contractVersion") not in SUPPORTED_VERSIONS:
            self.add("unsupported-version", "manifest.json")
        bundle_id = value.get("bundleId")
        if not isinstance(bundle_id, str) or len(bundle_id) > 80 or not KEBAB_RE.fullmatch(bundle_id):
            self.add("bundle-id", "manifest.json")
        revision = value.get("bundleRevision")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            self.add("bundle-revision", "manifest.json")
        if value.get("payloadRoot") != "payload":
            self.add("payload-root", "manifest.json")
        raw_routes = value.get("routes")
        if not isinstance(raw_routes, list):
            self.add("routes-shape", "manifest.json")
            return
        if not raw_routes:
            self.add("route-missing", "manifest.json")
        tasks: set[str] = set()
        entries: set[str] = set()
        for index, route in enumerate(raw_routes):
            path = f"manifest.json#/routes/{index}"
            if not isinstance(route, dict):
                self.add("route-shape", path)
                continue
            if set(route) != {"task", "entrypoint"}:
                self.add("route-shape", path)
            task, entry = route.get("task"), route.get("entrypoint")
            if not isinstance(task, str) or not KEBAB_RE.fullmatch(task):
                self.add("route-task", path)
                continue
            if not isinstance(entry, str) or not _safe_path(entry):
                self.add("route-path", path)
                continue
            if entry != f"guidance/{task}.md":
                self.add("route-path", path)
            if task in tasks or entry in entries:
                self.add("route-ambiguous", path)
            tasks.add(task)
            entries.add(entry)
            self.routes.append((task, entry))

    def _load_text(self) -> None:
        payload = self.bundle / "payload"
        if not payload.is_dir() or payload.is_symlink():
            return
        candidates = [payload / "index.md"]
        guidance = payload / "guidance"
        if guidance.is_dir() and not guidance.is_symlink():
            try:
                candidates.extend(sorted(guidance.iterdir(), key=lambda p: p.name))
            except OSError:
                self.add("read", "payload/guidance")
        for path in candidates:
            if not path.is_file() or path.is_symlink():
                continue
            relative = self.rel(path)
            try:
                self.text[relative] = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                self.add("utf8", relative)
            except OSError:
                self.add("read", relative)

    def _payload_layout(self) -> None:
        payload = self.bundle / "payload"
        if not payload.is_dir() or payload.is_symlink():
            return
        try:
            actual = {p.name for p in payload.iterdir()}
        except OSError:
            self.add("read", "payload")
            return
        if "index.md" not in actual:
            self.add("root-index-missing", "payload/index.md")
        elif not (payload / "index.md").is_file() or (payload / "index.md").is_symlink():
            self.add("file-type", "payload/index.md")
        for name in actual - {"index.md", "guidance"}:
            self.add("payload-entry-unexpected", f"payload/{name}")
        guidance = payload / "guidance"
        if not guidance.is_dir() or guidance.is_symlink():
            if not guidance.exists():
                self.add("guidance-missing", "payload/guidance")
            return
        try:
            children = list(guidance.iterdir())
        except OSError:
            self.add("read", "payload/guidance")
            return
        actual_files = {p.name for p in children}
        expected_files = {PurePosixPath(entry).name for _, entry in self.routes}
        for name in expected_files - actual_files:
            self.add("route-target-missing", f"payload/guidance/{name}")
        for name in actual_files - expected_files:
            self.add("guidance-unexpected", f"payload/guidance/{name}")
        for child in children:
            relative = f"payload/guidance/{child.name}"
            if not child.is_file() or child.is_symlink():
                self.add("file-type", relative)
            stem = child.name[:-3] if child.name.endswith(".md") else ""
            if not stem or not KEBAB_RE.fullmatch(stem):
                self.add("guidance-name", relative)

    def _inline_links(self, value: str, relative: str) -> list[tuple[str, str]]:
        if re.search(r"!\[[^]]*]\(", value) or re.search(r"^\s*\[[^]]+]:\s*\S+", value, re.MULTILINE):
            self.add("link-syntax", relative)
        if re.search(r"<[A-Za-z/][^>]*>", value):
            self.add("embedded-content", relative)
        return [(m.group(1), m.group(2)) for m in LINK_RE.finditer(value)]

    def _links(self) -> None:
        for relative, value in sorted(self.text.items()):
            for _, target in self._inline_links(value, relative):
                if target != target.strip() or any(c.isspace() for c in target):
                    self.add("link-target", relative)
                elif target.startswith("https://"):
                    continue
                elif ":" in target.split("/", 1)[0]:
                    self.add("link-scheme", relative)
                elif target.startswith("/"):
                    self.add("link-escape", relative)
                elif not _safe_path(target):
                    self.add("link-escape" if ".." in PurePosixPath(target).parts else "link-target", relative)
                else:
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
                    if not resolved.startswith("payload/"):
                        self.add("link-escape", relative)
                    elif resolved not in self.text:
                        self.add("link-broken", relative)
                    if relative.startswith("payload/guidance/"):
                        self.add("guidance-local-link", relative)

    def _index(self) -> None:
        value = self.text.get("payload/index.md")
        if value is None:
            return
        if len(value.encode()) > 1200 or sum(bool(line.strip()) for line in value.splitlines()) > 25:
            self.add("index-size", "payload/index.md")
        headings = [(len(m), title) for m, title in HEADING_RE.findall(value)]
        if sum(level == 1 for level, _ in headings) != 1:
            self.add("index-heading", "payload/index.md")
        links = self._inline_links(value, "payload/index.md")
        expected, actual = set(self.routes), set(links)
        if len(links) != len(actual):
            self.add("index-route-ambiguous", "payload/index.md")
        for _ in expected - actual:
            self.add("index-route-missing", "payload/index.md")
        for _ in actual - expected:
            self.add("index-route-ambiguous", "payload/index.md")

    def _front_matter(self, relative: str, value: str) -> tuple[dict[str, Any] | None, str]:
        if not value.startswith("---\n"):
            self.add("guidance-metadata", relative)
            return None, value
        closing = value.find("\n---\n", 4)
        if closing < 0:
            self.add("guidance-metadata", relative)
            return None, value
        try:
            metadata = json.loads(value[4:closing], object_pairs_hook=_unique_object)
        except (json.JSONDecodeError, DuplicateKeyError):
            self.add("provenance-malformed", relative)
            return None, value[closing + 5:]
        if not isinstance(metadata, dict):
            self.add("guidance-metadata", relative)
            return None, value[closing + 5:]
        return metadata, value[closing + 5:]

    def _guidance(self) -> None:
        for relative, expected_task in sorted((f"payload/{entry}", task) for task, entry in self.routes):
            value = self.text.get(relative)
            if value is None:
                continue
            metadata, body = self._front_matter(relative, value)
            if metadata is None:
                continue
            if set(metadata) != GUIDANCE_FIELDS:
                self.add("guidance-metadata", relative)
            task, title = metadata.get("task"), metadata.get("title")
            if task != expected_task:
                self.add("guidance-task", relative)
            if not isinstance(title, str) or not title.strip():
                self.add("guidance-title", relative)
            source_ids = self._provenance(relative, metadata.get("provenance"))
            headings = [(len(m), text) for m, text in HEADING_RE.findall(body)]
            h1 = [text for level, text in headings if level == 1]
            h2 = [text for level, text in headings if level == 2]
            if not isinstance(title, str) or h1 != [title]:
                self.add("guidance-heading", relative)
            if h2 != SECTIONS:
                self.add("guidance-sections", relative)
                continue
            sections = self._section_bodies(body)
            for section in SECTIONS:
                if not sections.get(section, "").strip():
                    self.add("guidance-section-empty", relative)
            if not NORMATIVE_RE.search(sections.get("Normative guidance", "")):
                self.add("guidance-normative", relative)
            provenance_body = sections.get("Source provenance", "")
            for source_id in source_ids:
                if source_id not in provenance_body:
                    self.add("provenance-reference", relative)

    def _provenance(self, relative: str, value: Any) -> list[str]:
        if not isinstance(value, list) or not value:
            self.add("provenance-malformed", relative)
            return []
        ids: list[str] = []
        for record in value:
            if not isinstance(record, dict) or set(record) != PROVENANCE_FIELDS:
                self.add("provenance-malformed", relative)
                continue
            if any(not isinstance(record.get(field), str) or not record[field].strip() for field in PROVENANCE_FIELDS):
                self.add("provenance-malformed", relative)
            source_id = record.get("sourceId")
            if isinstance(source_id, str):
                ids.append(source_id)
                if not KEBAB_RE.fullmatch(source_id):
                    self.add("provenance-malformed", relative)
            date = record.get("distilledAt")
            if isinstance(date, str):
                try:
                    if not DATE_RE.fullmatch(date):
                        raise ValueError
                    dt.date.fromisoformat(date)
                except ValueError:
                    self.add("provenance-malformed", relative)
        if len(ids) != len(set(ids)):
            self.add("provenance-malformed", relative)
        return ids

    @staticmethod
    def _section_bodies(body: str) -> dict[str, str]:
        matches = list(re.finditer(r"^##[ \t]+(.+?)[ \t]*$", body, re.MULTILINE))
        result: dict[str, str] = {}
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
            result[match.group(1)] = body[match.end():end]
        return result


def validate_bundle(bundle: Path | str) -> list[ValidationIssue]:
    return Validator(Path(bundle)).validate()
