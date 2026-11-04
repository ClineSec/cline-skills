#!/usr/bin/env python3
"""Helper for the tprm-review skill. Standard library only.

    tprm.py prepare --vendor NAME --docs DIR --out DIR [--policy PATH] [--previous DIR] [--allow-inside-docs]
    tprm.py capture --out DIR --id S001 --file SAVED_PAGE
    tprm.py check --out DIR
    tprm.py render --out DIR

`prepare` copies the operator's vendor documents into an output folder, extracts their text, and lists leads.
`capture` turns a public page or document the agent saved into text its quotes can be checked against. `check` reports
which documents still need a transcript and any problems in assessment.json. `render` checks every quote against the
documents and the saved research, and writes a report whose shape never changes.

Nothing here executes anything, reaches the network, or writes to the documents folder. Vendor documents are
untrusted input, so extraction has limits on size and decompression, and refuses XML that declares entities.

Exit codes: 0 success, 1 problems to correct, 2 refused or bad usage.
"""

from __future__ import annotations

import argparse
import base64
import bisect
import contextlib
import datetime
import hashlib
import html.parser
import io
import json
import os
import re
import shutil
import stat
import sys
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ElementTree
import zipfile
import zlib
from pathlib import Path
from typing import Any, Iterator

SCHEMA = 1
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_FILES = 500
MAX_TEXT_CHARS = 16 * 1024 * 1024
MAX_INFLATED_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_PDF_OBJECTS = 200000
MAX_PDF_PAGES = 5000
MAX_QUOTE_CHARS = 600
MIN_QUOTE_CHARS = 12
MAX_LEADS_PER_SOURCE = 40
MIN_PAGE_CHARS = 40
STALE_ASSURANCE_DAYS = 365
BRIDGE_AFTER_DAYS = 90
SHORT_PERIOD_DAYS = 180
MAX_REASONS = 6

OUTPUT_NAMES = {"manifest.json", "documents", "text", "policy", "transcripts", "research", "assessment.json", "report.md", "vendor-questions.md"}

TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".yaml", ".yml", ".eml", ".rtf", ".log"}
HTML_SUFFIXES = {".html", ".htm", ".xhtml", ".mhtml"}
OFFICE_SUFFIXES = {".docx", ".xlsx", ".pptx"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}

# Leads only. They start the search for text aimed at the assessor; the agent decides what each one means and
# looks past them, because a phrase list can never be the whole answer.
STEERING_TEXT = re.compile(
    r"\b(ai|llm|gpt|language model|chatbot|assistant|agent|copilot|automated|machine)[ -]?"
    r"(reader|reviewer|review|assessor|assessment|tool|system|model|assistant|agent|analysis|summar\w+)?s?\b"
    r"[^\n]{0,80}\b(should|must|shall|need not|do not|don'?t|may not|ignore|skip|omit|summari[sz]e|treat|report|rate|conclude)\b"
    r"|\b(ignore|disregard|forget|override)\b[^\n]{0,40}\b(previous|prior|above|earlier|system|instruction|prompt|finding|exception)"
    r"|\b(do not|don'?t|never|no need to|need not)\s+(report|flag|mention|raise|note|disclose|include)\b[^\n]{0,60}"
    r"\b(finding|exception|deviation|incident|breach|issue|weakness|vulnerabilit|discrepanc)"
    r"|\b(assessor|reviewer|auditor|evaluator)s?\b[^\n]{0,50}\b(should|must|need not|may skip|can skip)\b[^\n]{0,50}"
    r"\b(approve|pass|compliant|low[- ]risk|skip|ignore|without)\b"
    r"|\b(treat|mark|rate|classify|record)\b[^\n]{0,40}\b(as|vendor as)\b[^\n]{0,20}\b(compliant|approved|low[- ]risk|fully compliant|no findings)\b"
    r"|\b(system prompt|prompt injection|new instructions)\b",
    re.I,
)
INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0e-\x1f\x7f-\x9f­͏؜ᅟᅠ឴឵᠋-᠏​-‏"
    " -‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￻\U000e0000-\U000e0fff]"
)
HIDDEN_ANYWHERE = re.compile("[؜ᅟᅠ‪-‮⁦-⁩ㅤﾠ\U000e0000-\U000e0fff]")
CREDENTIAL_SHAPES = re.compile(
    r"(?<![A-Za-z0-9_-])(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)"
    r"|(?s:-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z))"
)
PAGE_MARKER = re.compile(r"^\[page (\d+)\]$")
QUOTE_FOLD = str.maketrans({"‘": "'", "’": "'", "‚": "'", "“": '"', "”": '"', "„": '"',
                            "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-"})

VERDICTS = ("approve", "approve-with-conditions", "reject", "insufficient-evidence")
VERDICT_LABEL = {"approve": "Approve", "approve-with-conditions": "Approve with conditions", "reject": "Reject",
                 "insufficient-evidence": "Insufficient evidence to decide"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
RISK_LEVELS = ("critical", "high", "medium", "low")
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
DATA_SENSITIVITY = {"restricted": 3, "confidential": 2, "internal": 1, "public": 0}
ACCESS_LEVELS = {"privileged": 3, "write": 2, "read": 1, "none": 0}
BUSINESS_IMPACT = {"critical": 3, "high": 2, "medium": 1, "low": 0}
SUBSERVICE_METHODS = ("carve-out", "inclusive", "none", "not-stated", "not-applicable")
SUBSERVICE_LABEL = {"carve-out": "Carve-out", "inclusive": "Inclusive", "none": "None used", "not-stated": "Not stated", "not-applicable": "Not applicable"}
COVERS_PRODUCT = ("yes", "partly", "no", "not-stated")
CONFIDENCE = ("confirmed", "probable")
DISCREPANCY_KINDS = ("document-vs-document", "within-document", "document-vs-public", "public-vs-public")
KIND_LABEL = {"document-vs-document": "Between documents", "within-document": "Within one document",
              "document-vs-public": "Document against public record", "public-vs-public": "Between public sources"}
POSTURE = (
    ("data-use", "What may the vendor do with our data, including training models?"),
    ("data-location", "Where is our data stored and processed, for how long, and how is it deleted?"),
    ("ai-use", "What AI does the product use, who sees or keeps our data because of it, and how are its actions and inputs contained?"),
    ("access", "Who can reach our data, on our side and the vendor's, and is that visible to us?"),
    ("protection", "How is our data protected from compromise, and how is the product built and tested?"),
    ("assurance", "Who independently checked these claims, for what scope and period, and what did they find?"),
    ("incidents", "What happens when something goes wrong, and how soon would we know?"),
    ("resilience", "Can the service keep running or recover, and what does it commit to?"),
    ("exit-and-recourse", "What rights do we have over changes, audits, liability, and leaving?"),
)
POSTURE_IDS = {key for key, _question in POSTURE}
POSTURE_STATUS = ("committed", "partial", "silent", "contradicted", "not-applicable")
STATUS_LABEL = {"committed": "Committed", "partial": "Partial", "silent": "Silent", "contradicted": "Contradicted",
                "not-applicable": "Not applicable"}
PROFILE_TOPICS = (
    ("legal-entity", "Legal entity"),
    ("jurisdiction", "Headquarters and jurisdiction"),
    ("ownership", "Ownership and funding"),
    ("history", "Operating history"),
    ("scale", "Size and customers"),
    ("financial-condition", "Financial condition"),
    ("leadership", "Security and company leadership"),
    ("foreign-influence", "Foreign ownership, control, or influence"),
    ("regulatory-standing", "Licenses, sanctions, and regulatory standing"),
    ("insurance", "Insurance coverage"),
)
PROFILE_IDS = {key for key, _label in PROFILE_TOPICS}
OPINIONS = ("unqualified", "qualified", "adverse", "disclaimer", "certificate-issued", "self-attested", "not-stated")
OPINION_LABEL = {"unqualified": "Unqualified", "qualified": "Qualified", "adverse": "Adverse", "disclaimer": "Disclaimer",
                 "certificate-issued": "Certificate issued", "self-attested": "Self-attested", "not-stated": "Not stated"}
RECORD_KINDS = ("security-incident", "regulatory", "litigation", "corporate-change", "service-change", "other")
RECORD_STANDING = ("established", "reported", "alleged", "vendor-stated")
SOURCE_KINDS = ("regulator-or-court", "official-register", "vendor-published", "independent-press", "research-or-analyst",
                "community", "other")
# A vendor's own page isn't here: what only the vendor says is vendor-stated.
PRIMARY_KINDS = {"regulator-or-court", "official-register"}
CLAIM_RESULTS = ("corroborated", "contradicted", "unverifiable")
RESEARCH_STATUS = ("full", "partial", "none")
POLICY_STATUS = ("met", "not-met", "unknown")

TOP_KEYS = {"engagement", "summary", "verdict", "steering", "dismissed_leads", "documents", "data_classification",
            "vendor_profile", "posture", "assurance", "subprocessors", "subprocessor_note", "public_sources", "research",
            "claims", "public_record", "discrepancies", "gaps", "policy", "questions_for_vendor", "not_checked"}
ENGAGEMENT_KEYS = {"product", "use", "connection", "data_in_scope", "data_sensitivity", "access", "business_impact", "risk_reason"}
VERDICT_KEYS = {"recommendation", "reasons", "conditions", "reassess"}
CONDITION_KEYS = {"action", "addresses", "owner", "due"}
REASSESS_KEYS = {"by", "triggers"}
REASON_KEYS = {"text", "refs", "cites"}
STEERING_KEYS = {"cite", "effect", "handled", "leads"}
DOC_KEYS = {"source", "kind", "issued", "covers", "note"}
CLASS_KEYS = {"data", "class", "basis"}
PROFILE_KEYS = {"topic", "finding", "cites"}
POSTURE_KEYS = {"id", "question", "status", "answer", "cites", "looked_in"}
ASSURANCE_KEYS = {"kind", "issuer", "subject_entity", "scope", "covers_product", "categories", "period_start", "period_end", "opinion",
                  "exceptions", "subservice_method", "carve_outs", "user_controls", "bridge_letter", "auditor_check", "cites"}
ASSURANCE_OPTIONAL = {"carve_outs", "bridge_letter"}
EXCEPTION_KEYS = {"control", "finding", "relevance", "response"}
USER_CONTROL_KEYS = {"control", "owner"}
SUBPROCESSOR_KEYS = {"name", "function", "data", "location", "model_provider", "cites"}
PUBLIC_SOURCE_KEYS = {"id", "url", "title", "publisher", "published", "retrieved", "kind", "captured"}
RESEARCH_KEYS = {"status", "note", "log"}
LOG_KEYS = {"question", "where_looked", "result"}
CLAIM_KEYS = {"claim", "cites", "tested_against", "result", "evidence_cites", "discrepancy"}
RECORD_KEYS = {"event", "date", "kind", "standing", "relevance", "cites"}
DISCREPANCY_KEYS = {"id", "title", "kind", "severity", "confidence", "side_a", "side_b", "why", "ask"}
SIDE_KEYS = {"says", "cite"}
GAP_KEYS = {"id", "topic", "severity", "looked_in", "why", "ask"}
POLICY_KEYS = {"requirement", "policy_cite", "status", "basis", "cites"}
CITE_KEYS = {"source", "quote", "credential"}


def write_exact(path: Path, text: str, errors: str = "strict") -> None:
    """Write UTF-8 with no newline translation: on Windows, text mode would corrupt Git's files and shift line numbers."""
    path.write_bytes(text.encode("utf-8", errors))


class Refused(Exception):
    """The helper will not proceed, and the reason is for the operator."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare, check, and render a third-party risk review.")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--vendor", required=True, help="The vendor's name, as the operator gave it.")
    prepare.add_argument("--docs", required=True, help="Folder holding the documents the operator downloaded.")
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--policy", help="File or folder holding the organization's own policy.")
    prepare.add_argument("--previous", help="Output folder of an earlier review of this vendor.")
    prepare.add_argument("--date", help="Assessment date, YYYY-MM-DD. Default: today.")
    prepare.add_argument("--allow-inside-docs", action="store_true")
    check = commands.add_parser("check")
    check.add_argument("--out", required=True)
    render = commands.add_parser("render")
    render.add_argument("--out", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("--out", required=True)
    capture.add_argument("--id", required=True, help="The public source's id, such as S001.")
    capture.add_argument("--file", required=True, help="A page or document you saved, in any format prepare can read.")
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            return cmd_prepare(args)
        if args.command == "capture":
            return cmd_capture(args)
        return cmd_check(args) if args.command == "check" else cmd_render(args)
    except Refused as refusal:
        print(f"Refused: {refusal}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError) as error:
        print(f"Refused: couldn't complete this because of a file problem: {error}", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------------------- prepare


def cmd_prepare(args: argparse.Namespace) -> int:
    docs = Path(args.docs).expanduser()
    if not docs.is_absolute():
        raise Refused("--docs must be an absolute path.")
    docs = docs.resolve()
    if not docs.is_dir():
        raise Refused(f"{docs} is not a folder. Ask the operator where the downloaded documents are.")
    vendor = re.sub(r"\s+", " ", args.vendor).strip()
    if not vendor:
        raise Refused("--vendor can't be empty.")
    assessed = parse_date(args.date) if args.date else datetime.date.today()
    if assessed is None:
        raise Refused("--date must be YYYY-MM-DD.")
    out = Path(args.out).expanduser().resolve()
    inside = is_within(Path.cwd().resolve(), docs)
    if inside and not args.allow_inside_docs:
        raise Refused(
            "this session is inside the documents folder, so it may already have loaded instruction files placed "
            "there. Start a new session in a different folder."
        )
    if is_within(out, docs):
        raise Refused("--out must be outside the documents folder, so nothing is written to it.")
    if is_within(docs, out):
        raise Refused("--out must not contain the documents folder.")

    previous = load_previous(Path(args.previous).expanduser().resolve(), out) if args.previous else None
    policy_path = Path(args.policy).expanduser().resolve() if args.policy else find_session_policy()
    if policy_path is not None and not policy_path.exists():
        raise Refused(f"{policy_path} doesn't exist. Check the policy path.")
    if policy_path is not None and (is_within(out, policy_path) or is_within(policy_path, out)):
        raise Refused("--out and the policy location must not contain each other.")

    prepare_output(out)
    skipped: dict[str, list[str]] = {}
    sources = ingest(docs, out, "D", "documents", "text", skipped)
    if not sources:
        shutil.rmtree(out / "documents", ignore_errors=True)
        shutil.rmtree(out / "text", ignore_errors=True)
        raise Refused(f"{docs} holds no documents this helper can take. Ask the operator to check the folder.")
    policy = None
    if policy_path is not None:
        policy_skipped: dict[str, list[str]] = {}
        policy_sources = ingest_policy(policy_path, out, policy_skipped)
        if policy_sources:
            policy = {"sources": policy_sources, "index": policy_index(policy_sources), "skipped": policy_skipped}
    (out / "transcripts").mkdir()
    (out / "research").mkdir()

    all_sources_found = sources + (policy["sources"] if policy else [])
    leads = []
    for source in all_sources_found:
        if source["text_status"] != "needs-transcript":
            leads += find_leads(source["id"], out / source["text"])
    for root in ("documents", "text", "policy"):
        if (out / root).is_dir():
            make_read_only(out / root)
    limits = [
        "Only the supplied documents and public sources were read. The vendor was not contacted, and none of its "
        "systems or products were tested, so nothing here confirms how the service behaves in practice.",
        "Documents were taken as supplied. The review can't tell whether they are the vendor's latest versions "
        "unless their dates or public copies show it.",
    ]
    limits.extend(skip_limits(skipped))
    for source in all_sources_found:
        if sum(lead["source"] == source["id"] for lead in leads) >= MAX_LEADS_PER_SOURCE:
            limits.append(f"The steering search stopped listing leads in {source['name']} at {MAX_LEADS_PER_SOURCE}, so more may exist. "
                          "A document with this many deserves a close read.")
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": "tprm-review",
        "vendor": vendor,
        "assessed": assessed.isoformat(),
        "docs_name": docs.name,
        "inside_docs": inside,
        "digest": digest_tree(out, ("documents", "text", "policy")),
        "sources": sources,
        "leads": leads,
        "skipped": skipped,
        "limits": limits,
    }
    if policy:
        manifest["policy"] = policy
    if previous:
        manifest["previous"] = previous
    write_json(out / "manifest.json", manifest)

    needing = [source for source in all_sources_found if source["text_status"] == "needs-transcript"]
    partial = [source for source in all_sources_found if source.get("pages_without_text")]
    print(f"Prepared {vendor}: {len(sources)} document(s), {len(leads)} lead(s).")
    print(f"Read the extracted text: {out / 'text'}")
    for source in needing:
        print(f"Needs a transcript: {source['id']} {source['name']} ({source['text_note']})")
    for source in partial:
        print(f"Pages with no extractable text: {source['id']} {source['name']} {source['pages_without_text']}")
    for reason, paths in sorted(skipped.items()):
        print(f"Not taken, {reason}: {preview(paths)}")
    return 0


def parse_date(value: Any) -> datetime.date | None:
    if not isinstance(value, str):
        return None
    with contextlib.suppress(ValueError):
        return datetime.date.fromisoformat(value)
    return None


def is_within(path: Path, root: Path) -> bool:
    """Compare by file identity, because paths that differ in case can name one directory."""
    for candidate in (path, *path.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def prepare_output(out: Path) -> None:
    if out.is_symlink() or (out.exists() and not out.is_dir()):
        raise Refused(f"{out} must be a real directory.")
    out.mkdir(parents=True, exist_ok=True)
    unexpected = [child.name for child in out.iterdir() if child.name not in OUTPUT_NAMES]
    if unexpected:
        raise Refused(f"{out} holds files this helper didn't write ({unexpected[0]}). Choose an empty directory.")
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


def digest_tree(out: Path, roots: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    for root in roots:
        base = out / root
        if not base.is_dir():
            continue
        for directory, subdirectories, files in os.walk(base):
            subdirectories.sort()
            for name in sorted(files):
                path = Path(directory) / name
                relative = path.relative_to(out).as_posix()
                hasher.update(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n".encode("utf-8", "surrogateescape"))
    return hasher.hexdigest()


def walk_input(root: Path, skipped: dict[str, list[str]]) -> Iterator[tuple[str, Path]]:
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        current = Path(directory)
        kept = []
        for name in sorted(subdirectories):
            relative = (current / name).relative_to(root).as_posix()
            if (current / name).is_symlink():
                skipped.setdefault("a link, which wasn't followed", []).append(relative)
            elif name.startswith("."):
                skipped.setdefault("a hidden folder", []).append(relative)
            else:
                kept.append(name)
        subdirectories[:] = kept
        for name in sorted(files):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.setdefault("a link, which wasn't followed", []).append(relative)
            elif name.startswith("."):
                skipped.setdefault("a hidden file", []).append(relative)
            elif not path.is_file():
                skipped.setdefault("not a regular file", []).append(relative)
            else:
                yield relative, path


def ingest(docs: Path, out: Path, prefix: str, originals: str, texts: str, skipped: dict[str, list[str]]) -> list[dict[str, Any]]:
    (out / originals).mkdir(parents=True, exist_ok=True)
    (out / texts).mkdir(parents=True, exist_ok=True)
    sources: list[dict[str, Any]] = []
    total = 0
    seen: dict[str, str] = {}
    for relative, path in walk_input(docs, skipped):
        size = path.stat().st_size
        suffix = path.suffix.lower()
        if suffix in ARCHIVE_SUFFIXES:
            skipped.setdefault("an archive. Ask the operator to unpack it", []).append(relative)
            continue
        if size > MAX_FILE_BYTES:
            skipped.setdefault("larger than the file limit", []).append(relative)
            continue
        if size == 0:
            skipped.setdefault("empty", []).append(relative)
            continue
        if len(sources) >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
            skipped.setdefault("past the total limit", []).append(relative)
            continue
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:
            skipped.setdefault(f"an exact copy of another document ({seen[digest]})", []).append(relative)
            continue
        seen[digest] = relative
        total += size
        number = f"{prefix}{len(sources) + 1:03d}"
        # Flat, numbered names, so no copied file can be picked up as an agent's instructions or configuration.
        (out / originals / f"{number}.original").write_bytes(raw)
        extraction = extract_text(raw, suffix)
        text_path = out / texts / f"{number}.txt"
        write_exact(text_path, extraction.text, errors="replace")
        source: dict[str, Any] = {
            "id": number,
            "name": relative,
            "sha256": digest,
            "bytes": size,
            "original": f"{originals}/{number}.original",
            "text": f"{texts}/{number}.txt",
            "text_status": extraction.status,
            "text_note": extraction.note,
            "pages": extraction.pages,
        }
        if extraction.empty_pages:
            source["pages_without_text"] = extraction.empty_pages
        sources.append(source)
    return sources


def find_session_policy() -> Path | None:
    """An organization's routed guidance beside the session is required reading when it is present."""
    index = Path.cwd() / "security" / "PolicyRelay" / "index.md"
    with contextlib.suppress(OSError):
        if index.is_file() and not index.is_symlink():
            return index.parent
    return None


def ingest_policy(path: Path, out: Path, skipped: dict[str, list[str]]) -> list[dict[str, Any]]:
    if path.is_dir():
        routed = path / "security" / "PolicyRelay"
        root = routed if (routed / "index.md").is_file() else path
        return ingest(root, out, "P", "policy/originals", "policy/text", skipped)
    scratch = out / "policy" / "single"
    scratch.mkdir(parents=True)
    shutil.copyfile(path, scratch / path.name)
    try:
        return ingest(scratch, out, "P", "policy/originals", "policy/text", skipped)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def policy_index(sources: list[dict[str, Any]]) -> str | None:
    for source in sources:
        if source["name"].lower() == "index.md":
            return source["id"]
    return None


def load_previous(path: Path, out: Path) -> dict[str, Any]:
    if os.path.exists(out) and path == out:
        raise Refused("--previous must be a different folder from --out.")
    manifest_path, assessment_path = path / "manifest.json", path / "assessment.json"
    if not manifest_path.is_file() or not assessment_path.is_file():
        raise Refused(f"{path} isn't the output of an earlier review: it needs manifest.json and assessment.json.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
        subprocessors = [
            {"name": str(item["name"]), "model_provider": bool(item.get("model_provider"))}
            for item in assessment["subprocessors"]
        ]
        return {
            "assessed": str(manifest["assessed"]),
            "vendor": str(manifest["vendor"]),
            "recommendation": str(assessment["verdict"]["recommendation"]),
            "subprocessors": subprocessors,
        }
    except (ValueError, KeyError, TypeError) as error:
        raise Refused(f"couldn't read the earlier review in {path}: {error}") from None


def find_leads(source: str, text_path: Path) -> list[dict[str, Any]]:
    found = []
    text = text_path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.split("\n"), 1):
        if HIDDEN_ANYWHERE.search(line):
            kind = "hidden-text"
        elif STEERING_TEXT.search(line):
            kind = "instruction-text"
        else:
            continue
        found.append({"id": f"{source}:{number}", "source": source, "line": number, "kind": kind, "text": display_line(line)})
        if len(found) >= MAX_LEADS_PER_SOURCE:
            break
    return found


def display_line(line: str) -> str:
    return visible(mask(re.sub(r"\s+", " ", line).strip()))[:240]


def visible(text: str) -> str:
    return INVISIBLE.sub(lambda match: f"<U+{ord(match.group()):04X}>", text)


def mask(text: str) -> str:
    return CREDENTIAL_SHAPES.sub("[credential withheld]", text)


def preview(paths: list[str], limit: int = 8) -> str:
    return ", ".join(paths[:limit]) + (f", and {len(paths) - limit} more" if len(paths) > limit else "")


def skip_limits(skipped: dict[str, list[str]]) -> list[str]:
    return [f"Not read: {preview(paths)}. Reason: {reason}." for reason, paths in sorted(skipped.items())]


def write_json(path: Path, value: Any) -> None:
    write_exact(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------------------- extraction


class Extraction:
    def __init__(self, text: str, status: str = "extracted", note: str = "", pages: int | None = None,
                 empty_pages: list[int] | None = None) -> None:
        self.text = text
        self.status = status
        self.note = note
        self.pages = pages
        self.empty_pages = empty_pages or []


NEEDS = "needs-transcript"


def extract_text(raw: bytes, suffix: str) -> Extraction:
    try:
        if raw[:5] == b"%PDF-" or suffix == ".pdf":
            return extract_pdf(raw)
        if suffix in OFFICE_SUFFIXES:
            return extract_office(raw, suffix)
        if suffix in HTML_SUFFIXES:
            return checked_text(extract_html(decode_text(raw)))
        if suffix in TEXT_SUFFIXES:
            return checked_text(decode_text(raw))
    except (zipfile.BadZipFile, KeyError, ValueError, ElementTree.ParseError, zlib.error, RecursionError, IndexError) as error:
        return Extraction("", NEEDS, f"couldn't be read automatically: {type(error).__name__}")
    if b"\x00" not in raw[:4096]:
        with contextlib.suppress(UnicodeDecodeError):
            return checked_text(raw.decode("utf-8"))
    return Extraction("", NEEDS, f"{suffix or 'this file type'} has no automatic text extraction")


def checked_text(text: str) -> Extraction:
    text = text[:MAX_TEXT_CHARS]
    if not text.strip():
        return Extraction("", NEEDS, "no text found")
    return Extraction(text)


def decode_text(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig",):
        with contextlib.suppress(UnicodeError):
            return raw.decode(encoding)
    return raw.decode("latin-1")


class HtmlText(html.parser.HTMLParser):
    """Keep what a reader sees and what is hidden from them. Hidden text is where steering goes."""

    BLOCK = {"p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "table", "ul", "ol",
             "header", "footer", "blockquote", "dd", "dt", "pre"}
    SKIP = {"script", "style"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self.skip_depth += 1
        if tag in self.BLOCK or tag == "td" or tag == "th":
            self.parts.append("\n" if tag not in ("td", "th") else " | ")
        for name, value in attrs:
            if name in ("alt", "title", "aria-label") and value and value.strip():
                self.parts.append(f" [{name}: {value.strip()}] ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self.skip_depth:
            self.skip_depth -= 1
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth:
            self.parts.append(data)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.parts.append(f"\n[hidden comment] {data.strip()}\n")


def extract_html(text: str) -> str:
    parser = HtmlText()
    parser.feed(text)
    parser.close()
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in "".join(parser.parts).split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


def read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
        raise ValueError("member too large")
    with archive.open(info) as handle:
        data = handle.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
    if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
        raise ValueError("member too large")
    return data


def parse_xml(data: bytes) -> ElementTree.Element:
    # Office files are vendor-controlled input, and none of them has a reason to declare entities.
    if b"<!DOCTYPE" in data[:4096].upper() or b"<!ENTITY" in data.upper():
        raise ValueError("XML declares entities")
    return ElementTree.fromstring(data)


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def office_paragraphs(root: ElementTree.Element, paragraph: str, run: str) -> list[str]:
    lines = []
    for element in root.iter():
        if local(element.tag) == paragraph:
            parts = []
            for child in element.iter():
                name = local(child.tag)
                if name == run and child.text:
                    parts.append(child.text)
                elif name == "tab":
                    parts.append(" ")
                elif name == "instrText" and child.text:
                    parts.append(f" [field: {child.text.strip()}] ")
            lines.append("".join(parts))
    return lines


def extract_office(raw: bytes, suffix: str) -> Extraction:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        if suffix == ".docx":
            lines: list[str] = []
            parts = ["word/document.xml"] + sorted(
                name for name in names if re.fullmatch(r"word/(footnotes|endnotes|comments|header\d*|footer\d*)\.xml", name))
            for part in parts:
                if part in names:
                    section = office_paragraphs(parse_xml(read_member(archive, part)), "p", "t")
                    if part != "word/document.xml" and any(line.strip() for line in section):
                        lines.append(f"[{part.split('/')[-1].rsplit('.', 1)[0]}]")
                    lines += section
            return checked_text("\n".join(lines) + "\n")
        if suffix == ".pptx":
            lines = []
            slides = sorted((name for name in names if re.fullmatch(r"ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml", name)),
                            key=lambda name: ("notes" in name, int(re.search(r"(\d+)\.xml$", name).group(1))))  # type: ignore[union-attr]
            for name in slides:
                label = "notes" if "notes" in name else "slide"
                number = re.search(r"(\d+)[.]xml$", name).group(1)  # type: ignore[union-attr]
                lines.append(f"[{label} {number}]")
                lines += office_paragraphs(parse_xml(read_member(archive, name)), "p", "t")
            return checked_text("\n".join(lines) + "\n")
        return checked_text(extract_xlsx(archive, names))


def extract_xlsx(archive: zipfile.ZipFile, names: list[str]) -> str:
    shared: list[str] = []
    if "xl/sharedStrings.xml" in names:
        root = parse_xml(read_member(archive, "xl/sharedStrings.xml"))
        for item in root:
            shared.append("".join(node.text or "" for node in item.iter() if local(node.tag) == "t"))
    labels: dict[str, str] = {}
    if "xl/workbook.xml" in names:
        for element in parse_xml(read_member(archive, "xl/workbook.xml")).iter():
            if local(element.tag) == "sheet":
                state = element.get("state", "visible")
                rid = next((value for key, value in element.attrib.items() if key.endswith("}id")), "")
                labels[rid] = element.get("name", "") + ("" if state == "visible" else f" (hidden sheet, {state})")
    targets: dict[str, str] = {}
    if "xl/_rels/workbook.xml.rels" in names:
        for element in parse_xml(read_member(archive, "xl/_rels/workbook.xml.rels")):
            target = element.get("Target", "").lstrip("/")
            targets[target if target.startswith("xl/") else f"xl/{target}"] = labels.get(element.get("Id", ""), "")
    lines: list[str] = []
    sheets = sorted((name for name in names if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)),
                    key=lambda name: int(re.search(r"(\d+)\.xml$", name).group(1)))  # type: ignore[union-attr]
    for name in sheets:
        lines.append(f"[sheet {targets.get(name) or name.rsplit('/', 1)[-1]}]")
        for row in parse_xml(read_member(archive, name)).iter():
            if local(row.tag) != "row":
                continue
            cells = []
            for cell in row:
                if local(cell.tag) != "c":
                    continue
                kind = cell.get("t", "")
                value = ""
                for node in cell.iter():
                    if local(node.tag) == "v" and node.text is not None:
                        value = node.text
                        if kind == "s" and value.isdigit() and int(value) < len(shared):
                            value = shared[int(value)]
                    elif local(node.tag) == "t" and kind == "inlineStr" and node.text:
                        value = node.text
                if value.strip():
                    cells.append(value.strip())
            if cells:
                lines.append(" | ".join(cells))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------- PDF


PDF_OBJECT = re.compile(rb"(?<![0-9])(\d{1,10})\s+(\d{1,5})\s+obj\b")
PDF_REF = re.compile(rb"(\d{1,10})\s+\d{1,5}\s+R\b")
PDF_EOL = re.compile(rb"[\r\n]")
PDF_NAME = re.compile(rb"/[^\s/<>\[\]()%]*")
PDF_WORD = re.compile(rb"[^\s/<>\[\]()%]+")
PDF_NUMBER = re.compile(rb"[-+]?\d*\.?\d+")
PDF_INLINE_END = re.compile(rb"\sEI(?=\s|$)")


class Inflated(Exception):
    """Decompression went past the budget for one PDF."""


class PdfReader:
    """Enough of PDF to read the text of ordinary documents. Anything it can't read becomes a transcript request."""

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.objects: dict[int, tuple[bytes, bytes | None]] = {}
        self.inflated_total = 0
        self.parse_objects()

    def parse_objects(self) -> None:
        raw = self.raw
        for match in PDF_OBJECT.finditer(raw):
            if len(self.objects) >= MAX_PDF_OBJECTS:
                break
            number = int(match.group(1))
            start = match.end()
            stream_at = raw.find(b"stream", start)
            end_at = raw.find(b"endobj", start)
            if end_at < 0:
                end_at = len(raw)
            if 0 <= stream_at < end_at or (stream_at >= 0 and end_at == len(raw)):
                head = raw[start:stream_at]
                body_start = stream_at + 6
                if raw[body_start:body_start + 2] == b"\r\n":
                    body_start += 2
                elif raw[body_start:body_start + 1] in (b"\n", b"\r"):
                    body_start += 1
                length = self.declared_length(head)
                body = None
                if length is not None and raw[body_start + length:body_start + length + 32].lstrip()[:9] == b"endstream":
                    body = raw[body_start:body_start + length]
                else:
                    stop = raw.find(b"endstream", body_start)
                    if stop >= 0:
                        body = raw[body_start:stop].rstrip(b"\r\n")
                self.objects[number] = (head, body)
            else:
                self.objects[number] = (raw[start:end_at], None)
        for number, (head, body) in list(self.objects.items()):
            if body is not None and re.search(rb"/Type\s*/ObjStm\b", head):
                self.expand_object_stream(head, body)

    def declared_length(self, head: bytes) -> int | None:
        match = re.search(rb"/Length\s+(\d+)(\s+\d+\s+R)?", head)
        if not match:
            return None
        if match.group(2):
            target = self.raw_object_int(int(match.group(1)))
            return target
        return int(match.group(1))

    def raw_object_int(self, number: int) -> int | None:
        match = re.search(rb"(?<![0-9])%d\s+\d+\s+obj\s+(\d+)" % number, self.raw)
        return int(match.group(1)) if match else None

    def expand_object_stream(self, head: bytes, body: bytes) -> None:
        count = re.search(rb"/N\s+(\d+)", head)
        first = re.search(rb"/First\s+(\d+)", head)
        if not count or not first:
            return
        data = self.decode_stream(head, body)
        if data is None:
            return
        offset = int(first.group(1))
        numbers = re.findall(rb"\d+", data[:offset])
        for index in range(min(int(count.group(1)), len(numbers) // 2)):
            number, start = int(numbers[index * 2]), int(numbers[index * 2 + 1])
            stop = int(numbers[index * 2 + 3]) if index * 2 + 3 < len(numbers) else len(data) - offset
            # A later object in the file replaces an earlier one, so keep what's already been parsed from the body.
            if number not in self.objects or self.objects[number][1] is None:
                self.objects[number] = (data[offset + start:offset + stop], None)

    def decode_stream(self, head: bytes, body: bytes) -> bytes | None:
        filters = re.findall(rb"/(FlateDecode|Fl|ASCIIHexDecode|AHx|ASCII85Decode|A85|LZWDecode|LZW|RunLengthDecode|RL|DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode|Crypt)\b",
                             self.filter_section(head))
        data = body
        for name in filters:
            if name in (b"FlateDecode", b"Fl"):
                data = self.inflate(data)
            elif name in (b"ASCIIHexDecode", b"AHx"):
                cleaned = re.sub(rb"[^0-9A-Fa-f]", b"", data.split(b">")[0])
                data = bytes.fromhex((cleaned + (b"0" if len(cleaned) % 2 else b"")).decode("ascii"))
            elif name in (b"ASCII85Decode", b"A85"):
                data = base64.a85decode(data.split(b"~>")[0].strip(), ignorechars=b" \t\r\n\x00\x0c")
            else:
                return None
        predictor = re.search(rb"/Predictor\s+(\d+)", head)
        if predictor and int(predictor.group(1)) >= 10:
            columns = re.search(rb"/Columns\s+(\d+)", head)
            data = undo_png_predictor(data, int(columns.group(1)) if columns else 1)
        return data

    def filter_section(self, head: bytes) -> bytes:
        match = re.search(rb"/Filter\s*(\[[^\]]*\]|/\w+)", head)
        return match.group(1) if match else b""

    def inflate(self, data: bytes) -> bytes:
        budget = MAX_INFLATED_BYTES - self.inflated_total
        if budget <= 0:
            raise Inflated
        engine = zlib.decompressobj()
        try:
            output = engine.decompress(data, budget + 1)
        except zlib.error:
            # Some producers truncate or pad streams. Take what inflates, and let the quality check judge it.
            engine = zlib.decompressobj()
            output = b""
            with contextlib.suppress(zlib.error):
                for index in range(0, len(data), 4096):
                    output += engine.decompress(data[index:index + 4096], budget + 1 - len(output))
                    if len(output) > budget:
                        break
        if len(output) > budget:
            raise Inflated
        self.inflated_total += len(output)
        return output

    def dictionary(self, number: int) -> bytes:
        entry = self.objects.get(number)
        return entry[0] if entry else b""

    def stream(self, number: int) -> bytes | None:
        entry = self.objects.get(number)
        if not entry or entry[1] is None:
            return None
        return self.decode_stream(entry[0], entry[1])

    def is_encrypted(self) -> bool:
        return bool(re.search(rb"/Encrypt\s+(\d+\s+\d+\s+R|<<)", self.raw[-65536:])) or any(
            b"/Encrypt" in head and b"/Root" in head for head, _body in self.objects.values())

    def pages(self) -> list[int]:
        root = None
        for number, (head, _body) in self.objects.items():
            if re.search(rb"/Type\s*/Catalog\b", head):
                root = number
        ordered: list[int] = []
        if root is not None:
            match = re.search(rb"/Pages\s+(\d+)\s+\d+\s+R", self.dictionary(root))
            if match:
                self.walk_pages(int(match.group(1)), ordered, set())
        if not ordered:
            ordered = [number for number, (head, _body) in sorted(self.objects.items())
                       if re.search(rb"/Type\s*/Page\b(?!s)", head)]
        return ordered[:MAX_PDF_PAGES]

    def walk_pages(self, number: int, ordered: list[int], visited: set[int]) -> None:
        if number in visited or len(ordered) >= MAX_PDF_PAGES:
            return
        visited.add(number)
        head = self.dictionary(number)
        kids = re.search(rb"/Kids\s*\[([^\]]*)\]", head)
        if kids is None:
            reference = re.search(rb"/Kids\s+(\d+)\s+\d+\s+R", head)
            if reference:
                kids_body = self.dictionary(int(reference.group(1)))
                kids = re.search(rb"\[([^\]]*)\]", kids_body)
        if kids is not None and re.search(rb"/Type\s*/Pages\b", head):
            for reference in PDF_REF.finditer(kids.group(1)):
                self.walk_pages(int(reference.group(1)), ordered, visited)
        elif re.search(rb"/Type\s*/Page\b", head):
            ordered.append(number)

    def inherited(self, page: int, key: bytes) -> bytes | None:
        """The value's bytes for a page attribute, walking up the page tree."""
        number: int | None = page
        hops = 0
        while number is not None and hops < 64:
            head = self.dictionary(number)
            value = dictionary_value(head, key)
            if value is not None:
                return value
            parent = re.search(rb"/Parent\s+(\d+)\s+\d+\s+R", head)
            number = int(parent.group(1)) if parent else None
            hops += 1
        return None

    def resolve(self, value: bytes) -> bytes:
        match = re.fullmatch(rb"\s*(\d+)\s+\d+\s+R\s*", value)
        return self.dictionary(int(match.group(1))) if match else value

    def resolve_array(self, value: bytes) -> bytes:
        """An array may sit behind a reference, as its own object with no dictionary."""
        return self.resolve(value)

    def page_fonts(self, page: int) -> dict[bytes, "PdfFont"]:
        resources = self.inherited(page, b"Resources")
        if resources is None:
            return {}
        fonts = dictionary_value(self.resolve(resources), b"Font")
        if fonts is None:
            return {}
        found = {}
        for name, number in re.findall(rb"/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R", self.resolve(fonts)):
            found[name] = self.font(int(number))
        return found

    def font(self, number: int) -> "PdfFont":
        cached = getattr(self, "_fonts", None)
        if cached is None:
            cached = self._fonts = {}
        if number not in cached:
            cached[number] = PdfFont(self, self.dictionary(number))
        return cached[number]

    def page_text(self, page: int) -> str:
        contents = self.inherited(page, b"Contents")
        if contents is None:
            return ""
        chunks: list[bytes] = []
        for match in PDF_REF.finditer(contents):
            chunk = self.stream(int(match.group(1)))
            if chunk:
                chunks.append(chunk)
        if not chunks and contents.strip().startswith(b"["):
            return ""
        return render_content(b"\n".join(chunks), self.page_fonts(page))


def dictionary_value(head: bytes, key: bytes) -> bytes | None:
    """The bytes of one dictionary value at the top level of head, tracking nesting so inner keys don't match."""
    depth = 0
    index = 0
    size = len(head)
    while index < size:
        byte = head[index:index + 2]
        if byte == b"<<":
            depth += 1
            index += 2
            continue
        if byte == b">>":
            depth -= 1
            index += 2
            continue
        char = head[index:index + 1]
        if char == b"(":
            index = skip_string(head, index)
            continue
        if char == b"/" and depth <= 1:
            end = index + 1
            while end < size and head[end] not in b" \t\r\n\f\x00()<>[]{}/%":
                end += 1
            if head[index + 1:end] == key:
                return read_value(head, end)
            index = end
            continue
        index += 1
    return None


def skip_string(data: bytes, index: int) -> int:
    depth = 0
    size = len(data)
    while index < size:
        char = data[index]
        if char == 0x5c:
            index += 2
            continue
        if char == 0x28:
            depth += 1
        elif char == 0x29:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return size


def read_value(head: bytes, index: int) -> bytes:
    size = len(head)
    while index < size and head[index] in b" \t\r\n\f\x00":
        index += 1
    if head[index:index + 2] == b"<<":
        depth = 0
        start = index
        while index < size:
            pair = head[index:index + 2]
            if pair == b"<<":
                depth += 1
                index += 2
            elif pair == b">>":
                depth -= 1
                index += 2
                if depth == 0:
                    return head[start:index]
            elif head[index:index + 1] == b"(":
                index = skip_string(head, index)
            else:
                index += 1
        return head[start:]
    if head[index:index + 1] == b"[":
        stop = head.find(b"]", index)
        return head[index:stop + 1] if stop >= 0 else head[index:]
    match = re.match(rb"\d+\s+\d+\s+R|/[^\s/<>\[\]()]+|[^\s/<>\[\]()]+", head[index:])
    return match.group(0) if match else b""


class PdfFont:
    def __init__(self, reader: PdfReader, head: bytes) -> None:
        self.two_byte = bool(re.search(rb"/Subtype\s*/Type0\b", head))
        self.unicode: dict[int, str] = {}
        self.byte_length = 2 if self.two_byte else 1
        reference = re.search(rb"/ToUnicode\s+(\d+)\s+\d+\s+R", head)
        if reference:
            stream = reader.stream(int(reference.group(1)))
            if stream:
                self.unicode, lengths = parse_cmap(stream)
                if lengths:
                    self.byte_length = max(set(lengths), key=lengths.count)
        self.mappable = bool(self.unicode) or not self.two_byte
        self.encoding = "mac_roman" if re.search(rb"MacRoman", head) else "cp1252"
        self.differences: dict[int, str] = {}
        encoding = dictionary_value(head, b"Encoding")
        if encoding is not None:
            encoding = reader.resolve(encoding)
            if b"MacRoman" in encoding:
                self.encoding = "mac_roman"
            differences = dictionary_value(encoding, b"Differences")
            if differences:
                code = 0
                for token in re.findall(rb"\d+|/[^\s/\[\]]+", differences):
                    if token.startswith(b"/"):
                        self.differences[code] = glyph_character(token[1:].decode("latin-1"))
                        code += 1
                    else:
                        code = int(token)
        self.widths: dict[int, float] = {}
        self.default_width = 0.0
        self.has_widths = False
        self.load_widths(reader, head)

    def load_widths(self, reader: PdfReader, head: bytes) -> None:
        if self.two_byte:
            descendants = dictionary_value(head, b"DescendantFonts")
            if descendants is None:
                return
            descendants = reader.resolve(descendants)
            reference = PDF_REF.search(descendants)
            body = reader.dictionary(int(reference.group(1))) if reference else descendants
            default = re.search(rb"/DW\s+(-?[\d.]+)", body)
            self.default_width = float(default.group(1)) if default else 1000.0
            widths = dictionary_value(body, b"W")
            if widths is not None:
                self.parse_cid_widths(reader.resolve_array(widths))
            self.has_widths = True
            return
        first = re.search(rb"/FirstChar\s+(\d+)", head)
        widths = dictionary_value(head, b"Widths")
        if first is None or widths is None:
            return
        numbers = re.findall(rb"-?\d*\.?\d+", reader.resolve_array(widths))
        for offset, value in enumerate(numbers):
            self.widths[int(first.group(1)) + offset] = float(value)
        descriptor = re.search(rb"/FontDescriptor\s+(\d+)\s+\d+\s+R", head)
        if descriptor:
            missing = re.search(rb"/MissingWidth\s+(-?[\d.]+)", reader.dictionary(int(descriptor.group(1))))
            if missing:
                self.default_width = float(missing.group(1))
        self.has_widths = True

    def parse_cid_widths(self, data: bytes) -> None:
        pending: list[float] = []
        for token in re.findall(rb"\[[^\]]*\]|-?\d*\.?\d+", data.strip()[1:-1] if data.strip().startswith(b"[") else data):
            if token.startswith(b"["):
                if pending:
                    start = int(pending[-1])
                    for offset, value in enumerate(re.findall(rb"-?\d*\.?\d+", token)):
                        self.widths[start + offset] = float(value)
                pending = []
                continue
            pending.append(float(token))
            if len(pending) == 3:
                low, high, width = int(pending[0]), int(pending[1]), pending[2]
                if 0 <= high - low <= 65535:
                    for code in range(low, high + 1):
                        self.widths[code] = width
                pending = []

    def width(self, code: int) -> float:
        return self.widths.get(code, self.default_width)

    def decode(self, data: bytes) -> str:
        output = []
        if self.byte_length == 2:
            for index in range(0, len(data) - 1, 2):
                code = (data[index] << 8) | data[index + 1]
                output.append(self.unicode.get(code, "�"))
            return "".join(output)
        for byte in data:
            if byte in self.unicode:
                output.append(self.unicode[byte])
            elif byte in self.differences:
                output.append(self.differences[byte])
            else:
                output.append(bytes([byte]).decode(self.encoding, "replace"))
        return "".join(output)


GLYPH_NAMES = {"space": " ", "hyphen": "-", "period": ".", "comma": ",", "colon": ":", "semicolon": ";", "slash": "/",
               "parenleft": "(", "parenright": ")", "quoteright": "'", "quoteleft": "'", "quotedbl": '"', "quotesingle": "'",
               "ampersand": "&", "percent": "%", "dollar": "$", "at": "@", "exclam": "!", "question": "?", "plus": "+",
               "equal": "=", "underscore": "_", "bullet": "•", "endash": "–", "emdash": "—", "fi": "fi", "fl": "fl",
               "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
               "eight": "8", "nine": "9", "numbersign": "#", "asterisk": "*", "quotedblleft": "“", "quotedblright": "”"}


def glyph_character(name: str) -> str:
    if name in GLYPH_NAMES:
        return GLYPH_NAMES[name]
    if len(name) == 1:
        return name
    match = re.fullmatch(r"uni([0-9A-Fa-f]{4})", name)
    return chr(int(match.group(1), 16)) if match else "�"


def cmap_text(value: bytes) -> str:
    hex_digits = re.sub(rb"\s", b"", value)
    if len(hex_digits) % 2:
        hex_digits += b"0"
    try:
        return bytes.fromhex(hex_digits.decode("ascii")).decode("utf-16-be", "replace")
    except ValueError:
        return "�"


def parse_cmap(stream: bytes) -> tuple[dict[int, str], list[int]]:
    mapping: dict[int, str] = {}
    lengths: list[int] = []
    for section in re.findall(rb"beginbfchar(.*?)endbfchar", stream, re.S):
        for source, target in re.findall(rb"<([0-9A-Fa-f\s]+)>\s*<([0-9A-Fa-f\s]*)>", section):
            digits = re.sub(rb"\s", b"", source)
            lengths.append(len(digits) // 2)
            mapping[int(digits, 16)] = cmap_text(target)
    for section in re.findall(rb"beginbfrange(.*?)endbfrange", stream, re.S):
        for low, high, rest in re.findall(rb"<([0-9A-Fa-f\s]+)>\s*<([0-9A-Fa-f\s]+)>\s*(<[0-9A-Fa-f\s]*>|\[[^\]]*\])", section):
            low_digits = re.sub(rb"\s", b"", low)
            lengths.append(len(low_digits) // 2)
            start, stop = int(low_digits, 16), int(re.sub(rb"\s", b"", high), 16)
            if stop - start > 65535 or stop < start:
                continue
            if rest.startswith(b"["):
                for offset, target in enumerate(re.findall(rb"<([0-9A-Fa-f\s]*)>", rest)):
                    mapping[start + offset] = cmap_text(target)
            else:
                base = cmap_text(rest[1:-1])
                if base:
                    for code in range(start, stop + 1):
                        mapping[code] = base[:-1] + chr(min(ord(base[-1]) + code - start, 0x10ffff))
    return mapping, lengths


def tokenize_content(data: bytes) -> Iterator[tuple[str, Any]]:
    index = 0
    size = len(data)
    while index < size:
        char = data[index]
        if char in b" \t\r\n\f\x00":
            index += 1
        elif char == 0x25:  # comment
            stop = PDF_EOL.search(data, index)
            index = stop.end() if stop else size
        elif char == 0x28:  # literal string
            stop = skip_string(data, index)
            yield "string", unescape_pdf_string(data[index + 1:stop - 1])
            index = stop
        elif data[index:index + 2] == b"<<":
            index += 2
        elif data[index:index + 2] == b">>":
            index += 2
        elif char == 0x3c:  # hex string
            stop = data.find(b">", index)
            if stop < 0:
                return
            digits = re.sub(rb"[^0-9A-Fa-f]", b"", data[index + 1:stop])
            if len(digits) % 2:
                digits += b"0"
            yield "string", bytes.fromhex(digits.decode("ascii"))
            index = stop + 1
        elif char == 0x5b:
            yield "array-open", None
            index += 1
        elif char == 0x5d:
            yield "array-close", None
            index += 1
        elif char == 0x2f:
            match = PDF_NAME.match(data, index)
            yield "name", match.group(0)[1:]  # type: ignore[union-attr]
            index = match.end()  # type: ignore[union-attr]
        else:
            match = PDF_WORD.match(data, index)
            if not match:
                index += 1
                continue
            word = match.group(0)
            index = match.end()
            if PDF_NUMBER.fullmatch(word):
                yield "number", float(word)
            elif word == b"ID":  # inline image: skip its binary body
                stop = PDF_INLINE_END.search(data, index)
                index = stop.end() if stop else size
            else:
                yield "op", word.decode("latin-1")


def unescape_pdf_string(value: bytes) -> bytes:
    output = bytearray()
    index = 0
    escapes = {0x6e: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5c: 0x5c}
    while index < len(value):
        char = value[index]
        if char != 0x5c:
            output.append(char)
            index += 1
            continue
        index += 1
        if index >= len(value):
            break
        code = value[index]
        if code in escapes:
            output.append(escapes[code])
            index += 1
        elif 0x30 <= code <= 0x37:
            digits = value[index:index + 3]
            count = 0
            total = 0
            for digit in digits:
                if 0x30 <= digit <= 0x37:
                    total = total * 8 + digit - 0x30
                    count += 1
                else:
                    break
            output.append(total & 0xff)
            index += count
        elif code in (0x0d, 0x0a):
            index += 2 if value[index:index + 2] == b"\r\n" else 1
        else:
            output.append(code)
            index += 1
    return bytes(output)


def multiply(left: tuple[float, ...], right: tuple[float, ...]) -> tuple[float, ...]:
    a, b, c, d, e, f = left
    g, h, i, j, k, l = right
    return (a * g + b * i, a * h + b * j, c * g + d * i, c * h + d * j, e * g + f * i + k, e * h + f * j + l)


IDENTITY = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
LINE_BREAK_RATIO = 0.5
WORD_GAP_RATIO = 0.17


class TextLayout:
    """Lay text out where the page puts it. PDF has no words or lines, only glyphs at positions."""

    def __init__(self) -> None:
        self.pieces: list[str] = []
        self.ctm = IDENTITY
        self.stack: list[tuple[float, ...]] = []
        self.matrix = IDENTITY
        self.line_matrix = IDENTITY
        self.font: PdfFont | None = None
        self.size = 1.0
        self.char_space = self.word_space = self.leading = 0.0
        self.scale = 1.0
        self.end: tuple[float, float] | None = None

    def next_line(self, dx: float, dy: float) -> None:
        self.line_matrix = multiply((1.0, 0.0, 0.0, 1.0, dx, dy), self.line_matrix)
        self.matrix = self.line_matrix

    def show(self, items: list[Any]) -> None:
        for item in items:
            if isinstance(item, bytes):
                self.show_string(item)
            elif isinstance(item, float):
                self.advance(-item / 1000.0 * self.size * self.scale)

    def advance(self, distance: float) -> None:
        self.matrix = multiply((1.0, 0.0, 0.0, 1.0, distance, 0.0), self.matrix)

    def position(self) -> tuple[float, float, float]:
        device = multiply(self.matrix, self.ctm)
        return device[4], device[5], max(abs(device[3]), abs(device[0]), abs(device[1])) * self.size or 1.0

    def show_string(self, data: bytes) -> None:
        font = self.font
        text = font.decode(data) if font else data.decode("latin-1")
        x, y, size = self.position()
        if text and self.end is not None:
            end_x, end_y = self.end
            if abs(y - end_y) > LINE_BREAK_RATIO * size:
                self.pieces.append("\n")
            elif x - end_x > WORD_GAP_RATIO * size or x < end_x - size:
                self.pieces.append(" ")
        self.pieces.append(text)
        length = font.byte_length if font else 1
        known = bool(font and font.has_widths)
        for start in range(0, len(data), length):
            chunk = data[start:start + length]
            code_point = int.from_bytes(chunk, "big")
            width = font.width(code_point) if font and known else 500.0
            spacing = self.char_space + (self.word_space if length == 1 and code_point == 32 else 0.0)
            self.advance((width / 1000.0 * self.size + spacing) * self.scale)
        if text:
            end_x, end_y, _size = self.position()
            # Without real widths the end of the run is a guess, so only the line it sits on can be trusted.
            self.end = (end_x, end_y) if known else (float("inf"), end_y)


def render_content(data: bytes, fonts: dict[bytes, PdfFont]) -> str:
    """Text in stream order, with spaces and line breaks where the glyph positions call for them."""
    layout = TextLayout()
    operands: list[Any] = []
    in_array = False
    array: list[Any] = []
    for kind, value in tokenize_content(data):
        if kind == "array-open":
            in_array, array = True, []
        elif kind == "array-close":
            in_array = False
            operands.append(array)
        elif kind in ("string", "number", "name"):
            (array if in_array else operands).append(value)
        elif kind == "op":
            numbers = [item for item in operands if isinstance(item, float)]
            if value == "q":
                if len(layout.stack) < 512:
                    layout.stack.append(layout.ctm)
            elif value == "Q":
                if layout.stack:
                    layout.ctm = layout.stack.pop()
            elif value == "cm" and len(numbers) >= 6:
                layout.ctm = multiply(tuple(numbers[-6:]), layout.ctm)
            elif value == "BT":
                layout.matrix = layout.line_matrix = IDENTITY
            elif value == "Tf" and len(operands) >= 2 and isinstance(operands[-2], bytes):
                layout.font = fonts.get(operands[-2])
                if isinstance(operands[-1], float):
                    layout.size = operands[-1]
            elif value == "Tc" and numbers:
                layout.char_space = numbers[-1]
            elif value == "Tw" and numbers:
                layout.word_space = numbers[-1]
            elif value == "Tz" and numbers:
                layout.scale = numbers[-1] / 100.0
            elif value == "TL" and numbers:
                layout.leading = numbers[-1]
            elif value == "Td" and len(numbers) >= 2:
                layout.next_line(numbers[-2], numbers[-1])
            elif value == "TD" and len(numbers) >= 2:
                layout.leading = -numbers[-1]
                layout.next_line(numbers[-2], numbers[-1])
            elif value == "Tm" and len(numbers) >= 6:
                layout.matrix = layout.line_matrix = tuple(numbers[-6:])
            elif value == "T*":
                layout.next_line(0.0, -layout.leading)
            elif value == "Tj" and operands and isinstance(operands[-1], bytes):
                layout.show([operands[-1]])
            elif value == "TJ" and operands and isinstance(operands[-1], list):
                layout.show(operands[-1])
            elif value == "'" and operands and isinstance(operands[-1], bytes):
                layout.next_line(0.0, -layout.leading)
                layout.show([operands[-1]])
            elif value == '"' and len(operands) >= 3 and isinstance(operands[-1], bytes):
                if isinstance(operands[-3], float) and isinstance(operands[-2], float):
                    layout.word_space, layout.char_space = operands[-3], operands[-2]
                layout.next_line(0.0, -layout.leading)
                layout.show([operands[-1]])
            operands = []
    return "".join(layout.pieces)


def undo_png_predictor(data: bytes, columns: int) -> bytes:
    row = columns + 1
    previous = bytearray(columns)
    output = bytearray()
    for start in range(0, len(data), row):
        kind, line = data[start], bytearray(data[start + 1:start + row])
        for index in range(len(line)):
            left = line[index - 1] if index else 0
            up = previous[index] if index < len(previous) else 0
            corner = previous[index - 1] if index and index - 1 < len(previous) else 0
            if kind == 1:
                line[index] = (line[index] + left) & 0xff
            elif kind == 2:
                line[index] = (line[index] + up) & 0xff
            elif kind == 3:
                line[index] = (line[index] + (left + up) // 2) & 0xff
            elif kind == 4:
                estimate = left + up - corner
                choices = sorted((abs(estimate - left), abs(estimate - up), abs(estimate - corner)))
                pick = left if abs(estimate - left) == choices[0] else up if abs(estimate - up) == choices[0] else corner
                line[index] = (line[index] + pick) & 0xff
        output += line
        previous = line
    return bytes(output)


def extract_pdf(raw: bytes) -> Extraction:
    try:
        reader = PdfReader(raw)
    except Inflated:
        return Extraction("", NEEDS, "its compressed content is larger than the limit")
    if reader.is_encrypted():
        return Extraction("", NEEDS, "the PDF is encrypted or restricted, so its text can't be read automatically")
    pages = reader.pages()
    if not pages:
        return Extraction("", NEEDS, "no pages could be found in the PDF")
    lines: list[str] = []
    empty: list[int] = []
    good = bad = 0
    for number, page in enumerate(pages, 1):
        try:
            text = reader.page_text(page)
        except Inflated:
            return Extraction("", NEEDS, "its compressed content is larger than the limit")
        except (ValueError, IndexError, zlib.error, OverflowError):
            text = ""
        text = "\n".join(re.sub(r"[ \t]+", " ", line).strip() for line in text.split("\n"))
        text = re.sub(r"\n{2,}", "\n", text).strip()
        visible_chars = [char for char in text if not char.isspace()]
        if len(visible_chars) < MIN_PAGE_CHARS:
            empty.append(number)
        good += sum(1 for char in visible_chars if char.isalnum() or char in ".,;:()-'\"/%&$@#+=!?[]_’‘“”–—•")
        bad += sum(1 for char in visible_chars if char == "�" or unicodedata.category(char) in ("Co", "Cn", "Cc"))
        lines += [f"[page {number}]", text, ""]
    text = "\n".join(lines)[:MAX_TEXT_CHARS]
    total = good + bad
    if total == 0 or len(empty) == len(pages):
        return Extraction("", NEEDS, "no text layer, so it is probably scanned", len(pages))
    if bad > total * 0.10 or not has_words(text):
        return Extraction("", NEEDS, "its text didn't decode to readable characters", len(pages))
    return Extraction(text, "extracted", "", len(pages), empty)


def has_words(text: str) -> bool:
    """Reject text that decodes to characters but not language, as fonts with scrambled encodings do."""
    words = re.findall(r"[^\W\d_]{2,}", text)
    if not words:
        return False
    vowels = sum(1 for word in words if re.search(r"[aeiouyAEIOUYÀ-￿]", word))
    return vowels / len(words) > 0.5


# ---------------------------------------------------------------------------------------- render


def load_manifest(out: Path) -> dict[str, Any]:
    path = out / "manifest.json"
    if not path.is_file():
        raise Refused(f"{out} has no manifest.json. Run prepare first.")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["digest"], manifest["sources"], manifest["leads"], manifest["limits"], manifest["vendor"]
    except (ValueError, KeyError, TypeError):
        raise Refused("manifest.json isn't what prepare wrote. Run prepare again.") from None
    if digest_tree(out, ("documents", "text", "policy")) != manifest["digest"]:
        raise Refused("the documents changed after prepare, so their evidence can't be trusted. Run prepare again.")
    return manifest


def cmd_capture(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    load_manifest(out)
    if not re.fullmatch(r"S\d{3}", args.id):
        raise Refused("--id must look like S001.")
    path = Path(args.file).expanduser().resolve()
    if not path.is_file():
        raise Refused(f"{path} isn't a file.")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise Refused(f"{path} is larger than the file limit.")
    extraction = extract_text(path.read_bytes(), path.suffix.lower())
    if extraction.status == NEEDS:
        print(f"{path.name} couldn't be read automatically: {extraction.note}. Save its text as research/{args.id}.txt yourself, "
              "or set captured to false.", file=sys.stderr)
        return 1
    write_exact(out / "research" / f"{args.id}.txt", extraction.text, errors="replace")
    print(f"Saved research/{args.id}.txt")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    manifest = load_manifest(out)
    sources = all_sources(manifest)
    open_items = 0
    for source in sources:
        transcript = out / "transcripts" / f"{source['id']}.txt"
        if source["text_status"] == NEEDS and not transcript.is_file():
            print(f"Needs a transcript: {source['id']} {source['name']} ({source['text_note']})")
            open_items += 1
        if source.get("pages_without_text") and not transcript.is_file():
            print(f"Pages to read directly: {source['id']} {source['name']} {source['pages_without_text']}")
            open_items += 1
    assessment = out / "assessment.json"
    if not assessment.is_file():
        print("assessment.json isn't written yet.")
        return 1 if open_items else 0
    code = validate_file(assessment, manifest, out)[0]
    if code == 0:
        print("assessment.json has no problems.")
    return code


def cmd_render(args: argparse.Namespace) -> int:
    out = Path(args.out).expanduser().resolve()
    manifest = load_manifest(out)
    assessment = out / "assessment.json"
    if not assessment.is_file():
        raise Refused(f"{out} has no assessment.json. Write it first, using references/report-contract.md.")
    code, data, index = validate_file(assessment, manifest, out)
    if code:
        return code
    report = out / "report.md"
    write_exact(report, build_report(data, manifest, index), errors="replace")
    questions = vendor_questions(data)
    letter = out / "vendor-questions.md"
    if questions:
        write_exact(letter, build_vendor_questions(questions, manifest), errors="replace")
    elif letter.exists():
        letter.unlink()
    counts = severity_counts(data["discrepancies"] + data["gaps"])
    print("Wrote", report, "|", VERDICT_LABEL[data["verdict"]["recommendation"]], "| residual risk:",
          residual_risk(data), "|", ", ".join(f"{counts[name]} {name}" for name in SEVERITIES))
    return 0


def validate_file(path: Path, manifest: dict[str, Any], out: Path) -> tuple[int, Any, "SourceIndex | None"]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as error:
        print(f"assessment.json isn't valid JSON: {error}", file=sys.stderr)
        return 1, None, None
    index = SourceIndex(manifest, out)
    try:
        problems = validate(data, manifest, index)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        problems = [f"a field has the wrong type ({error}). Compare it with references/report-contract.md."]
    if problems:
        print(f"assessment.json has {len(problems)} problem(s). Correct them against the evidence:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1, data, index
    return 0, data, index


def all_sources(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return list(manifest["sources"]) + list(manifest.get("policy", {}).get("sources", []))


def fold(text: str) -> str:
    """Compare text the way a reader would: PDF spacing, ligatures, and typographic quotes don't change a quotation."""
    text = unicodedata.normalize("NFKC", INVISIBLE.sub("", text)).translate(QUOTE_FOLD)
    return re.sub(r"\s+", "", text)


class SourceIndex:
    """Find a quotation in what the helper extracted, or in what the agent saved."""

    def __init__(self, manifest: dict[str, Any], out: Path) -> None:
        self.out = out
        self.documents = {source["id"]: source for source in all_sources(manifest)}
        self.cache: dict[Path, tuple[str, list[int], list[str]]] = {}

    def texts(self, path: Path) -> tuple[str, list[int], list[str]]:
        cached = self.cache.get(path)
        if cached:
            return cached
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        folded_parts, offsets = [], []
        position = 0
        for line in lines:
            # A page marker is the helper's, not the document's, so a quote may run across one.
            folded = "" if PAGE_MARKER.match(line.strip()) else fold(line)
            offsets.append(position)
            folded_parts.append(folded)
            position += len(folded)
        result = ("".join(folded_parts), offsets, lines)
        self.cache[path] = result
        return result

    def find(self, path: Path, quote: str) -> tuple[int, int | None] | None:
        joined, offsets, lines = self.texts(path)
        wanted = fold(quote)
        at = joined.find(wanted)
        if at < 0:
            # A word hyphenated across a line break reads "secur-" then "ity" in the text and "security" in a quote.
            compact, mapping = without_hyphens(joined)
            spot = compact.find(wanted.replace("-", ""))
            if spot < 0:
                return None
            at = mapping[spot]
        line_index = max(0, bisect.bisect_right(offsets, at) - 1)
        page = None
        for back in range(line_index, -1, -1):
            match = PAGE_MARKER.match(lines[back].strip())
            if match:
                page = int(match.group(1))
                break
        return line_index + 1, page


def without_hyphens(text: str) -> tuple[str, list[int]]:
    kept = []
    mapping = []
    for index, char in enumerate(text):
        if char != "-":
            kept.append(char)
            mapping.append(index)
    return "".join(kept), mapping


def text_problem(value: Any, label: str, problems: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{label} must be non-empty text.")


def brief(value: Any, limit: int, label: str, problems: list[str]) -> None:
    """Non-empty text, within a word limit. Length limits apply per entry, so a long story becomes more entries, not less truth."""
    text_problem(value, label, problems)
    if isinstance(value, str) and len(value.split()) > limit:
        problems.append(f"{label} is {len(value.split())} words; the limit is {limit}. Say it more tightly, or split it into "
                        "separate entries. Keep the facts.")


def keys_problem(value: Any, allowed: set[str], required: set[str], label: str, problems: list[str]) -> bool:
    if not isinstance(value, dict):
        problems.append(f"{label} must be an object.")
        return False
    for key in sorted(set(value) - allowed):
        problems.append(f"{label} has an unknown field: {key}.")
    for key in sorted(required - set(value)):
        problems.append(f"{label} is missing: {key}.")
    return True


class Validator:
    def __init__(self, data: dict[str, Any], manifest: dict[str, Any], index: SourceIndex) -> None:
        self.data = data
        self.manifest = manifest
        self.index = index
        self.problems: list[str] = []
        self.public = {item["id"]: item for item in data["public_sources"] if isinstance(item, dict) and isinstance(item.get("id"), str)}
        self.documents = {source["id"]: source for source in all_sources(manifest)}

    def cite(self, cite: Any, label: str, allow: str = "DSP") -> None:
        problems = self.problems
        if not keys_problem(cite, CITE_KEYS, {"source", "quote"}, label, problems):
            return
        source = cite.get("source")
        if not isinstance(source, str) or not source or source[0] not in allow:
            allowed = {"D": "a document (D...)", "S": "a public source (S...)", "P": "a policy document (P...)"}
            problems.append(f"{label}: source must be {' or '.join(allowed[char] for char in allow)}, not {source!r}.")
            return
        quote = cite.get("quote")
        if cite.get("credential") is True and quote == "":
            if source[0] == "S" or source not in self.documents:
                problems.append(f"{label}: only a supplied document can withhold a credential.")
            return
        if not isinstance(quote, str) or not quote.strip():
            problems.append(f"{label}: quote the source. Only a credential may be left empty, with credential set to true.")
            return
        if len(quote) > MAX_QUOTE_CHARS:
            problems.append(f"{label}: quote is too long. Quote only what proves the point.")
            return
        if len(fold(quote)) < MIN_QUOTE_CHARS:
            problems.append(f"{label}: quote is too short to prove anything. Quote the whole phrase.")
            return
        if source[0] == "S":
            self.public_quote(source, quote, label)
        else:
            self.document_quote(source, quote, label)

    def document_quote(self, source: str, quote: str, label: str) -> None:
        document = self.documents.get(source)
        if document is None:
            self.problems.append(f"{label}: {source} isn't a document in this review.")
            return
        text = self.index.out / document["text"]
        transcript = self.index.out / "transcripts" / f"{source}.txt"
        if self.index.find(text, quote) is not None:
            return
        if transcript.is_file() and self.index.find(transcript, quote) is not None:
            return
        where = f"{document['text']}" + (f" or transcripts/{source}.txt" if transcript.is_file() else "")
        self.problems.append(f"{label}: this quote isn't in {source} ({where}): {quote[:80]!r}. Quote the text as it is.")

    def public_quote(self, source: str, quote: str, label: str) -> None:
        item = self.public.get(source)
        if item is None:
            self.problems.append(f"{label}: {source} isn't in public_sources.")
            return
        capture = self.index.out / "research" / f"{source}.txt"
        if item.get("captured") is True and capture.is_file() and self.index.find(capture, quote) is None:
            self.problems.append(f"{label}: this quote isn't in research/{source}.txt: {quote[:80]!r}. Quote the page as saved.")

    def cites(self, value: Any, label: str, allow: str = "DSP", minimum: int = 1) -> None:
        if not isinstance(value, list):
            self.problems.append(f"{label} must be a list.")
            return
        if len(value) < minimum:
            self.problems.append(f"{label} needs at least {minimum} citation(s).")
        for number, cite in enumerate(value, 1):
            self.cite(cite, f"{label} {number}", allow)


def validate(data: Any, manifest: dict[str, Any], index: SourceIndex) -> list[str]:
    problems: list[str] = []
    if not keys_problem(data, TOP_KEYS, TOP_KEYS, "assessment.json", problems) or problems:
        return problems
    for key in ("steering", "dismissed_leads", "documents", "data_classification", "vendor_profile", "posture", "assurance",
                "subprocessors", "public_sources", "claims", "public_record", "discrepancies", "gaps", "policy",
                "questions_for_vendor", "not_checked"):
        if not isinstance(data[key], list):
            problems.append(f"{key} must be a list.")
    if problems:
        return problems
    check = Validator(data, manifest, index)
    check.problems = problems
    validate_public_sources(check)
    validate_engagement(check)
    brief(data["summary"], 90, "summary", problems)
    brief(data["subprocessor_note"], 30, "subprocessor_note", problems)
    validate_steering(check)
    validate_documents(check)
    validate_transcripts(check)
    validate_classification(check)
    validate_profile(check)
    validate_posture(check)
    validate_assurance(check)
    validate_subprocessors(check)
    validate_research(check)
    discrepancy_ids = validate_discrepancies(check)
    gap_ids = validate_gaps(check)
    validate_claims(check, discrepancy_ids)
    validate_record(check)
    validate_policy(check)
    validate_verdict(check, discrepancy_ids, gap_ids)
    for number, item in enumerate(data["questions_for_vendor"], 1):
        brief(item, 40, f"questions_for_vendor {number}", problems)
    for number, item in enumerate(data["not_checked"], 1):
        brief(item, 30, f"not_checked {number}", problems)
    return problems


def validate_engagement(check: Validator) -> None:
    item = check.data["engagement"]
    if keys_problem(item, ENGAGEMENT_KEYS, ENGAGEMENT_KEYS, "engagement", check.problems):
        for key in ("product", "use", "connection", "data_in_scope", "risk_reason"):
            brief(item.get(key), 30, f"engagement {key}", check.problems)
        for key, values in (("data_sensitivity", DATA_SENSITIVITY), ("access", ACCESS_LEVELS), ("business_impact", BUSINESS_IMPACT)):
            if item.get(key) not in values:
                check.problems.append(f"engagement {key} must be one of {', '.join(values)}.")


def validate_steering(check: Validator) -> None:
    known = {lead["id"] for lead in check.manifest["leads"]}
    capture_leads = {}
    for source in check.public.values():
        capture = check.index.out / "research" / f"{source['id']}.txt"
        if source.get("captured") is True and capture.is_file():
            for lead in find_leads(source["id"], capture):
                capture_leads[lead["id"]] = lead
    for source in check.documents.values():
        transcript = check.index.out / "transcripts" / f"{source['id']}.txt"
        if transcript.is_file():
            for lead in find_leads(f"{source['id']}T", transcript):
                capture_leads[lead["id"]] = lead
    known |= set(capture_leads)
    used: list[str] = []
    for number, item in enumerate(check.data["steering"], 1):
        label = f"steering {number}"
        if not keys_problem(item, STEERING_KEYS, {"cite", "effect", "handled"}, label, check.problems):
            continue
        check.cite(item.get("cite"), f"{label} cite")
        brief(item.get("effect"), 30, f"{label} effect", check.problems)
        brief(item.get("handled"), 30, f"{label} handled", check.problems)
        leads = item.get("leads") or []
        if not isinstance(leads, list):
            check.problems.append(f"{label}: leads must be a list.")
            leads = []
        used += [str(value) for value in leads]
    for number, entry in enumerate(check.data["dismissed_leads"], 1):
        label = f"dismissed_leads {number}"
        if keys_problem(entry, {"leads", "reason"}, {"leads", "reason"}, label, check.problems):
            brief(entry.get("reason"), 20, f"{label} reason", check.problems)
            if isinstance(entry.get("leads"), list):
                used += [str(value) for value in entry["leads"]]
            else:
                check.problems.append(f"{label}: leads must be a list.")
    for value in sorted(set(used) - known):
        check.problems.append(f"{value} isn't a lead from this review.")
    for value in sorted({lead for lead in used if used.count(lead) > 1}):
        check.problems.append(f"lead {value} is used more than once. Each belongs in exactly one place.")
    for value in sorted(known - set(used)):
        check.problems.append(f"lead {value} isn't accounted for. Use it in steering or dismiss it with a reason.")


def validate_documents(check: Validator) -> None:
    seen = []
    for number, item in enumerate(check.data["documents"], 1):
        label = f"documents {number}"
        if not keys_problem(item, DOC_KEYS, {"source", "kind", "issued", "covers"}, label, check.problems):
            continue
        seen.append(item.get("source"))
        if not str(item.get("source", "")).startswith("D") or item.get("source") not in check.documents:
            check.problems.append(f"{label}: {item.get('source')!r} isn't a document from this review.")
        for key, limit in (("kind", 10), ("issued", 8), ("covers", 25)):
            brief(item.get(key), limit, f"{label} {key}", check.problems)
        if item.get("note"):
            brief(item.get("note"), 20, f"{label} note", check.problems)
    for source in check.manifest["sources"]:
        if source["id"] not in seen:
            check.problems.append(f"{source['id']} ({source['name']}) isn't described in documents. Say what it is.")


def validate_transcripts(check: Validator) -> None:
    for source in check.manifest["sources"]:
        transcript = check.index.out / "transcripts" / f"{source['id']}.txt"
        if source["text_status"] == NEEDS and not transcript.is_file():
            mentioned = any(source["id"] in str(item) or source["name"] in str(item) for item in check.data["not_checked"])
            if not mentioned:
                check.problems.append(
                    f"{source['id']} ({source['name']}) has no extractable text and no transcript. Write "
                    f"transcripts/{source['id']}.txt, or name it in not_checked if you can't read it.")


def validate_classification(check: Validator) -> None:
    if not check.data["data_classification"]:
        check.problems.append("data_classification is empty. Say what data would reach this vendor.")
    for number, item in enumerate(check.data["data_classification"], 1):
        label = f"data_classification {number}"
        if keys_problem(item, CLASS_KEYS, CLASS_KEYS, label, check.problems):
            for key, limit in (("data", 12), ("class", 3), ("basis", 15)):
                brief(item.get(key), limit, f"{label} {key}", check.problems)


def validate_profile(check: Validator) -> None:
    seen = []
    for number, item in enumerate(check.data["vendor_profile"], 1):
        label = f"vendor_profile {number}"
        if not keys_problem(item, PROFILE_KEYS, {"topic", "finding", "cites"}, label, check.problems):
            continue
        topic = item.get("topic")
        seen.append(topic)
        if topic not in PROFILE_IDS:
            check.problems.append(f"{label}: topic must be one of {', '.join(sorted(PROFILE_IDS))}.")
        brief(item.get("finding"), 35, f"{label} finding", check.problems)
        check.cites(item.get("cites"), f"{label} cites", minimum=0)
    for key, _label in PROFILE_TOPICS:
        if key not in seen:
            check.problems.append(f"vendor_profile is missing {key}. If you couldn't establish it, say so with no citations.")


def validate_posture(check: Validator) -> None:
    seen = []
    for number, item in enumerate(check.data["posture"], 1):
        label = f"posture {number}"
        if not keys_problem(item, POSTURE_KEYS, {"id", "status", "answer", "cites"}, label, check.problems):
            continue
        key, status = item.get("id"), item.get("status")
        seen.append(key)
        if key == "other":
            brief(item.get("question"), 20, f"{label} question", check.problems)
        elif key not in POSTURE_IDS:
            check.problems.append(f"{label}: id must be one of {', '.join(sorted(POSTURE_IDS))}, or other with a question.")
        if status not in POSTURE_STATUS:
            check.problems.append(f"{label}: status must be one of {', '.join(POSTURE_STATUS)}.")
        brief(item.get("answer"), 45, f"{label} answer", check.problems)
        needed = 0 if status in ("silent", "not-applicable") else 1
        check.cites(item.get("cites"), f"{label} cites", minimum=needed)
        if status == "silent":
            looked = item.get("looked_in")
            if not isinstance(looked, list) or not looked or any(value not in check.documents and value not in check.public for value in looked):
                check.problems.append(f"{label}: a silent answer needs looked_in, naming the sources you searched.")
    for key, _question in POSTURE:
        if key not in seen:
            check.problems.append(f"posture is missing {key}. Answer it, or mark it silent or not-applicable.")


def validate_assurance(check: Validator) -> None:
    for number, item in enumerate(check.data["assurance"], 1):
        label = f"assurance {number}"
        if not keys_problem(item, ASSURANCE_KEYS, ASSURANCE_KEYS - ASSURANCE_OPTIONAL, label, check.problems):
            continue
        for key, limit in (("kind", 10), ("issuer", 12), ("subject_entity", 15), ("scope", 40), ("categories", 12), ("auditor_check", 30)):
            brief(item.get(key), limit, f"{label} {key}", check.problems)
        for key, limit in (("carve_outs", 30), ("bridge_letter", 20)):
            if key in item:
                brief(item.get(key), limit, f"{label} {key}", check.problems)
        if item.get("opinion") not in OPINIONS:
            check.problems.append(f"{label}: opinion must be one of {', '.join(OPINIONS)}.")
        if item.get("covers_product") not in COVERS_PRODUCT:
            check.problems.append(f"{label}: covers_product must be one of {', '.join(COVERS_PRODUCT)}.")
        if item.get("subservice_method") not in SUBSERVICE_METHODS:
            check.problems.append(f"{label}: subservice_method must be one of {', '.join(SUBSERVICE_METHODS)}.")
        for key in ("period_start", "period_end"):
            if item.get(key) != "" and parse_date(item.get(key)) is None:
                check.problems.append(f"{label}: {key} must be YYYY-MM-DD, or empty if the document doesn't state it.")
        for key, keys, limits in (("exceptions", EXCEPTION_KEYS, (("control", 8), ("finding", 30), ("relevance", 20), ("response", 20))),
                                  ("user_controls", USER_CONTROL_KEYS, (("control", 20), ("owner", 5)))):
            entries = item.get(key)
            if not isinstance(entries, list):
                check.problems.append(f"{label}: {key} must be a list, empty if the document states none.")
                continue
            for position, entry in enumerate(entries, 1):
                if keys_problem(entry, keys, keys, f"{label} {key} {position}", check.problems):
                    for field, limit in limits:
                        brief(entry.get(field), limit, f"{label} {key} {position} {field}", check.problems)
        check.cites(item.get("cites"), f"{label} cites")


def validate_subprocessors(check: Validator) -> None:
    seen = []
    for number, item in enumerate(check.data["subprocessors"], 1):
        label = f"subprocessors {number}"
        if not keys_problem(item, SUBPROCESSOR_KEYS, SUBPROCESSOR_KEYS, label, check.problems):
            continue
        for key, limit in (("name", 10), ("function", 12), ("data", 12), ("location", 8)):
            brief(item.get(key), limit, f"{label} {key}", check.problems)
        if not isinstance(item.get("model_provider"), bool):
            check.problems.append(f"{label}: model_provider must be true or false.")
        check.cites(item.get("cites"), f"{label} cites")
        seen.append(normal_name(str(item.get("name"))))
    for value in sorted({name for name in seen if seen.count(name) > 1}):
        check.problems.append(f"subprocessor {value} is listed more than once. Merge its citations into one entry.")


def validate_public_sources(check: Validator) -> None:
    seen = []
    assessed = parse_date(check.manifest["assessed"])
    for number, item in enumerate(check.data["public_sources"], 1):
        label = f"public_sources {number}"
        if not keys_problem(item, PUBLIC_SOURCE_KEYS, PUBLIC_SOURCE_KEYS, label, check.problems):
            continue
        identity = item.get("id")
        if not isinstance(identity, str) or not re.fullmatch(r"S\d{3}", identity):
            check.problems.append(f"{label}: id must look like S001.")
        seen.append(identity)
        parsed = urllib.parse.urlsplit(str(item.get("url")))
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            check.problems.append(f"{label}: url must be a full http or https address.")
        for key in ("title", "publisher"):
            text_problem(item.get(key), f"{label} {key}", check.problems)
        retrieved = parse_date(item.get("retrieved"))
        if retrieved is None or (assessed and retrieved > assessed + datetime.timedelta(days=1)):
            check.problems.append(f"{label}: retrieved must be the YYYY-MM-DD date you read it, not in the future.")
        published = item.get("published")
        if not isinstance(published, str) or (published and not re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", published)):
            check.problems.append(f"{label}: published must be YYYY, YYYY-MM, YYYY-MM-DD, or empty if unknown.")
        if item.get("kind") not in SOURCE_KINDS:
            check.problems.append(f"{label}: kind must be one of {', '.join(SOURCE_KINDS)}.")
        if not isinstance(item.get("captured"), bool):
            check.problems.append(f"{label}: captured must be true or false.")
        elif item["captured"] and not (check.index.out / "research" / f"{identity}.txt").is_file():
            check.problems.append(f"{label}: captured is true, but research/{identity}.txt doesn't exist.")
    for value in sorted({str(item) for item in seen if seen.count(item) > 1}):
        check.problems.append(f"public source {value} is listed more than once.")


def validate_research(check: Validator) -> None:
    item = check.data["research"]
    if not keys_problem(item, RESEARCH_KEYS, RESEARCH_KEYS, "research", check.problems):
        return
    if item.get("status") not in RESEARCH_STATUS:
        check.problems.append(f"research status must be one of {', '.join(RESEARCH_STATUS)}.")
    brief(item.get("note"), 40, "research note", check.problems)
    log = item.get("log")
    if not isinstance(log, list):
        check.problems.append("research log must be a list.")
        return
    if item.get("status") != "none" and not log:
        check.problems.append("research log is empty. Say what you looked for, where, and what came back.")
    for number, entry in enumerate(log, 1):
        label = f"research log {number}"
        if keys_problem(entry, LOG_KEYS, LOG_KEYS, label, check.problems):
            for key, limit in (("question", 15), ("where_looked", 15), ("result", 25)):
                brief(entry.get(key), limit, f"{label} {key}", check.problems)


def validate_discrepancies(check: Validator) -> set[str]:
    ids: list[str] = []
    for number, item in enumerate(check.data["discrepancies"], 1):
        label = f"discrepancies {number}"
        if not keys_problem(item, DISCREPANCY_KEYS, DISCREPANCY_KEYS, label, check.problems):
            continue
        ids.append(str(item.get("id")))
        if not re.fullmatch(r"X\d+", str(item.get("id"))):
            check.problems.append(f"{label}: id must look like X1.")
        for key, limit in (("title", 15), ("why", 45), ("ask", 30)):
            brief(item.get(key), limit, f"{label} {key}", check.problems)
        if item.get("kind") not in DISCREPANCY_KINDS:
            check.problems.append(f"{label}: kind must be one of {', '.join(DISCREPANCY_KINDS)}.")
        if item.get("severity") not in SEVERITIES:
            check.problems.append(f"{label}: severity must be one of {', '.join(SEVERITIES)}.")
        if item.get("confidence") not in CONFIDENCE:
            check.problems.append(f"{label}: confidence must be one of {', '.join(CONFIDENCE)}.")
        sides = []
        for key in ("side_a", "side_b"):
            side = item.get(key)
            if keys_problem(side, SIDE_KEYS, SIDE_KEYS, f"{label} {key}", check.problems):
                brief(side.get("says"), 15, f"{label} {key} says", check.problems)
                check.cite(side.get("cite"), f"{label} {key} cite")
                if isinstance(side.get("cite"), dict):
                    sides.append(side["cite"])
        if len(sides) == 2:
            if fold(str(sides[0].get("quote"))) == fold(str(sides[1].get("quote"))) and sides[0].get("source") == sides[1].get("source"):
                check.problems.append(f"{label}: both sides quote the same text. A discrepancy needs two statements.")
            same = sides[0].get("source") == sides[1].get("source")
            kind = item.get("kind")
            if kind == "within-document" and not same:
                check.problems.append(f"{label}: within-document needs both quotes from one document.")
            first, second = str(sides[0].get("source", " "))[0], str(sides[1].get("source", " "))[0]
            if kind == "document-vs-document" and (first != "D" or second != "D" or same):
                check.problems.append(f"{label}: document-vs-document needs quotes from two documents.")
            if kind == "document-vs-public" and {first, second} != {"D", "S"}:
                check.problems.append(f"{label}: document-vs-public needs one document and one public source.")
            if kind == "public-vs-public" and (first != "S" or second != "S"):
                check.problems.append(f"{label}: public-vs-public needs two public sources.")
    for value in sorted({item for item in ids if ids.count(item) > 1}):
        check.problems.append(f"discrepancy id {value} is used more than once.")
    return set(ids)


def validate_gaps(check: Validator) -> set[str]:
    ids: list[str] = []
    for number, item in enumerate(check.data["gaps"], 1):
        label = f"gaps {number}"
        if not keys_problem(item, GAP_KEYS, GAP_KEYS, label, check.problems):
            continue
        ids.append(str(item.get("id")))
        if not re.fullmatch(r"G\d+", str(item.get("id"))):
            check.problems.append(f"{label}: id must look like G1.")
        for key, limit in (("topic", 12), ("why", 30), ("ask", 30)):
            brief(item.get(key), limit, f"{label} {key}", check.problems)
        if item.get("severity") not in SEVERITIES:
            check.problems.append(f"{label}: severity must be one of {', '.join(SEVERITIES)}.")
        looked = item.get("looked_in")
        if not isinstance(looked, list) or not looked or any(value not in check.documents and value not in check.public for value in looked):
            check.problems.append(f"{label}: looked_in must name the document and public source ids you searched.")
    for value in sorted({item for item in ids if ids.count(item) > 1}):
        check.problems.append(f"gap id {value} is used more than once.")
    return set(ids)


def validate_claims(check: Validator, discrepancy_ids: set[str]) -> None:
    if not check.data["claims"]:
        check.problems.append("claims is empty. List the vendor's claims this engagement relies on, and how you tested each.")
    for number, item in enumerate(check.data["claims"], 1):
        label = f"claims {number}"
        if not keys_problem(item, CLAIM_KEYS, {"claim", "cites", "tested_against", "result"}, label, check.problems):
            continue
        brief(item.get("claim"), 20, f"{label} claim", check.problems)
        brief(item.get("tested_against"), 20, f"{label} tested_against", check.problems)
        check.cites(item.get("cites"), f"{label} cites")
        result = item.get("result")
        if result not in CLAIM_RESULTS:
            check.problems.append(f"{label}: result must be one of {', '.join(CLAIM_RESULTS)}.")
        if result == "contradicted" and item.get("discrepancy") not in discrepancy_ids:
            check.problems.append(f"{label}: a contradicted claim must name its discrepancy.")
        if item.get("evidence_cites") not in (None, []):
            check.cites(item.get("evidence_cites"), f"{label} evidence_cites")
        if result == "corroborated" and not item.get("evidence_cites"):
            check.problems.append(f"{label}: corroborated needs evidence_cites, from a source other than the claim itself.")


def validate_record(check: Validator) -> None:
    for number, item in enumerate(check.data["public_record"], 1):
        label = f"public_record {number}"
        if not keys_problem(item, RECORD_KEYS, RECORD_KEYS, label, check.problems):
            continue
        for key in ("event", "relevance"):
            brief(item.get(key), 25, f"{label} {key}", check.problems)
        date = item.get("date")
        if not isinstance(date, str) or (date and not re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", date)):
            check.problems.append(f"{label}: date must be YYYY, YYYY-MM, YYYY-MM-DD, or empty if unknown.")
        if item.get("kind") not in RECORD_KINDS:
            check.problems.append(f"{label}: kind must be one of {', '.join(RECORD_KINDS)}.")
        standing = item.get("standing")
        if standing not in RECORD_STANDING:
            check.problems.append(f"{label}: standing must be one of {', '.join(RECORD_STANDING)}.")
        check.cites(item.get("cites"), f"{label} cites", allow="S")
        if standing == "established" and isinstance(item.get("cites"), list):
            kinds = [check.public.get(cite.get("source"), {}).get("kind") for cite in item["cites"] if isinstance(cite, dict)]
            publishers = {check.public.get(cite.get("source"), {}).get("publisher") for cite in item["cites"] if isinstance(cite, dict)}
            if not (PRIMARY_KINDS & set(kinds)) and len(publishers) < 2:
                check.problems.append(f"{label}: established needs a regulator, court, or official register, or two independent publishers. Otherwise it is reported or alleged.")


def validate_policy(check: Validator) -> None:
    has_policy = "policy" in check.manifest
    if check.data["policy"] and not has_policy:
        check.problems.append("policy has entries, but no organizational policy was supplied. Leave it empty.")
    if has_policy and not check.data["policy"]:
        check.problems.append("policy is empty, but the organization's policy was supplied. Report how the vendor measures against it.")
    for number, item in enumerate(check.data["policy"], 1):
        label = f"policy {number}"
        if not keys_problem(item, POLICY_KEYS, POLICY_KEYS, label, check.problems):
            continue
        brief(item.get("requirement"), 25, f"{label} requirement", check.problems)
        brief(item.get("basis"), 30, f"{label} basis", check.problems)
        check.cite(item.get("policy_cite"), f"{label} policy_cite", "P")
        if item.get("status") not in POLICY_STATUS:
            check.problems.append(f"{label}: status must be one of {', '.join(POLICY_STATUS)}.")
        check.cites(item.get("cites"), f"{label} cites", allow="DS", minimum=0)


def validate_verdict(check: Validator, discrepancy_ids: set[str], gap_ids: set[str]) -> None:
    data, verdict = check.data, check.data["verdict"]
    if not keys_problem(verdict, VERDICT_KEYS, VERDICT_KEYS, "verdict", check.problems):
        return
    recommendation = verdict.get("recommendation")
    if recommendation not in VERDICTS:
        check.problems.append(f"verdict recommendation must be one of {', '.join(VERDICTS)}.")
    reasons, conditions = verdict.get("reasons"), verdict.get("conditions")
    if not isinstance(reasons, list) or not reasons:
        check.problems.append("verdict reasons must list the reasoning, each line backed by a reference or citation.")
        reasons = []
    if len(reasons) > MAX_REASONS:
        check.problems.append(f"verdict reasons has {len(reasons)} entries; the limit is {MAX_REASONS}. Give what decides it, and let the findings carry the rest.")
    if not isinstance(conditions, list):
        check.problems.append("verdict conditions must be a list.")
        conditions = []
    known = discrepancy_ids | gap_ids | POSTURE_IDS
    addressed: set[str] = set()
    for number, condition in enumerate(conditions, 1):
        label = f"verdict condition {number}"
        if not keys_problem(condition, CONDITION_KEYS, CONDITION_KEYS, label, check.problems):
            continue
        brief(condition.get("action"), 30, f"{label} action", check.problems)
        brief(condition.get("owner"), 5, f"{label} owner", check.problems)
        brief(condition.get("due"), 6, f"{label} due", check.problems)
        targets = condition.get("addresses")
        if not isinstance(targets, list):
            check.problems.append(f"{label}: addresses must be a list of finding or posture ids.")
            continue
        addressed.update(str(value) for value in targets)
        for value in targets:
            if value not in known:
                check.problems.append(f"{label}: {value!r} isn't a discrepancy, gap, or posture id in this review.")
    reassess = verdict.get("reassess")
    if keys_problem(reassess, REASSESS_KEYS, REASSESS_KEYS, "verdict reassess", check.problems):
        brief(reassess.get("triggers"), 25, "verdict reassess triggers", check.problems)
        by, assessed = parse_date(reassess.get("by")), parse_date(check.manifest["assessed"])
        if by is None or (assessed and by <= assessed):
            check.problems.append("verdict reassess by must be a YYYY-MM-DD date after this assessment.")
    for number, reason in enumerate(reasons, 1):
        label = f"verdict reason {number}"
        if not keys_problem(reason, REASON_KEYS, {"text"}, label, check.problems):
            continue
        brief(reason.get("text"), 35, f"{label} text", check.problems)
        references = reason.get("refs") or []
        cites = reason.get("cites") or []
        for value in references:
            if value not in known:
                check.problems.append(f"{label}: {value!r} isn't a discrepancy, gap, or posture id in this review.")
        check.cites(cites, f"{label} cites", minimum=0)
        if not references and not cites:
            check.problems.append(f"{label}: back this with refs or cites, or it is an opinion.")

    findings = [item for item in data["discrepancies"] + data["gaps"] if isinstance(item, dict)]
    serious = [str(item.get("id")) for item in findings if item.get("severity") in ("critical", "high")]
    if recommendation == "approve-with-conditions":
        if not conditions:
            check.problems.append("approve-with-conditions needs at least one condition.")
        unmet = [value for value in serious if value not in addressed]
        if unmet:
            check.problems.append(f"approve-with-conditions leaves critical or high findings with no condition: {', '.join(unmet)}. "
                                  "Address each in a condition's addresses, or the recommendation isn't this.")
    if recommendation != "approve":
        return
    blockers = []
    if conditions:
        blockers.append("it has conditions, so it is approve-with-conditions")
    if serious:
        blockers.append(f"critical or high findings are open: {', '.join(serious)}")
    contradicted = [item.get("id") for item in data["posture"] if isinstance(item, dict) and item.get("status") == "contradicted"]
    if contradicted:
        blockers.append(f"posture answers are contradicted: {', '.join(map(str, contradicted))}")
    if isinstance(data["research"], dict) and data["research"].get("status") == "none":
        blockers.append("no public research was done")
    unmet = [item for item in data["policy"] if isinstance(item, dict) and item.get("status") == "not-met"]
    if unmet:
        blockers.append(f"{len(unmet)} policy requirement(s) aren't met")
    if blockers:
        check.problems.append("verdict can't be approve: " + "; ".join(blockers) + ".")


# ---------------------------------------------------------------------------------------- report


def severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for item in items:
        counts[item["severity"]] += 1
    return counts


def inherent_risk(engagement: dict[str, Any]) -> str:
    """From the engagement alone, never the vendor's documents, so better marketing copy can't lower it."""
    sensitivity, access, impact = engagement["data_sensitivity"], engagement["access"], engagement["business_impact"]
    score = DATA_SENSITIVITY[sensitivity] + ACCESS_LEVELS[access] + BUSINESS_IMPACT[impact]
    if score >= 7:
        return "critical"
    if score >= 5 or sensitivity == "restricted" or access == "privileged" or impact == "critical":
        return "high"
    return "medium" if score >= 3 else "low"


def residual_risk(data: dict[str, Any]) -> str:
    """The worst open finding, one level lower when a condition addresses it, and never above the inherent risk."""
    if data["verdict"]["recommendation"] == "insufficient-evidence":
        return "Not determined"
    addressed = {str(value) for condition in data["verdict"]["conditions"] for value in condition["addresses"]}
    inherent = inherent_risk(data["engagement"])
    worst = len(RISK_LEVELS) - 1
    for item in data["discrepancies"] + data["gaps"]:
        rank = min(RANK[item["severity"]], worst)
        if item["id"] in addressed:
            rank = min(rank + 1, worst)
        worst = min(worst, rank)
    return RISK_LEVELS[max(worst, RISK_LEVELS.index(inherent))].capitalize()


def finding_key(item: dict[str, Any]) -> tuple[int, int, int]:
    return RANK[item["severity"]], 0 if item["id"].startswith("X") else 1, int(item["id"][1:])


def vendor_questions(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Each finding's question once, worst first, then any others. Findings that ask the same thing share a line."""
    merged: dict[str, list[str]] = {}
    for item in sorted(data["discrepancies"] + data["gaps"], key=finding_key):
        merged.setdefault(" ".join(item["ask"].split()), []).append(item["id"])
    for text in data["questions_for_vendor"]:
        merged.setdefault(" ".join(text.split()), [])
    return [(", ".join(ids), text) for text, ids in merged.items()]


def build_vendor_questions(questions: list[tuple[str, str]], manifest: dict[str, Any]) -> str:
    lines = [f"# Questions for {inline(manifest['vendor'])}", "", f"Draft of {manifest['assessed']}. A person reviews this before it is sent.",
             "", "Please answer each in writing and point to the document or contract clause that supports your answer.", ""]
    lines += [f"{number}. {inline(text)}" for number, (_ids, text) in enumerate(questions, 1)]
    return "\n".join(lines) + "\n"


def normal_name(name: str) -> str:
    cleaned = re.sub(r"[^\w\s]", " ", unicodedata.normalize("NFKC", name).lower())
    cleaned = re.sub(r"\b(inc|incorporated|llc|ltd|limited|corp|corporation|co|company|gmbh|sa|plc|bv|ag|pty|lp)\b", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def inline(value: Any) -> str:
    """One line of supplied text, safe to place in Markdown. It may quote a vendor, so nothing renders."""
    text = visible(re.sub(r"\s+", " ", mask(str(value))).strip()).replace("\\", "\\\\")
    text = re.sub(r"[`*\[\]~|]", r"\\\g<0>", text)
    text = re.sub(r"(?<!\w)_|_(?!\w)", r"\\_", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"^[#+=-]", r"\\\g<0>", text)
    return re.sub(r"^(\d+)([.)])", r"\1\\\2", text)


def code(value: Any) -> str:
    text = visible(re.sub(r"\s+", " ", mask(str(value))).strip()).replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {text} {fence}" if longest else f"`{text}`"


def link_url(value: str) -> str:
    """Show a URL for a person to inspect. It is never a live link, because it came from what the agent read."""
    return code(value)


class Citer:
    """Where a quote is. Findings show the quote; everything else shows a short locator, with the quote kept in the last appendix."""

    def __init__(self, data: dict[str, Any], manifest: dict[str, Any], index: SourceIndex) -> None:
        self.index = index
        self.documents = {source["id"]: source for source in all_sources(manifest)}
        self.public = {item["id"]: item for item in data["public_sources"]}
        self.machine = self.transcribed = self.captured = self.uncaptured = 0
        self.evidence: list[tuple[str, dict[str, Any]]] = []

    def where(self, cite: dict[str, Any]) -> tuple[str, str, str]:
        """(how it was checked, short locator, what a reader should know about it)"""
        source = cite["source"]
        if cite.get("credential") is True and cite.get("quote") == "":
            return "credential", f"{source} (credential withheld)", ""
        if source[0] == "S":
            capture = self.index.out / "research" / f"{source}.txt"
            if self.public[source]["captured"] and capture.is_file():
                return "captured", source, "quote found in the saved copy"
            return "uncaptured", f"{source} (not machine-checked)", "**quote not machine-checked**, no saved copy"
        found = self.index.find(self.index.out / self.documents[source]["text"], cite["quote"])
        if found is not None:
            line, page = found
            return "machine", f"{source} p. {page}" if page else f"{source} line {line}", f"line {line}" if page else ""
        line, page = self.index.find(self.index.out / "transcripts" / f"{source}.txt", cite["quote"]) or (0, None)
        place = f"{source} p. {page}" if page else source
        return "transcribed", f"{place} (agent transcript)", f"transcript line {line}; **agent transcript**, check against the original"

    def count(self, kind: str) -> None:
        if kind == "machine":
            self.machine += 1
        elif kind == "transcribed":
            self.transcribed += 1
        elif kind == "captured":
            self.captured += 1
        elif kind == "uncaptured":
            self.uncaptured += 1

    def quote_line(self, cite: dict[str, Any]) -> str:
        kind, short, note = self.where(cite)
        self.count(kind)
        if kind == "credential":
            name = self.documents[cite["source"]]["name"]
            return f"{cite['source']} {code(name)}: credential withheld by the reviewer, so the helper couldn't check this location"
        return f"“{inline(cite['quote'])}” — {short.split(' (')[0]}" + (f" ({note})" if note else "")

    def refs(self, section: str, cites: list[dict[str, Any]], empty: str = "**Not verified**") -> str:
        """Short locators for a table. The quotes go to the appendix."""
        self.evidence += [(section, cite) for cite in cites]
        return ", ".join(self.where(cite)[1] for cite in cites) or empty


def assurance_age(item: dict[str, Any], assessed: datetime.date) -> str:
    end, start = parse_date(item.get("period_end")), parse_date(item.get("period_start"))
    if end is None:
        return "Period end not stated"
    days = (assessed - end).days
    if days < 0:
        return "Period still open"
    if days > STALE_ASSURANCE_DAYS:
        age = f"Ended {days} days ago (about {days // 30} months): **stale**"
    elif days > BRIDGE_AFTER_DAYS and not item.get("bridge_letter"):
        age = f"Ended {days} days ago: **coverage gap, ask for a bridge letter**"
    else:
        age = f"Ended {days} days ago"
    if start and (end - start).days < SHORT_PERIOD_DAYS:
        age += f". **Short period:** {(end - start).days} days"
    return age


def subprocessor_changes(data: dict[str, Any], previous: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    now = {normal_name(item["name"]): item for item in data["subprocessors"]}
    before = {normal_name(item["name"]): item for item in previous["subprocessors"]}
    added = [now[key] for key in sorted(set(now) - set(before))]
    removed = [before[key] for key in sorted(set(before) - set(now))]
    return added, removed, len(set(now) & set(before))


def build_report(data: dict[str, Any], manifest: dict[str, Any], index: SourceIndex) -> str:
    assessed = datetime.date.fromisoformat(manifest["assessed"])
    citer = Citer(data, manifest, index)
    discrepancies = sorted(data["discrepancies"], key=finding_key)
    gaps = sorted(data["gaps"], key=finding_key)
    findings = sorted(discrepancies + gaps, key=finding_key)
    counts = severity_counts(findings)
    verdict, engagement, research = data["verdict"], data["engagement"], data["research"]
    has_policy = "policy" in manifest
    inherent, residual = inherent_risk(engagement).capitalize(), residual_risk(data)
    treated: dict[str, list[str]] = {}
    for number, condition in enumerate(verdict["conditions"], 1):
        for value in condition["addresses"]:
            treated.setdefault(str(value), []).append(f"C{number}")

    limits = list(dict.fromkeys([*manifest["limits"], *data["not_checked"]]))
    for source in all_sources(manifest):
        transcript = index.out / "transcripts" / f"{source['id']}.txt"
        if source["text_status"] == NEEDS and not transcript.is_file():
            limits.append(f"{source['id']} {source['name']} was not read: {source['text_note']}.")
        elif source.get("pages_without_text") and not transcript.is_file():
            limits.append(f"{source['id']} {source['name']}: pages {', '.join(map(str, source['pages_without_text']))} have no extractable text "
                          "and weren't transcribed. Scanned signature or opinion pages are often among these.")

    body: list[str] = []

    body += ["## Executive summary", "", inline(data["summary"]), "",
             f"**Recommendation: {VERDICT_LABEL[verdict['recommendation']]}.** The person who signs below makes the decision.", ""]
    for reason in verdict["reasons"]:
        pointers = [code(value) for value in reason.get("refs") or []]
        if reason.get("cites"):
            pointers.append(citer.refs("Executive summary", reason["cites"]))
        body.append(f"- {inline(reason['text'])}" + (f" ({', '.join(pointers)})" if pointers else ""))
    body += ["", "**Conditions**", ""]
    if verdict["conditions"]:
        body += ["| # | Action | Addresses | Owner | Due |", "| --- | --- | --- | --- | --- |"]
        for number, condition in enumerate(verdict["conditions"], 1):
            body.append(f"| C{number} | {inline(condition['action'])} | {', '.join(code(value) for value in condition['addresses']) or 'General'} | "
                        f"{inline(condition['owner'])} | {inline(condition['due'])} |")
    else:
        body.append("None.")
    body += ["", f"**Reassess by** {verdict['reassess']['by']}. **Sooner if:** {inline(verdict['reassess']['triggers'])}", "",
             f"**Public research: {research['status']}.** {inline(research['note'])}"]
    if data["steering"]:
        body += ["", f"**Steering found:** {len(data['steering'])} instruction(s) tried to change this review's result. None was followed."]
    if limits:
        body += ["", f"**Not checked:** {len(limits)} item(s), listed below. Nothing listed there is a clean result."]

    body += ["", "## Scope and inherent risk", "", "| | |", "| --- | --- |", f"| Product | {inline(engagement['product'])} |",
             f"| Intended use | {inline(engagement['use'])} |", f"| Connects to | {inline(engagement['connection'])} |",
             f"| Data in scope | {inline(engagement['data_in_scope'])} |", "",
             f"**Inherent risk: {inherent}.** {engagement['data_sensitivity'].capitalize()} data, {engagement['access']} access, "
             f"{engagement['business_impact']} business impact. {inline(engagement['risk_reason'])} Rated from this engagement, not the vendor's "
             "documents. If your organization tiers vendors its own way, use that.", "",
             "| Data | Class | Basis |", "| --- | --- | --- |"]
    body += [f"| {inline(item['data'])} | {inline(item['class'])} | {inline(item['basis'])} |" for item in data["data_classification"]]

    body += ["", "## Steering instructions", ""]
    if data["steering"]:
        body += ["Text in the documents or public sources that tries to change what this review concludes. It was not followed.", ""]
        for number, item in enumerate(data["steering"], 1):
            body += [f"- **T-{number:03d}.** {citer.quote_line(item['cite'])}", f"  - **Tries to:** {inline(item['effect'])}",
                     f"  - **Done:** {inline(item['handled'])}"]
    else:
        body.append("None found in what was read.")

    body += ["", "## Findings", ""]
    if findings:
        body += ["| ID | Severity | Type | Finding | Treatment |", "| --- | --- | --- | --- | --- |"]
        for item in findings:
            kind = f"{KIND_LABEL[item['kind']]}, {item['confidence']}" if item["id"].startswith("X") else "Gap"
            title = item["title"] if item["id"].startswith("X") else item["topic"]
            body.append(f"| {item['id']} | {SEVERITY_LABEL[item['severity']]} | {kind} | {inline(title)} | {', '.join(treated.get(item['id'], [])) or 'Open'} |")
    else:
        body.append("None found among what was read. Read this with Not checked and Appendix A.")
    for item in discrepancies:
        body += ["", f"### {item['id']}: {inline(item['title'])}", "",
                 f"- **One source says:** {inline(item['side_a']['says'])} {citer.quote_line(item['side_a']['cite'])}",
                 f"- **Another says:** {inline(item['side_b']['says'])} {citer.quote_line(item['side_b']['cite'])}",
                 f"- **Why it matters here:** {inline(item['why'])}"]
    if gaps:
        body += ["", "### Gaps", "", "What the documents and public record don't say, and this engagement needs to know.", "",
                 "| ID | Missing | Looked in | Why it matters |", "| --- | --- | --- | --- |"]
        body += [f"| {item['id']} | {inline(item['topic'])} | {', '.join(code(value) for value in item['looked_in'])} | {inline(item['why'])} |" for item in gaps]

    body += ["", "## Independent assurance", ""]
    if data["assurance"]:
        for number, item in enumerate(data["assurance"]):
            if number:
                body.append("")
            period = f"{item['period_start'] or 'not stated'} to {item['period_end'] or 'not stated'}"
            subservice = SUBSERVICE_LABEL[item["subservice_method"]] + (f": {inline(item['carve_outs'])}" if item.get("carve_outs") else "")
            body += [f"### {inline(item['kind'])}, from {inline(item['issuer'])}", "", "| | |", "| --- | --- |",
                     f"| Opinion | {OPINION_LABEL[item['opinion']]} |",
                     f"| Period | {period}. {assurance_age(item, assessed)} |",
                     f"| Covers this product | {item['covers_product'].capitalize().replace('-', ' ')} |",
                     f"| Entity and scope | {inline(item['subject_entity'])}. {inline(item['scope'])} |",
                     f"| Categories | {inline(item['categories'])} |",
                     f"| Subservice organizations | {subservice} |",
                     f"| Bridge letter | {inline(item['bridge_letter']) if item.get('bridge_letter') else 'None supplied'} |",
                     f"| Auditor check | {inline(item['auditor_check'])} |",
                     f"| Evidence | {citer.refs('Independent assurance: ' + item['kind'], item['cites'])} |", ""]
            if item["exceptions"]:
                body += ["| Control | Exception | Relevance here | Vendor response |", "| --- | --- | --- | --- |"]
                body += [f"| {inline(entry['control'])} | {inline(entry['finding'])} | {inline(entry['relevance'])} | {inline(entry['response'])} |"
                         for entry in item["exceptions"]]
            else:
                body.append("Exceptions: none stated.")
            body.append("")
            if item["user_controls"]:
                body += ["Controls this report expects your organization to operate:", "", "| Customer control | Suggested owner |", "| --- | --- |"]
                body += [f"| {inline(entry['control'])} | {inline(entry['owner'])} |" for entry in item["user_controls"]]
            else:
                body.append("Customer controls: none stated.")
    else:
        body.append("None supplied or found. Nothing here has been independently checked.")

    body += ["", "## Control posture", "", "| Question | Status | Answer | Evidence |", "| --- | --- | --- | --- |"]
    questions = dict(POSTURE)
    ordered = [item for key, _question in POSTURE for item in data["posture"] if item["id"] == key]
    ordered += [item for item in data["posture"] if item["id"] == "other"]
    for item in ordered:
        question = item.get("question") if item["id"] == "other" else questions[item["id"]]
        evidence = citer.refs(f"Control posture: {item['id']}", item.get("cites") or [], "None")
        if item["status"] == "silent":
            evidence = "Looked in " + ", ".join(code(value) for value in item["looked_in"])
        body.append(f"| {inline(question)} | {STATUS_LABEL[item['status']]} | {inline(item['answer'])} | {evidence} |")

    body += ["", "## Subprocessors", "", inline(data["subprocessor_note"]), ""]
    if data["subprocessors"]:
        body += ["| Name | Function | Data | Location | Model provider | Source |", "| --- | --- | --- | --- | --- | --- |"]
        for item in sorted(data["subprocessors"], key=lambda entry: (not entry["model_provider"], normal_name(entry["name"]))):
            body.append(f"| {inline(item['name'])} | {inline(item['function'])} | {inline(item['data'])} | {inline(item['location'])} | "
                        f"{'**Yes**' if item['model_provider'] else 'No'} | {citer.refs('Subprocessors: ' + item['name'], item['cites'])} |")
    else:
        body.append("None established.")
    if "previous" in manifest:
        previous = manifest["previous"]
        added, removed, kept = subprocessor_changes(data, previous)
        body += ["", f"**Changes since the review of {previous['assessed']}** "
                 f"(its recommendation: {VERDICT_LABEL.get(previous['recommendation'], previous['recommendation'])}):", ""]
        for item in added:
            body.append(f"- **Added:** {inline(item['name'])}" + (" (**model provider**)" if item.get("model_provider") else ""))
        for item in removed:
            body.append(f"- **Removed:** {inline(item['name'])}" + (" (model provider)" if item.get("model_provider") else ""))
        body.append(f"- {kept} unchanged.")

    body += ["", "## Vendor profile", "", "| Topic | Finding | Source |", "| --- | --- | --- |"]
    labels = dict(PROFILE_TOPICS)
    for key, _label in PROFILE_TOPICS:
        for item in data["vendor_profile"]:
            if item["topic"] == key:
                body.append(f"| {labels[key]} | {inline(item['finding'])} | {citer.refs('Vendor profile: ' + key, item['cites'])} |")

    body += ["", "## Public record", ""]
    if data["public_record"]:
        body += ["| Date | Kind | Standing | Event | Relevance | Source |", "| --- | --- | --- | --- | --- | --- |"]
        for item in sorted(data["public_record"], key=lambda entry: entry["date"], reverse=True):
            body.append(f"| {item['date'] or 'Unknown'} | {item['kind']} | {item['standing']} | {inline(item['event'])} | "
                        f"{inline(item['relevance'])} | {citer.refs('Public record: ' + item['date'], item['cites'])} |")
    else:
        body.append("Nothing relevant found in the searches logged in Appendix C. That is not evidence that nothing happened.")

    body += ["", "## Policy fit", ""]
    if has_policy:
        routed = " Routed guidance was used." if manifest["policy"].get("index") else ""
        body += [f"Measured against the organization's policy, treated as required.{routed}", "",
                 "| Requirement | Status | Basis | Policy source | Vendor evidence |", "| --- | --- | --- | --- | --- |"]
        for item in data["policy"]:
            body.append(f"| {inline(item['requirement'])} | {item['status']} | {inline(item['basis'])} | "
                        f"{citer.refs('Policy fit', [item['policy_cite']])} | {citer.refs('Policy fit', item['cites'], 'None')} |")
    else:
        body.append("No organizational policy was supplied, so this was assessed against general third-party risk practice. "
                    "Check the verdict against your own requirements.")

    body += ["", "## Questions for the vendor", ""]
    asked = vendor_questions(data)
    if asked:
        body += ["Also in `vendor-questions.md`, without finding ids, ready for you to review and send.", ""]
        body += [f"{number}. {inline(text)}" + (f" ({ids})" if ids else "") for number, (ids, text) in enumerate(asked, 1)]
    else:
        body.append("None.")

    body += ["", "## Not checked", ""]
    body += [f"- {inline(item)}" for item in limits] or ["Nothing recorded."]

    body += ["", "## Sign-off", "", "A working assessment from what was written down. It is not an audit opinion or legal advice.", "",
             "| | |", "| --- | --- |", "| Reviewer | |", "| Date | |", "| Decision (approve, approve with conditions, reject) | |",
             "| Residual risk accepted by | |", "| Conditions owner | |"]

    body += ["", "## Appendix A: Claims tested", "", "| Claim | Vendor source | Tested against | Result |", "| --- | --- | --- | --- |"]
    for item in data["claims"]:
        result = item["result"].capitalize() + (f" ({code(item['discrepancy'])})" if item.get("discrepancy") else "")
        tested = inline(item["tested_against"])
        if item.get("evidence_cites"):
            tested += f" ({citer.refs('Claims tested', item['evidence_cites'])})"
        body.append(f"| {inline(item['claim'])} | {citer.refs('Claims tested', item['cites'])} | {tested} | {result} |")

    body += ["", "## Appendix B: Documents reviewed", "", "| Id | File | Kind | Issued | Covers | SHA-256 | Text |", "| --- | --- | --- | --- | --- | --- | --- |"]
    described = {item["source"]: item for item in data["documents"]}
    for source in manifest["sources"]:
        item = described[source["id"]]
        transcript = index.out / "transcripts" / f"{source['id']}.txt"
        if source["text_status"] == NEEDS:
            state = "Agent transcript" if transcript.is_file() else "**Not read**"
        elif source.get("pages_without_text"):
            state = f"Extracted, except p. {', '.join(map(str, source['pages_without_text']))}" + ("; those transcribed" if transcript.is_file() else "")
        else:
            state = "Extracted"
        note = f" {inline(item['note'])}" if item.get("note") else ""
        body.append(f"| {source['id']} | {code(source['name'])} | {inline(item['kind'])}{note} | {inline(item['issued'])} | {inline(item['covers'])} | "
                    f"{code(source['sha256'][:12])} | {state} |")

    body += ["", "## Appendix C: Research log and sources", ""]
    if research["log"]:
        body += ["| Looked for | Where | What came back |", "| --- | --- | --- |"]
        body += [f"| {inline(item['question'])} | {inline(item['where_looked'])} | {inline(item['result'])} |" for item in research["log"]]
    else:
        body.append("No searches were run.")
    body += ["", "Addresses are shown as text. Open them yourself to check what they say.", ""]
    if data["public_sources"]:
        body += ["| Id | Title | Publisher | Kind | Published | Read on | Saved copy | Address |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for item in data["public_sources"]:
            body.append(f"| {item['id']} | {inline(item['title'])} | {inline(item['publisher'])} | {item['kind']} | {item['published'] or 'Unknown'} | "
                        f"{item['retrieved']} | {'Yes' if item['captured'] else 'No'} | {link_url(item['url'])} |")
    else:
        body.append("None.")

    body += ["", "## Appendix D: Dismissed leads", ""]
    if data["dismissed_leads"]:
        leads = {lead["id"]: lead for lead in manifest["leads"]}
        body += ["| Dismissed | Reason |", "| --- | --- |"]
        for entry in data["dismissed_leads"]:
            where = ", ".join(code(value) + (f" {code(leads[value]['text'])}" if value in leads else "") for value in entry["leads"])
            body.append(f"| {where} | {inline(entry['reason'])} |")
    else:
        body.append("None.")

    body += ["", "## Appendix E: Quoted evidence", "", "The words behind the locators above. Findings and steering quote theirs in place.", ""]
    seen: set[tuple[str, str, str]] = set()
    for section, cite in citer.evidence:
        key = (section, str(cite["source"]), str(cite.get("quote")))
        if key not in seen:
            seen.add(key)
            body.append(f"- **{inline(section)}.** {citer.quote_line(cite)}")
    if not seen:
        body.append("None.")
    body.append("")

    header = [f"# Third-party risk assessment: {inline(manifest['vendor'])}", "", "| | |", "| --- | --- |"]
    header.append(f"| Assessed | {manifest['assessed']} |")
    header.append(f"| Recommendation | **{VERDICT_LABEL[verdict['recommendation']]}** |")
    header.append(f"| Inherent risk | {inherent} |")
    header.append(f"| Residual risk | {residual} |")
    header.append(f"| Findings | {', '.join(f'{counts[name]} {name}' for name in SEVERITIES if counts[name]) or 'None'} |")
    header.append(f"| Evidence | {len(manifest['sources'])} documents ({code(manifest['digest'][:12])}), {len(data['public_sources'])} public sources, research {research['status']} |")
    header.append(f"| Quotes | {citer.machine} checked in extracted text, {citer.transcribed} in agent transcripts, "
                  f"{citer.captured} in saved public copies, {citer.uncaptured} not machine-checked |")
    if manifest["inside_docs"]:
        header.append("| Session | Inside the documents folder, at the request of the operator |")
    header.append("| Status | **Unsigned.** A person reviews this before anyone relies on it. Handle it like the documents it quotes. |")
    return "\n".join(header + [""] + body)


if __name__ == "__main__":
    sys.exit(main())
