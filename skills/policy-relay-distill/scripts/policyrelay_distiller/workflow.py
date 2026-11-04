"""Source-independent adapter and safe local policy-repository workflow."""

from __future__ import annotations

import argparse
import copy
import ctypes
import dataclasses
import datetime as dt
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence

from .engine import DistillationError, distill, load_input, write_bundle


DOCUMENT_FIELDS = {
    "sourceId",
    "sourceTitle",
    "sourceRevision",
    "sourceLocator",
    "content",
}
MAPPING_FIELDS = {"contractVersion", "bundleId", "routes", "ambiguities"}
MAPPING_ROUTE_FIELDS = {
    "task",
    "title",
    "summary",
    "applicability",
    "normativeRequirements",
    "exceptionsAndEscalation",
}
MAX_PREVIEW_PATHS = 20


class WorkflowError(ValueError):
    """The workflow cannot continue safely without new input or correction."""


class SourceAccessError(RuntimeError):
    """An explicitly selected source-access method could not fetch authorized data."""


class AuthorizedSourceAccess(Protocol):
    """Boundary implemented by an already selected MCP or local source method."""

    def fetch_authorized(self, requests: Sequence[Mapping[str, Any]]) -> Sequence[Mapping[str, Any]]:
        """Return authorized documents as inert mappings, or raise SourceAccessError."""


@dataclasses.dataclass(frozen=True)
class Candidate:
    normalized_input: dict[str, Any]
    files: dict[str, bytes]
    bundle_id: str
    revision: str
    routes: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class RepositoryPreview:
    operation: str
    bundle_id: str
    revision: str
    routes: tuple[str, ...]
    added: tuple[str, ...]
    changed: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged_count: int
    unrelated_dirty_count: int

    def as_dict(self) -> dict[str, Any]:
        paths = [
            *(f"add {path}" for path in self.added),
            *(f"change {path}" for path in self.changed),
            *(f"remove {path}" for path in self.removed),
        ]
        return {
            "operation": self.operation,
            "bundleId": self.bundle_id,
            "bundleRevision": self.revision,
            "routes": list(self.routes),
            "changes": paths[:MAX_PREVIEW_PATHS],
            "omittedChangeCount": max(0, len(paths) - MAX_PREVIEW_PATHS),
            "unchangedFileCount": self.unchanged_count,
            "unrelatedDirtyPathCount": self.unrelated_dirty_count,
            "confirmationRequired": "initialize/update main and create one local commit",
        }


@dataclasses.dataclass(frozen=True)
class RepositoryResult:
    repository: Path
    commit: str | None
    changed: bool
    initialized: bool


def collect_authorized_documents(
    access: AuthorizedSourceAccess, requests: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """Call only the access implementation selected before any source data was read."""
    try:
        documents = access.fetch_authorized(requests)
    except Exception as exc:
        raise SourceAccessError(
            "authorized source access failed; verify the selected access method and authorization"
        ) from exc
    if not isinstance(documents, Sequence) or isinstance(documents, (str, bytes)):
        raise SourceAccessError("authorized source access returned no document sequence")
    return list(documents)


def _exact_fields(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise WorkflowError(f"{location} missing required fields: {', '.join(missing)}")
    if unknown:
        raise WorkflowError(f"{location} has unsupported fields: {', '.join(unknown)}")


def _nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkflowError(f"{location} must be a non-empty string")
    return value


def adapt_authorized_documents(
    documents: Sequence[Mapping[str, Any]],
    mapping: Mapping[str, Any],
    distilled_at: str,
) -> dict[str, Any]:
    """Map explicit human decisions and inert fetched documents to the accepted input model.

    Document content is deliberately not interpreted. The mapping must state every normalized
    policy decision and source reference; unresolved ambiguity is a hard stop.
    """
    if not isinstance(mapping, Mapping):
        raise WorkflowError("mapping root must be an object")
    _exact_fields(mapping, MAPPING_FIELDS, "mapping")
    ambiguities = mapping["ambiguities"]
    if not isinstance(ambiguities, list):
        raise WorkflowError("mapping.ambiguities must be an array")
    if ambiguities:
        raise WorkflowError(
            "mapping.ambiguities: unresolved source ambiguity "
            f"count={len(ambiguities)}; resolve all items before distillation"
        )
    try:
        parsed_date = dt.date.fromisoformat(distilled_at)
    except (TypeError, ValueError) as exc:
        raise WorkflowError("distilled_at must be a real YYYY-MM-DD date") from exc
    if parsed_date.isoformat() != distilled_at:
        raise WorkflowError("distilled_at must use YYYY-MM-DD format")

    if not isinstance(documents, Sequence) or isinstance(documents, (str, bytes)) or not documents:
        raise WorkflowError("authorized documents must be a non-empty array")
    provenance: dict[str, dict[str, str]] = {}
    for index, raw in enumerate(documents):
        location = f"documents[{index}]"
        if not isinstance(raw, Mapping):
            raise WorkflowError(f"{location} must be an object")
        _exact_fields(raw, DOCUMENT_FIELDS, location)
        content = raw["content"]
        if not isinstance(content, str) or not content.strip():
            raise WorkflowError(f"{location}.content must be non-empty fetched text")
        source_id = _nonempty_string(raw["sourceId"], f"{location}.sourceId")
        if source_id in provenance:
            raise WorkflowError(f"documents contain duplicate sourceId: {source_id}")
        provenance[source_id] = {
            "sourceId": source_id,
            "sourceTitle": _nonempty_string(raw["sourceTitle"], f"{location}.sourceTitle"),
            "sourceRevision": _nonempty_string(
                raw["sourceRevision"], f"{location}.sourceRevision"
            ),
            "sourceLocator": _nonempty_string(raw["sourceLocator"], f"{location}.sourceLocator"),
            "distilledAt": distilled_at,
        }

    routes = mapping["routes"]
    if not isinstance(routes, list) or not routes:
        raise WorkflowError("mapping.routes must be a non-empty array")
    normalized_routes: list[dict[str, Any]] = []
    for index, raw_route in enumerate(routes):
        location = f"mapping.routes[{index}]"
        if not isinstance(raw_route, Mapping):
            raise WorkflowError(f"{location} must be an object")
        _exact_fields(raw_route, MAPPING_ROUTE_FIELDS, location)
        route = dict(raw_route)
        used_ids: set[str] = set()
        for section in ("applicability", "normativeRequirements", "exceptionsAndEscalation"):
            statements = route.get(section)
            if not isinstance(statements, list):
                raise WorkflowError(f"{location}.{section} must be an array")
            for statement_index, statement in enumerate(statements):
                if not isinstance(statement, Mapping):
                    raise WorkflowError(f"{location}.{section}[{statement_index}] must be an object")
                source_ids = statement.get("sourceIds")
                if not isinstance(source_ids, list):
                    raise WorkflowError(
                        f"{location}.{section}[{statement_index}].sourceIds must be an array"
                    )
                for source_id in source_ids:
                    if not isinstance(source_id, str) or source_id not in provenance:
                        raise WorkflowError(
                            f"{location}.{section}[{statement_index}] references an inaccessible "
                            f"or missing authorized source: {source_id!r}"
                        )
                    used_ids.add(source_id)
        route["provenance"] = [provenance[source_id] for source_id in sorted(used_ids)]
        normalized_routes.append(route)

    normalized = {
        "contractVersion": mapping["contractVersion"],
        "bundleId": mapping["bundleId"],
        "routes": normalized_routes,
    }
    try:
        distill(normalized)
    except DistillationError as exc:
        raise WorkflowError(f"normalized policy was rejected: {exc}") from exc
    return normalized


def build_candidate(normalized_input: dict[str, Any]) -> Candidate:
    """Generate and validate a complete candidate with the accepted engine."""
    try:
        files = distill(normalized_input)
    except DistillationError as exc:
        raise WorkflowError(f"candidate generation failed: {exc}") from exc
    try:
        manifest = json.loads(files["manifest.json"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise WorkflowError("generated candidate has no valid manifest") from exc
    expected = {"manifest.json", "payload/index.md"}
    expected.update(f"payload/{route['entrypoint']}" for route in manifest["routes"])
    if set(files) != expected:
        raise WorkflowError("generated candidate is incomplete or has unexpected files")
    return Candidate(
        normalized_input=copy.deepcopy(normalized_input),
        files=files,
        bundle_id=manifest["bundleId"],
        revision=manifest["bundleRevision"],
        routes=tuple(route["task"] for route in manifest["routes"]),
    )


def _revalidate_candidate(candidate: Candidate) -> Candidate:
    rebuilt = build_candidate(candidate.normalized_input)
    if (
        candidate.files != rebuilt.files
        or candidate.bundle_id != rebuilt.bundle_id
        or candidate.revision != rebuilt.revision
        or candidate.routes != rebuilt.routes
    ):
        raise WorkflowError("candidate does not exactly match regenerated engine output")
    return rebuilt


def _canonical_selected_path(path: Path | str) -> Path:
    # Canonical system prefixes (for example macOS /var) are outside this workflow's control.
    # Reject an explicitly selected symlink target and canonicalize all parent aliases.
    absolute = Path(path).absolute()
    if os.path.lexists(absolute) and absolute.is_symlink():
        raise WorkflowError(f"symlink path component is not allowed: {absolute}")
    return absolute.resolve(strict=False)


def _safe_relative_path(relative: str) -> PurePosixPath:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise WorkflowError(f"unsafe candidate path: {relative!r}")
    return path


def _write_plan(candidate: Candidate, output: Path) -> None:
    output = _canonical_selected_path(output)
    if os.path.lexists(output):
        raise WorkflowError(f"plan output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".policyrelay-plan-", dir=output.parent))
    plan = temporary / "plan"
    try:
        plan.mkdir()
        normalized = json.dumps(candidate.normalized_input, ensure_ascii=False, indent=2) + "\n"
        (plan / "normalized-input.json").write_text(normalized, encoding="utf-8")
        write_bundle(candidate.files, plan / "bundle")
        plan.rename(output)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _read_tree(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        raise WorkflowError(f"candidate bundle is not a safe directory: {root}")
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            if path.is_dir() and not path.is_symlink():
                continue
            raise WorkflowError(f"candidate contains a symlink or special file: {path}")
        relative = path.relative_to(root).as_posix()
        _safe_relative_path(relative)
        files[relative] = path.read_bytes()
    return files


def load_plan(path: Path | str) -> Candidate:
    """Revalidate a saved plan by regenerating it from its normalized input."""
    plan = _canonical_selected_path(path)
    if not plan.is_dir() or plan.is_symlink():
        raise WorkflowError(f"plan is not a safe directory: {plan}")
    names = {entry.name for entry in plan.iterdir()}
    if names != {"normalized-input.json", "bundle"}:
        raise WorkflowError("plan must contain exactly normalized-input.json and bundle/")
    normalized_path = plan / "normalized-input.json"
    if normalized_path.is_symlink() or not normalized_path.is_file():
        raise WorkflowError("plan normalized-input.json must be a regular file")
    try:
        normalized = load_input(normalized_path)
    except DistillationError as exc:
        raise WorkflowError(f"plan normalized input is invalid: {exc}") from exc
    candidate = build_candidate(normalized)
    if _read_tree(plan / "bundle") != candidate.files:
        raise WorkflowError("saved candidate does not exactly match regenerated engine output")
    return candidate


def create_plan(
    documents: Sequence[Mapping[str, Any]],
    mapping: Mapping[str, Any],
    distilled_at: str,
    destination: Path | str,
    output: Path | str,
) -> RepositoryPreview:
    """Generate a separately stored candidate and inspect the repository without mutating it."""
    destination_path = _canonical_selected_path(destination)
    output_path = _canonical_selected_path(output)
    try:
        output_path.relative_to(destination_path)
    except ValueError:
        pass
    else:
        raise WorkflowError("plan output must be outside the destination repository")
    normalized = adapt_authorized_documents(documents, mapping, distilled_at)
    candidate = build_candidate(normalized)
    preview = preview_repository(candidate, destination_path)
    _write_plan(candidate, output_path)
    return preview


def _git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update({"GIT_PAGER": "cat", "GIT_TERMINAL_PROMPT": "0"})
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        *args,
    ]
    result = subprocess.run(
        command,
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise WorkflowError(f"local Git command failed ({args[0]}): {detail}")
    return result


def _status_entries(repository: Path) -> list[tuple[str, str]]:
    result = _git(repository, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    tokens = result.stdout.split("\0")
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        record = tokens[index]
        if len(record) < 4:
            raise WorkflowError("Git returned malformed repository status")
        status, path = record[:2], record[3:]
        entries.append((status, path))
        index += 1
        if "R" in status or "C" in status:
            if index >= len(tokens) or not tokens[index]:
                raise WorkflowError("Git returned malformed rename status")
            entries.append((status, tokens[index]))
            index += 1
    return entries


def _is_bundle_path(path: str) -> bool:
    return path == "bundle" or path.startswith("bundle/")


def _inspect_existing_tree(root: Path) -> dict[str, bytes]:
    if not os.path.lexists(root):
        return {}
    if root.is_symlink() or not root.is_dir():
        raise WorkflowError("managed bundle path must be a real directory, not a symlink or file")
    return _read_tree(root)


def _repository_state(destination: Path, candidate_paths: Sequence[str]) -> tuple[str, int]:
    if not destination.exists():
        return "initialize", 0
    if not destination.is_dir():
        raise WorkflowError("destination must be a directory or a new path")
    git_dir = destination / ".git"
    if not os.path.lexists(git_dir):
        if os.path.lexists(destination / "bundle"):
            raise WorkflowError("cannot initialize over an existing unversioned bundle directory")
        return "initialize", 0
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise WorkflowError("destination .git must be a real local directory")
    top = Path(_git(destination, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != destination.resolve():
        raise WorkflowError("destination must be the policy repository root")
    branch = _git(destination, "branch", "--show-current").stdout.strip()
    if branch != "main":
        raise WorkflowError("policy repository must have main checked out")
    entries = _status_entries(destination)
    staged = [path for status, path in entries if status[0] not in (" ", "?")]
    if staged:
        raise WorkflowError(f"repository index is not clean: {staged[0]}")
    overlap = [path for _, path in entries if _is_bundle_path(path)]
    if overlap:
        raise WorkflowError(f"managed bundle has uncommitted overlap: {overlap[0]}")
    _reject_content_filters(destination, candidate_paths)
    return "update", len(entries)


def _reject_content_filters(repository: Path, candidate_paths: Sequence[str]) -> None:
    attributes = _git(repository, "check-attr", "filter", "--", *candidate_paths)
    for line in attributes.stdout.splitlines():
        value = line.rsplit(": ", 1)[-1]
        if value != "unspecified":
            raise WorkflowError("Git content filters are not allowed for managed bundle files")


def preview_repository(candidate: Candidate, destination: Path | str) -> RepositoryPreview:
    """Return a bounded, read-only preview after checking repository safety."""
    candidate = _revalidate_candidate(candidate)
    repository = _canonical_selected_path(destination)
    candidate_paths = [f"bundle/{path}" for path in candidate.files]
    operation, unrelated_dirty = _repository_state(repository, candidate_paths)
    current = _inspect_existing_tree(repository / "bundle") if repository.exists() else {}
    added = tuple(sorted(f"bundle/{path}" for path in candidate.files.keys() - current.keys()))
    removed = tuple(sorted(f"bundle/{path}" for path in current.keys() - candidate.files.keys()))
    common = candidate.files.keys() & current.keys()
    changed = tuple(sorted(f"bundle/{path}" for path in common if candidate.files[path] != current[path]))
    unchanged = sum(candidate.files[path] == current[path] for path in common)
    return RepositoryPreview(
        operation=operation,
        bundle_id=candidate.bundle_id,
        revision=candidate.revision,
        routes=candidate.routes,
        added=added,
        changed=changed,
        removed=removed,
        unchanged_count=unchanged,
        unrelated_dirty_count=unrelated_dirty,
    )


def _materialize(files: Mapping[str, bytes], root: Path) -> None:
    root.mkdir()
    for relative, content in sorted(files.items()):
        safe = _safe_relative_path(relative)
        target = root.joinpath(*safe.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _atomic_exchange(left: Path, right: Path) -> None:
    """Exchange two directory names with one atomic kernel operation.

    Existing-bundle updates must not emulate this with multiple renames: that creates a crash
    window in which the accepted bundle name is absent. Unsupported platforms and filesystems
    fail before either directory moves.
    """
    library = ctypes.CDLL(None, use_errno=True)
    left_bytes = os.fsencode(left)
    right_bytes = os.fsencode(right)
    if sys.platform == "darwin":
        try:
            rename = library.renamex_np
        except AttributeError as exc:
            raise WorkflowError("atomic directory exchange is unavailable") from exc
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = rename(left_bytes, right_bytes, 0x00000002)  # RENAME_SWAP
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as exc:
            raise WorkflowError("atomic directory exchange is unavailable") from exc
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        ctypes.set_errno(0)
        result = rename(-100, left_bytes, -100, right_bytes, 0x00000002)  # RENAME_EXCHANGE
    else:
        raise WorkflowError("atomic directory exchange is unavailable")
    if result:
        error_number = ctypes.get_errno()
        error_name = errno.errorcode.get(error_number, "UNKNOWN")
        raise WorkflowError(f"atomic directory exchange failed ({error_name})")


def update_repository(
    candidate: Candidate,
    destination: Path | str,
    *,
    confirmed: bool,
    commit_message: str = "Update PolicyRelay policy bundle",
) -> RepositoryResult:
    """Atomically replace only bundle/, stage it, and create one local commit on main."""
    if not confirmed:
        raise WorkflowError("repository mutation requires explicit local-commit confirmation")
    _nonempty_string(commit_message, "commit_message")
    candidate = _revalidate_candidate(candidate)
    repository = _canonical_selected_path(destination)
    preview = preview_repository(candidate, repository)
    if not preview.added and not preview.changed and not preview.removed:
        return RepositoryResult(repository, None, False, False)

    existed = repository.exists()
    initialized = preview.operation == "initialize"
    repository.mkdir(parents=True, exist_ok=True)
    initialized_here = False
    transaction = Path(tempfile.mkdtemp(prefix=".policyrelay-update-", dir=repository.parent))
    new_bundle = transaction / "new-bundle"
    bundle = repository / "bundle"
    had_bundle = os.path.lexists(bundle)
    committed = False
    installed = False
    exchanged = False
    cleanup_transaction = True
    try:
        _materialize(candidate.files, new_bundle)
        if initialized:
            _git(repository, "init", "--initial-branch=main")
            initialized_here = True
            _reject_content_filters(repository, [f"bundle/{path}" for path in candidate.files])
        if had_bundle:
            try:
                _atomic_exchange(bundle, new_bundle)
            except WorkflowError as exc:
                raise WorkflowError(f"{exc}; accepted bundle was not changed") from exc
            exchanged = True
        else:
            new_bundle.rename(bundle)
            installed = True
        _git(repository, "add", "--all", "--", "bundle")
        staged = _git(repository, "diff", "--cached", "--name-only").stdout.splitlines()
        if not staged or any(not _is_bundle_path(path) for path in staged):
            raise WorkflowError("staging did not contain exactly managed bundle changes")
        _git(repository, "commit", "--no-gpg-sign", "-m", commit_message)
        committed = True
        commit = _git(repository, "rev-parse", "HEAD").stdout.strip()
    except Exception:
        if not committed:
            if initialized and (repository / ".git").is_dir():
                initialized_here = True
            if initialized_here:
                shutil.rmtree(repository / ".git", ignore_errors=True)
            else:
                has_head = _git(
                    repository, "rev-parse", "--verify", "HEAD", check=False
                ).returncode == 0
                if has_head:
                    _git(repository, "reset", "HEAD", "--", "bundle", check=False)
                else:
                    _git(
                        repository,
                        "rm",
                        "--cached",
                        "-r",
                        "--ignore-unmatch",
                        "--",
                        "bundle",
                        check=False,
                    )
            if exchanged:
                try:
                    _atomic_exchange(bundle, new_bundle)
                except Exception as rollback_error:
                    cleanup_transaction = False
                    raise WorkflowError(
                        "repository update failed and atomic rollback could not restore bundle/; "
                        f"the previous accepted bundle was retained at {new_bundle}"
                    ) from rollback_error
                exchanged = False
            elif installed and os.path.lexists(bundle):
                shutil.rmtree(bundle)
            if not existed and repository.exists() and not any(repository.iterdir()):
                repository.rmdir()
        raise
    finally:
        if cleanup_transaction:
            shutil.rmtree(transaction, ignore_errors=True)
    return RepositoryResult(repository, commit, True, initialized)


def _load_json_array(path: Path) -> list[Mapping[str, Any]]:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise WorkflowError(f"documents file has duplicate JSON key: {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=object_without_duplicates
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowError(f"documents file is not readable unambiguous UTF-8 JSON: {exc}") from exc
    if not isinstance(value, list):
        raise WorkflowError("documents file root must be an array")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or apply a validated PolicyRelay local repository update."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="generate a candidate and print a read-only preview")
    plan.add_argument("--documents", type=Path, required=True)
    plan.add_argument("--mapping", type=Path, required=True)
    plan.add_argument("--distilled-at", required=True)
    plan.add_argument("--destination", type=Path, required=True)
    plan.add_argument("--output", type=Path, required=True, help="new plan directory outside repo")
    apply = subparsers.add_parser("apply", help="apply a previously previewed plan locally")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--destination", type=Path, required=True)
    apply.add_argument("--commit-message", default="Update PolicyRelay policy bundle")
    apply.add_argument("--confirm-local-commit", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "plan":
            mapping = load_input(args.mapping)
            preview = create_plan(
                _load_json_array(args.documents),
                mapping,
                args.distilled_at,
                args.destination,
                args.output,
            )
            print(json.dumps(preview.as_dict(), indent=2))
        else:
            candidate = load_plan(args.plan)
            result = update_repository(
                candidate,
                args.destination,
                confirmed=args.confirm_local_commit,
                commit_message=args.commit_message,
            )
            print(
                json.dumps(
                    {
                        "repository": str(result.repository),
                        "changed": result.changed,
                        "initialized": result.initialized,
                        "commit": result.commit,
                    },
                    indent=2,
                )
            )
    except (WorkflowError, SourceAccessError, DistillationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
