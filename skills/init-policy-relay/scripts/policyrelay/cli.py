"""Deterministic command-line boundaries for PolicyRelay."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .lifecycle import InstallError, LifecycleError, install, session_start
from .sync import SyncError, SyncResult, synchronize


def _arguments(argv: list[str]) -> argparse.Namespace:
    # A bare two-argument call is the original sync form; every other operation is a
    # named subcommand.
    if len(argv) == 2 and argv[0] not in {"sync", "install", "session-start", "-h", "--help"}:
        return argparse.Namespace(command="sync", candidate=Path(argv[0]), consumer_root=Path(argv[1]))
    parser = argparse.ArgumentParser(description="Install and synchronize PolicyRelay guidance")
    commands = parser.add_subparsers(dest="command", required=True)

    sync_parser = commands.add_parser("sync", help="synchronize an already-local bundle")
    sync_parser.add_argument("--candidate", required=True, type=Path)
    sync_parser.add_argument("--consumer-root", required=True, type=Path)

    install_parser = commands.add_parser("install", help="install PolicyRelay into a consumer")
    install_parser.add_argument("--consumer-root", required=True, type=Path)
    install_parser.add_argument("--upstream", required=True)
    install_parser.add_argument("--branch", required=True)

    start_parser = commands.add_parser("session-start", help="acquire configured policy")
    start_parser.add_argument("--consumer-root", required=True, type=Path)
    return parser.parse_args(argv)


def _print_sync(result: SyncResult) -> None:
    print(
        f"OK status={result.status} bundleId={result.bundle_id} "
        f"revision={result.bundle_revision} routes={result.route_count}"
    )


def _print_error(error: SyncError | LifecycleError) -> None:
    print(f"ERROR phase={error.phase} code={error.code}", file=sys.stderr)
    if isinstance(error, SyncError):
        for diagnostic in error.diagnostics:
            print(f"DIAGNOSTIC {diagnostic}", file=sys.stderr)


def installed_session_start(consumer_root: Path | str) -> int:
    """Entry point used by the repository-local installed launcher."""
    try:
        result = session_start(consumer_root)
    except (SyncError, LifecycleError) as error:
        _print_error(error)
        return 1
    _print_sync(result)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _arguments(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "sync":
            _print_sync(synchronize(args.candidate, args.consumer_root))
        elif args.command == "install":
            result = install(args.consumer_root, args.upstream, args.branch)
            print(f"OK status={result.status}")
        else:
            _print_sync(session_start(args.consumer_root))
    except (SyncError, InstallError, LifecycleError) as error:
        _print_error(error)
        return 1
    return 0
