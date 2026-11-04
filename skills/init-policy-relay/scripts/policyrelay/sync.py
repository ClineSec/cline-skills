"""Transactional synchronization of a local PolicyRelay candidate bundle."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn

from .validator import ValidationIssue, validate_bundle

FaultInjector = Callable[[str], None]
MAX_DIAGNOSTICS = 20


@dataclass(frozen=True)
class SyncResult:
    status: str
    bundle_id: str
    bundle_revision: str
    route_count: int


class SyncError(RuntimeError):
    """A bounded failure safe to show to an operator."""

    def __init__(self, phase: str, code: str, diagnostics: tuple[str, ...] = ()):
        self.phase = phase
        self.code = code
        self.diagnostics = diagnostics[:MAX_DIAGNOSTICS]
        super().__init__(f"PolicyRelay sync failed: phase={phase} code={code}")


def _fail(phase: str, code: str, issues: list[ValidationIssue] | None = None) -> NoReturn:
    diagnostics: tuple[str, ...] = ()
    if issues:
        diagnostics = tuple(f"{issue.code}:{issue.path}" for issue in issues[:MAX_DIAGNOSTICS])
    raise SyncError(phase, code, diagnostics)


def _checkpoint(injector: FaultInjector | None, point: str) -> None:
    if injector is not None:
        injector(point)


def _fault_checkpoint(injector: FaultInjector | None, point: str, phase: str) -> None:
    try:
        _checkpoint(injector, point)
    except Exception as exc:
        raise SyncError(phase, "injected-failure") from exc


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def _copy_directory_fd(source_fd: int, destination: Path) -> None:
    """Copy only regular files/directories without ever following a source link."""
    with os.scandir(source_fd) as entries:
        ordered = sorted(entries, key=lambda entry: entry.name)
    for entry in ordered:
        before = entry.stat(follow_symlinks=False)
        target = destination / entry.name
        if stat.S_ISDIR(before.st_mode):
            child_fd = os.open(
                entry.name,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            try:
                after = os.fstat(child_fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise OSError(errno.ESTALE, "source changed during staging")
                target.mkdir(mode=0o700)
                _copy_directory_fd(child_fd, target)
                _fsync_directory(target)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(before.st_mode):
            source_file = os.open(
                entry.name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=source_fd,
            )
            try:
                after = os.fstat(source_file)
                if not stat.S_ISREG(after.st_mode) or (
                    before.st_dev,
                    before.st_ino,
                ) != (after.st_dev, after.st_ino):
                    raise OSError(errno.ESTALE, "source changed during staging")
                destination_file = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    while True:
                        chunk = os.read(source_file, 1024 * 1024)
                        if not chunk:
                            break
                        _write_all(destination_file, chunk)
                    os.fsync(destination_file)
                finally:
                    os.close(destination_file)
            finally:
                os.close(source_file)
        else:
            raise OSError(errno.EINVAL, "source entry is not a regular file or directory")


def _safe_snapshot(source: Path, destination: Path) -> None:
    try:
        root_stat = source.lstat()
    except OSError as exc:
        raise OSError(exc.errno or errno.ENOENT, "source unavailable") from None
    if not stat.S_ISDIR(root_stat.st_mode):
        raise OSError(errno.EINVAL, "source is not a real directory")
    source_fd = os.open(
        source,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(source_fd)
        if (root_stat.st_dev, root_stat.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError(errno.ESTALE, "source changed during staging")
        _copy_directory_fd(source_fd, destination)
        _fsync_directory(destination)
    finally:
        os.close(source_fd)


def _tree_digest(root: Path) -> bytes | None:
    """Return a deterministic content/name digest, or None for an unsafe tree."""
    digest = hashlib.sha256()

    def visit(path: Path, relative: str) -> bool:
        try:
            entries = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError:
            return False
        for entry in entries:
            child_relative = f"{relative}/{entry.name}" if relative else entry.name
            encoded = child_relative.encode("utf-8", "surrogateescape")
            try:
                info = entry.lstat()
            except OSError:
                return False
            if stat.S_ISDIR(info.st_mode):
                digest.update(b"D" + len(encoded).to_bytes(8, "big") + encoded)
                if not visit(entry, child_relative):
                    return False
            elif stat.S_ISREG(info.st_mode):
                digest.update(
                    b"F"
                    + len(encoded).to_bytes(8, "big")
                    + encoded
                    + info.st_size.to_bytes(8, "big")
                )
                try:
                    fd = os.open(entry, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    with os.fdopen(fd, "rb") as stream:
                        while chunk := stream.read(1024 * 1024):
                            digest.update(chunk)
                except OSError:
                    return False
            else:
                return False
        return True

    return digest.digest() if visit(root, "") else None


def _exchange_directories(left: Path, right: Path) -> None:
    """Atomically exchange two directory names on macOS or Linux."""
    libc = ctypes.CDLL(None, use_errno=True)
    left_bytes, right_bytes = os.fsencode(left), os.fsencode(right)
    if hasattr(libc, "renamex_np"):
        # RENAME_SWAP from <stdio.h> on Darwin.
        result = libc.renamex_np(left_bytes, right_bytes, ctypes.c_uint(0x00000002))
    elif hasattr(libc, "renameat2"):
        # RENAME_EXCHANGE from <linux/fs.h>; AT_FDCWD from <fcntl.h>.
        result = libc.renameat2(
            ctypes.c_int(-100), left_bytes, ctypes.c_int(-100), right_bytes, ctypes.c_uint(0x2)
        )
    else:
        raise OSError(errno.ENOTSUP, "atomic directory exchange unavailable")
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _activate(next_tree: Path, target: Path, injector: FaultInjector | None) -> None:
    existed = target.exists()
    exchanged = False
    installed = False
    try:
        _checkpoint(injector, "activation-before-commit")
        if existed:
            _exchange_directories(next_tree, target)
            exchanged = True
        else:
            os.replace(next_tree, target)
            installed = True
        _checkpoint(injector, "activation-after-commit")
        _fsync_directory(target.parent)
    except Exception:
        try:
            if exchanged:
                _exchange_directories(next_tree, target)
                _fsync_directory(target.parent)
            elif installed:
                os.replace(target, next_tree)
                _fsync_directory(target.parent)
        except OSError as rollback_error:
            raise SyncError("activation", "rollback-failed") from rollback_error
        raise


def _real_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def synchronize(
    candidate_bundle: Path | str,
    consumer_root: Path | str,
    *,
    fault_injector: FaultInjector | None = None,
) -> SyncResult:
    """Validate, stage, and atomically activate a local contract 1.0 bundle.

    ``fault_injector`` is a library-only test seam.  It receives documented
    checkpoint names and is never wired to command-line input or environment data.
    """
    candidate = Path(candidate_bundle)
    consumer = Path(consumer_root)
    if not _real_directory(consumer):
        _fail("preflight", "consumer-root-not-real-directory")

    security = consumer / "security"
    try:
        if security.exists() or security.is_symlink():
            if not _real_directory(security):
                _fail("preflight", "security-path-not-real-directory")
        else:
            security.mkdir(mode=0o700)
    except SyncError:
        raise
    except OSError:
        _fail("preflight", "security-directory-unavailable")

    target = security / "PolicyRelay"
    lock_path = security / ".PolicyRelay.lock"
    try:
        try:
            existing_lock = lock_path.lstat()
        except FileNotFoundError:
            existing_lock = None
        if existing_lock is not None and not stat.S_ISREG(existing_lock.st_mode):
            _fail("preflight", "lock-not-regular-file")
        lock_fd = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            0o600,
        )
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            os.close(lock_fd)
            _fail("preflight", "lock-not-regular-file")
    except OSError:
        _fail("preflight", "lock-unavailable")

    stage: Path | None = None
    next_tree: Path | None = None
    try:
        with os.fdopen(lock_fd, "r+b", closefd=True) as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if target.exists() or target.is_symlink():
                    if not _real_directory(target):
                        _fail("preflight", "managed-target-not-real-directory")

                stage = Path(tempfile.mkdtemp(prefix=".PolicyRelay.bundle-", dir=security))
                try:
                    _safe_snapshot(candidate, stage)
                    _fault_checkpoint(fault_injector, "staging-after-snapshot", "staging")
                except Exception as exc:
                    if isinstance(exc, SyncError):
                        raise
                    raise SyncError("staging", "snapshot-failed") from exc

                try:
                    _fault_checkpoint(fault_injector, "parse-before-validation", "parse")
                    issues = validate_bundle(stage)
                    _fault_checkpoint(fault_injector, "validation-after-checks", "validation")
                except Exception as exc:
                    if isinstance(exc, SyncError):
                        raise
                    raise SyncError("validation", "validator-failed") from exc
                if issues:
                    _fail("validation", "candidate-rejected", issues)

                try:
                    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise SyncError("parse", "accepted-manifest-unavailable") from exc

                next_tree = Path(tempfile.mkdtemp(prefix=".PolicyRelay.next-", dir=security))
                try:
                    _safe_snapshot(stage / "payload", next_tree)
                    _fault_checkpoint(fault_injector, "materialization-after-copy", "staging")
                except Exception as exc:
                    if isinstance(exc, SyncError):
                        raise
                    raise SyncError("staging", "materialization-failed") from exc

                candidate_digest = _tree_digest(next_tree)
                if candidate_digest is None:
                    _fail("staging", "materialized-tree-unreadable")
                current_digest = _tree_digest(target) if target.exists() else None
                if current_digest is not None and candidate_digest == current_digest:
                    status = "unchanged"
                else:
                    try:
                        _activate(next_tree, target, fault_injector)
                    except Exception as exc:
                        if isinstance(exc, SyncError):
                            raise
                        raise SyncError("activation", "commit-failed") from exc
                    status = "activated"

                return SyncResult(
                    status=status,
                    bundle_id=manifest["bundleId"],
                    bundle_revision=manifest["bundleRevision"],
                    route_count=len(manifest["routes"]),
                )
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    finally:
        for temporary in (next_tree, stage):
            if temporary is not None:
                shutil.rmtree(temporary, ignore_errors=True)
