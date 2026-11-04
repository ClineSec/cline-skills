"""Transactional installer and read-only Git acquisition lifecycle."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NoReturn
from urllib.parse import urlsplit

from .sync import (
    FaultInjector,
    SyncResult,
    _exchange_directories,
    _fsync_directory,
    _real_directory,
    synchronize,
)

LifecycleFaultInjector = Callable[[str], None]
CONFIG_DIRECTORY = ".policyrelay"
CONFIG_FILE = "config.json"
SESSION_COMMAND = "session-start"
CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 16 * 1024
MAX_LOCATION_LENGTH = 4096
MAX_BRANCH_LENGTH = 255
BEGIN_MARKER = b"<!-- BEGIN PolicyRelay managed instructions -->"
END_MARKER = b"<!-- END PolicyRelay managed instructions -->"
MANAGED_BLOCK = b"""<!-- BEGIN PolicyRelay managed instructions -->
## PolicyRelay session start

Before repository work, run `./.policyrelay/session-start` from the repository root. If it fails,
stop and do not use stale or missing security guidance.

After it succeeds, open `security/PolicyRelay/index.md` and load only the guidance routes relevant
to the current task. Do not load the entire policy bundle by default.
<!-- END PolicyRelay managed instructions -->"""
RUNTIME_MODULES = (
    "__init__.py",
    "lifecycle.py",
    "sync.py",
    "validator.py",
)
_BRANCH_FORBIDDEN = re.compile(r"[\x00-\x20\x7f~^:?*\\[]")
# user@host:path, the SSH form Git hosts offer. The user carries no password, the host cannot
# be parsed as an option, and the path cannot begin an option or contain a query.
_SCP_LOCATION = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9][A-Za-z0-9.-]*:(?!-)[^\s:?#]+")
# Apple Git reports its built-in configuration, which holds osxkeychain, as "unknown".
_CREDENTIAL_SCOPES = {"system", "global", "unknown"}
MAX_CREDENTIAL_SETTINGS = 64
MAX_CREDENTIAL_SETTING_BYTES = 4096


@dataclass(frozen=True)
class InstallResult:
    status: str
    consumer_root: Path


@dataclass(frozen=True)
class LocalConfiguration:
    upstream: str
    branch: str


class LifecycleError(RuntimeError):
    """A bounded lifecycle failure safe to show to an operator."""

    def __init__(self, phase: str, code: str):
        self.phase = phase
        self.code = code
        super().__init__(f"PolicyRelay lifecycle failed: phase={phase} code={code}")


class InstallError(LifecycleError):
    """A bounded installation failure safe to show to an operator."""


def _fail(error_type: type[LifecycleError], phase: str, code: str) -> NoReturn:
    raise error_type(phase, code)


def _checkpoint(
    injector: LifecycleFaultInjector | None,
    point: str,
    error_type: type[LifecycleError],
    phase: str,
) -> None:
    if injector is None:
        return
    try:
        injector(point)
    except Exception as exc:
        raise error_type(phase, "injected-failure") from exc


def _valid_branch(branch: object) -> bool:
    if not isinstance(branch, str) or not branch or len(branch) > MAX_BRANCH_LENGTH:
        return False
    if branch == "@" or branch.startswith(("-", ".", "/")) or branch.endswith((".", "/")):
        return False
    if ".." in branch or "@{" in branch or "//" in branch:
        return False
    if any(component.startswith(".") or component.endswith(".lock") for component in branch.split("/")):
        return False
    return _BRANCH_FORBIDDEN.search(branch) is None


def _valid_upstream(location: object) -> bool:
    if not isinstance(location, str) or not location or len(location) > MAX_LOCATION_LENGTH:
        return False
    if location.startswith("-") or any(ord(character) < 32 for character in location):
        return False
    if _SCP_LOCATION.fullmatch(location):
        return True
    try:
        parsed = urlsplit(location)
        scheme = parsed.scheme.lower()
        if parsed.query or parsed.fragment:
            return False
        if scheme:
            if scheme not in {"file", "https", "ssh"}:
                return False
            if scheme == "file" and parsed.netloc not in {"", "localhost"}:
                return False
            if scheme == "file" and not parsed.path.startswith("/"):
                return False
            if scheme in {"https", "ssh"} and parsed.hostname is None:
                return False
        elif not Path(location).is_absolute():
            return False
        if scheme in {"http", "https"} and "@" in parsed.netloc:
            return False
        if parsed.password is not None:
            return False
    except ValueError:
        return False
    return True


def _configuration_bytes(upstream: object, branch: object) -> bytes:
    if not _valid_upstream(upstream):
        _fail(InstallError, "configuration", "upstream-invalid")
    if not _valid_branch(branch):
        _fail(InstallError, "configuration", "branch-invalid")
    value = {
        "schemaVersion": CONFIG_VERSION,
        "upstream": upstream,
        "branch": branch,
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _read_regular(path: Path, maximum: int, error_type: type[LifecycleError], phase: str) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            _fail(error_type, phase, "file-invalid")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (info.st_dev, info.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                _fail(error_type, phase, "file-invalid")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > maximum:
                _fail(error_type, phase, "file-invalid")
            return data
        finally:
            os.close(fd)
    except LifecycleError:
        raise
    except OSError:
        _fail(error_type, phase, "file-unavailable")


def load_configuration(consumer_root: Path | str) -> LocalConfiguration:
    consumer = Path(consumer_root)
    if not _real_directory(consumer):
        _fail(LifecycleError, "configuration", "consumer-root-not-real-directory")
    config_directory = consumer / CONFIG_DIRECTORY
    if not _real_directory(config_directory):
        _fail(LifecycleError, "configuration", "config-directory-not-real-directory")
    path = config_directory / CONFIG_FILE
    data = _read_regular(path, MAX_CONFIG_BYTES, LifecycleError, "configuration")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        _fail(LifecycleError, "configuration", "config-invalid")
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "upstream", "branch"}:
        _fail(LifecycleError, "configuration", "config-invalid")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != CONFIG_VERSION:
        _fail(LifecycleError, "configuration", "config-version-unsupported")
    if not _valid_upstream(value["upstream"]):
        _fail(LifecycleError, "configuration", "upstream-invalid")
    if not _valid_branch(value["branch"]):
        _fail(LifecycleError, "configuration", "branch-invalid")
    return LocalConfiguration(upstream=value["upstream"], branch=value["branch"])


def _managed_file(path: Path) -> tuple[bytes | None, bytes, int]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, MANAGED_BLOCK + b"\n", 0o644
    except OSError:
        _fail(InstallError, "instructions", "instruction-file-unavailable")
    if not stat.S_ISREG(info.st_mode):
        _fail(InstallError, "instructions", "instruction-file-not-regular")
    original = _read_regular(path, 1024 * 1024, InstallError, "instructions")
    begins = original.count(BEGIN_MARKER)
    ends = original.count(END_MARKER)
    if begins == 0 and ends == 0:
        if not original:
            updated = MANAGED_BLOCK + b"\n"
        elif original.endswith(b"\n\n"):
            updated = original + MANAGED_BLOCK + b"\n"
        elif original.endswith(b"\n"):
            updated = original + b"\n" + MANAGED_BLOCK + b"\n"
        else:
            updated = original + b"\n\n" + MANAGED_BLOCK + b"\n"
    elif begins == 1 and ends == 1:
        start = original.index(BEGIN_MARKER)
        finish = original.index(END_MARKER)
        if finish < start:
            _fail(InstallError, "instructions", "managed-markers-conflicting")
        finish += len(END_MARKER)
        updated = original[:start] + MANAGED_BLOCK + original[finish:]
    else:
        _fail(InstallError, "instructions", "managed-markers-conflicting")
    return original, updated, stat.S_IMODE(info.st_mode)


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    temporary: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _restore_file(path: Path, original: bytes | None, mode: int) -> None:
    if original is None:
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)
    else:
        _atomic_write(path, original, mode)


def _validate_existing_install(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if not _real_directory(path):
        _fail(InstallError, "installation", "install-path-not-real-directory")
    allowed_files = {
        CONFIG_FILE,
        SESSION_COMMAND,
        *(f"runtime/policyrelay/{name}" for name in RUNTIME_MODULES),
    }
    allowed_directories = {"runtime", "runtime/policyrelay"}
    try:
        for entry in path.rglob("*"):
            relative = entry.relative_to(path).as_posix()
            info = entry.lstat()
            if relative in allowed_directories and stat.S_ISDIR(info.st_mode):
                continue
            if relative in allowed_files and stat.S_ISREG(info.st_mode):
                continue
            _fail(InstallError, "installation", "install-layout-conflicting")
    except LifecycleError:
        raise
    except OSError:
        _fail(InstallError, "installation", "install-layout-unavailable")
    if not all((path / relative).exists() for relative in allowed_files):
        _fail(InstallError, "installation", "install-layout-conflicting")
    try:
        load_configuration(path.parent)
    except LifecycleError as exc:
        raise InstallError("installation", "existing-config-invalid") from exc


def _build_installation(destination: Path, config: bytes) -> None:
    def write_new(path: Path, data: bytes, mode: int) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    destination.mkdir(mode=0o700)
    destination.chmod(0o700)
    runtime = destination / "runtime" / "policyrelay"
    runtime.mkdir(parents=True, mode=0o700)
    runtime.parent.chmod(0o700)
    runtime.chmod(0o700)
    source = Path(__file__).resolve().parent
    for name in RUNTIME_MODULES:
        data = _read_regular(source / name, 2 * 1024 * 1024, InstallError, "installation")
        target = runtime / name
        write_new(target, data, 0o600)
    config_path = destination / CONFIG_FILE
    write_new(config_path, config, 0o600)
    launcher = destination / SESSION_COMMAND
    write_new(
        launcher,
        b"#!/usr/bin/env python3\n"
        b"import sys\n"
        b"from pathlib import Path\n"
        b"sys.dont_write_bytecode = True\n"
        b"install_dir = Path(__file__).resolve().parent\n"
        b"sys.path.insert(0, str(install_dir / 'runtime'))\n"
        b"from policyrelay.lifecycle import LifecycleError, session_start\n"
        b"from policyrelay.sync import SyncError\n"
        b"try:\n"
        b"    result = session_start(install_dir.parent)\n"
        b"except (SyncError, LifecycleError) as error:\n"
        b"    print(f'ERROR phase={error.phase} code={error.code}', file=sys.stderr)\n"
        b"    if isinstance(error, SyncError):\n"
        b"        for diagnostic in error.diagnostics:\n"
        b"            print(f'DIAGNOSTIC {diagnostic}', file=sys.stderr)\n"
        b"    raise SystemExit(1)\n"
        b"print(f'OK status={result.status} bundleId={result.bundle_id} ' "
        b"      f'revision={result.bundle_revision} routes={result.route_count}')\n",
        0o700,
    )
    _fsync_directory(runtime)
    _fsync_directory(runtime.parent)
    _fsync_directory(destination)


def install(
    consumer_root: Path | str,
    upstream: str,
    branch: str,
    *,
    fault_injector: LifecycleFaultInjector | None = None,
) -> InstallResult:
    """Install a local runtime, validated configuration, and bounded routing blocks."""
    consumer = Path(consumer_root)
    if not _real_directory(consumer):
        _fail(InstallError, "installation", "consumer-root-not-real-directory")
    config = _configuration_bytes(upstream, branch)
    lifecycle = consumer / CONFIG_DIRECTORY
    _validate_existing_install(lifecycle)
    instructions = []
    for name in ("AGENTS.md", "CLAUDE.md"):
        path = consumer / name
        original, updated, mode = _managed_file(path)
        instructions.append((path, original, updated, mode))

    stage = Path(tempfile.mkdtemp(prefix=".PolicyRelay.install-", dir=consumer))
    next_install = stage / "next"
    lifecycle_activated = False
    lifecycle_exchanged = False
    written: list[tuple[Path, bytes | None, int]] = []
    try:
        _build_installation(next_install, config)
        if lifecycle.exists():
            _exchange_directories(next_install, lifecycle)
            lifecycle_exchanged = True
        else:
            os.replace(next_install, lifecycle)
        lifecycle_activated = True
        _fsync_directory(consumer)
        _checkpoint(fault_injector, "installation-after-lifecycle", InstallError, "installation")
        for path, original, updated, mode in instructions:
            written.append((path, original, mode))
            _atomic_write(path, updated, mode)
            point = "installation-after-agents" if path.name == "AGENTS.md" else "installation-after-claude"
            _checkpoint(fault_injector, point, InstallError, "installation")
        return InstallResult(status="installed", consumer_root=consumer)
    except Exception as exc:
        try:
            for path, original, mode in reversed(written):
                _restore_file(path, original, mode)
            if lifecycle_activated:
                if lifecycle_exchanged:
                    _exchange_directories(next_install, lifecycle)
                else:
                    os.replace(lifecycle, next_install)
                _fsync_directory(consumer)
        except Exception as rollback_error:
            raise InstallError("installation", "rollback-failed") from rollback_error
        if isinstance(exc, LifecycleError):
            raise
        raise InstallError("installation", "install-failed") from exc
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("GIT_") or key in {"SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"}:
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file:https:ssh",
            "GIT_OPTIONAL_LOCKS": "0",
            "GCM_INTERACTIVE": "Never",
        }
    )
    return environment


def _user_credential_settings() -> list[tuple[str, str]]:
    """Return the operator's ``credential.*`` settings, or nothing if they cannot be bounded.

    Only system and user configuration qualify. Reading from a private empty directory with no
    inherited ``GIT_*`` variables keeps consumer-repository configuration and the caller's Git
    environment out of the result, because a consumer checkout is not a trusted source of
    executable credential helpers.
    """
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        with tempfile.TemporaryDirectory(prefix="policyrelay-config-") as neutral:
            result = subprocess.run(
                ["git", "config", "--includes", "--list", "--show-scope", "-z"],
                cwd=neutral,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    fields = result.stdout.split(b"\0")
    settings: list[tuple[str, str]] = []
    for scope, entry in zip(fields[0::2], fields[1::2]):
        key, separator, value = entry.partition(b"\n")
        if not separator or scope.decode("ascii", "replace") not in _CREDENTIAL_SCOPES:
            continue
        if not key.lower().startswith(b"credential."):
            continue
        if len(key) + len(value) > MAX_CREDENTIAL_SETTING_BYTES:
            return []
        try:
            settings.append((key.decode("utf-8"), value.decode("utf-8")))
        except UnicodeDecodeError:
            return []
    return settings if len(settings) <= MAX_CREDENTIAL_SETTINGS else []


def _clone_environment(upstream: str) -> dict[str, str]:
    """Isolate the clone, forwarding credential settings only where HTTPS needs them.

    Values travel in the environment rather than argv, which keeps them out of process listings.
    Everything else in user configuration, such as ``url.*.insteadOf``, ``core.sshCommand``, and
    ``core.hooksPath``, stays excluded. SSH needs none of this: ``ssh`` uses its own configuration
    and agent.
    """
    environment = _git_environment()
    if urlsplit(upstream).scheme.lower() != "https":
        return environment
    settings = _user_credential_settings()
    if settings:
        environment["GIT_CONFIG_COUNT"] = str(len(settings))
        for index, (key, value) in enumerate(settings):
            environment[f"GIT_CONFIG_KEY_{index}"] = key
            environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def _clone(upstream: str, branch: str, checkout: Path) -> None:
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.autocrlf=false",
        "-c",
        "uploadpack.packObjectsHook=git pack-objects",
        "clone",
        "--quiet",
        "--no-local",
        "--depth",
        "1",
        "--single-branch",
        "--branch",
        branch,
        "--",
        upstream,
        str(checkout),
    ]
    try:
        result = subprocess.run(
            command,
            env=_clone_environment(upstream),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        _fail(LifecycleError, "acquisition", "git-unavailable")
    except subprocess.TimeoutExpired:
        _fail(LifecycleError, "acquisition", "git-timeout")
    except OSError:
        _fail(LifecycleError, "acquisition", "git-failed")
    if result.returncode != 0:
        _fail(LifecycleError, "acquisition", "git-failed")


def _verify_checkout_branch(checkout: Path, branch: str) -> None:
    try:
        result = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(checkout),
                "show-ref",
                "--verify",
                "--quiet",
                f"refs/remotes/origin/{branch}",
            ],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(LifecycleError, "acquisition", "checkout-failed")
    if result.returncode != 0:
        _fail(LifecycleError, "acquisition", "checkout-failed")


def session_start(
    consumer_root: Path | str,
    *,
    fault_injector: LifecycleFaultInjector | None = None,
    sync_fault_injector: FaultInjector | None = None,
) -> SyncResult:
    """Acquire configured branch into private staging and synchronize checkout/bundle/."""
    consumer = Path(consumer_root)
    configuration = load_configuration(consumer)
    _checkpoint(fault_injector, "acquisition-before-clone", LifecycleError, "acquisition")
    with tempfile.TemporaryDirectory(prefix="PolicyRelay.acquire-") as temporary:
        private = Path(temporary)
        private.chmod(0o700)
        checkout = private / "checkout"
        _clone(configuration.upstream, configuration.branch, checkout)
        _verify_checkout_branch(checkout, configuration.branch)
        _checkpoint(fault_injector, "acquisition-after-clone", LifecycleError, "acquisition")
        candidate = checkout / "bundle"
        if not _real_directory(candidate):
            _fail(LifecycleError, "acquisition", "bundle-not-real-directory")
        _checkpoint(fault_injector, "synchronization-before-core", LifecycleError, "synchronization")
        return synchronize(candidate, consumer, fault_injector=sync_fault_injector)
