from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from policyrelay import InstallError, LifecycleError, SyncError, install, session_start
from policyrelay.lifecycle import BEGIN_MARKER, END_MARKER, MANAGED_BLOCK, load_configuration

from .support import REFERENCE, ROOT, RUNTIME_SCRIPTS, digest_tree


class InjectedFailure(RuntimeError):
    pass


def fail_at(expected: str):
    def inject(actual: str) -> None:
        if actual == expected:
            raise InjectedFailure(expected)
    return inject


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def create_upstream(root: Path, *, branch: str = "main", include_bundle: bool = True) -> Path:
    upstream = root / "upstream"
    upstream.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch", branch, str(upstream)],
        check=True,
        capture_output=True,
    )
    git(upstream, "config", "user.email", "tests@example.invalid")
    git(upstream, "config", "user.name", "PolicyRelay Tests")
    (upstream / "wrapper.txt").write_text("wrapper metadata is not a bundle\n", encoding="utf-8")
    if include_bundle:
        import shutil

        shutil.copytree(REFERENCE, upstream / "bundle")
    git(upstream, "add", ".")
    git(upstream, "commit", "--quiet", "-m", "fixture")
    return upstream


def commit_update(upstream: Path) -> None:
    manifest_path = upstream / "bundle" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["bundleRevision"] = "2026-08-27.2"
    manifest["routes"] = manifest["routes"][:1]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    guidance = upstream / "bundle" / "payload" / "guidance"
    (guidance / "vulnerability-triage.md").unlink()
    secure = guidance / "secure-coding.md"
    secure.write_text(secure.read_text(encoding="utf-8") + "\nUpdated.\n", encoding="utf-8")
    (upstream / "bundle" / "payload" / "index.md").write_text(
        "# PolicyRelay guidance\n\nChoose the route matching the task.\n\n"
        "- [secure-coding](guidance/secure-coding.md) — changing code\n",
        encoding="utf-8",
    )
    git(upstream, "add", "-A")
    git(upstream, "commit", "--quiet", "-m", "update")


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.consumer = self.root / "consumer"
        self.consumer.mkdir()
        self.upstream = create_upstream(self.root)

    def test_install_creates_bounded_assets_and_routing_files(self) -> None:
        result = install(self.consumer, str(self.upstream), "main")
        self.assertEqual("installed", result.status)
        config = load_configuration(self.consumer)
        self.assertEqual(str(self.upstream), config.upstream)
        self.assertEqual("main", config.branch)
        for name in ("AGENTS.md", "CLAUDE.md"):
            content = (self.consumer / name).read_bytes()
            self.assertEqual(1, content.count(BEGIN_MARKER))
            self.assertEqual(1, content.count(END_MARKER))
            self.assertIn(b"./.policyrelay/session-start", content)
            self.assertIn(b"security/PolicyRelay/index.md", content)
            self.assertIn(b"only the guidance routes relevant", content)
            self.assertNotIn(str(self.upstream).encode(), content)
        launcher = self.consumer / ".policyrelay" / "session-start"
        self.assertTrue(os.access(launcher, os.X_OK))
        self.assertEqual(0o700, launcher.stat().st_mode & 0o777)
        self.assertEqual(0o600, (self.consumer / ".policyrelay" / "config.json").stat().st_mode & 0o777)
        self.assertTrue((self.consumer / ".policyrelay" / "runtime" / "policyrelay" / "sync.py").is_file())
        self.assertFalse((self.consumer / ".policyrelay" / "runtime" / "policyrelay" / "cli.py").exists())

    def test_install_cli_has_explicit_deterministic_boundary(self) -> None:
        consumer = self.root / "cli-consumer"
        consumer.mkdir()
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(RUNTIME_SCRIPTS)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "policyrelay",
                "install",
                "--consumer-root",
                str(consumer),
                "--upstream",
                str(self.upstream),
                "--branch",
                "main",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("OK status=installed\n", result.stdout)
        self.assertEqual("main", load_configuration(consumer).branch)

    def test_existing_text_is_byte_preserved_and_reinstall_is_idempotent(self) -> None:
        agents_original = b"# Existing agents\n\nKeep this.\x00\n"
        claude_original = b"No final newline"
        (self.consumer / "AGENTS.md").write_bytes(agents_original)
        (self.consumer / "CLAUDE.md").write_bytes(claude_original)
        (self.consumer / "unrelated.bin").write_bytes(b"unrelated\x00bytes")
        install(self.consumer, str(self.upstream), "main")
        first_agents = (self.consumer / "AGENTS.md").read_bytes()
        first_claude = (self.consumer / "CLAUDE.md").read_bytes()
        first_install = digest_tree(self.consumer / ".policyrelay")
        self.assertTrue(first_agents.startswith(agents_original))
        self.assertTrue(first_claude.startswith(claude_original))
        install(self.consumer, str(self.upstream), "main")
        self.assertEqual(first_agents, (self.consumer / "AGENTS.md").read_bytes())
        self.assertEqual(first_claude, (self.consumer / "CLAUDE.md").read_bytes())
        self.assertEqual(first_install, digest_tree(self.consumer / ".policyrelay"))
        self.assertEqual(b"unrelated\x00bytes", (self.consumer / "unrelated.bin").read_bytes())

    def test_reinstall_updates_only_unambiguous_managed_block(self) -> None:
        surrounding = b"prefix\n" + MANAGED_BLOCK + b"\nsuffix\n"
        (self.consumer / "AGENTS.md").write_bytes(surrounding)
        install(self.consumer, str(self.upstream), "main")
        self.assertEqual(surrounding, (self.consumer / "AGENTS.md").read_bytes())

    def test_instruction_symlinks_and_conflicting_markers_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"preserve")
        (self.consumer / "AGENTS.md").symlink_to(outside)
        with self.assertRaises(InstallError):
            install(self.consumer, str(self.upstream), "main")
        self.assertEqual(b"preserve", outside.read_bytes())
        self.assertFalse((self.consumer / ".policyrelay").exists())
        (self.consumer / "AGENTS.md").unlink()
        (self.consumer / "AGENTS.md").write_bytes(BEGIN_MARKER + b"\nunterminated\n")
        with self.assertRaisesRegex(InstallError, "managed-markers-conflicting"):
            install(self.consumer, str(self.upstream), "main")
        self.assertFalse((self.consumer / ".policyrelay").exists())

    def test_conflicting_install_directory_symlink_is_rejected(self) -> None:
        outside = self.root / "outside-install"
        outside.mkdir()
        (outside / "preserve").write_bytes(b"keep")
        (self.consumer / ".policyrelay").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(InstallError):
            install(self.consumer, str(self.upstream), "main")
        self.assertEqual(b"keep", (outside / "preserve").read_bytes())

    def test_unowned_install_directory_is_rejected_without_deleting_content(self) -> None:
        install_path = self.consumer / ".policyrelay"
        install_path.mkdir()
        (install_path / "user-file").write_bytes(b"preserve")
        with self.assertRaises(InstallError):
            install(self.consumer, str(self.upstream), "main")
        self.assertEqual(b"preserve", (install_path / "user-file").read_bytes())
        self.assertFalse((self.consumer / "AGENTS.md").exists())

    def test_installer_rolls_back_all_owned_files_at_each_transition(self) -> None:
        (self.consumer / "AGENTS.md").write_bytes(b"agents original")
        points = (
            "installation-after-lifecycle",
            "installation-after-agents",
            "installation-after-claude",
        )
        for point in points:
            with self.subTest(point=point):
                with self.assertRaisesRegex(InstallError, "injected-failure"):
                    install(
                        self.consumer,
                        str(self.upstream),
                        "main",
                        fault_injector=fail_at(point),
                    )
                self.assertEqual(b"agents original", (self.consumer / "AGENTS.md").read_bytes())
                self.assertFalse((self.consumer / "CLAUDE.md").exists())
                self.assertFalse((self.consumer / ".policyrelay").exists())

    def test_reinstall_failure_restores_previous_install_and_instructions(self) -> None:
        install(self.consumer, str(self.upstream), "main")
        before_agents = (self.consumer / "AGENTS.md").read_bytes()
        before_claude = (self.consumer / "CLAUDE.md").read_bytes()
        before_runtime = digest_tree(self.consumer / ".policyrelay")
        with self.assertRaises(InstallError):
            install(
                self.consumer,
                str(self.upstream),
                "release",
                fault_injector=fail_at("installation-after-agents"),
            )
        self.assertEqual(before_agents, (self.consumer / "AGENTS.md").read_bytes())
        self.assertEqual(before_claude, (self.consumer / "CLAUDE.md").read_bytes())
        self.assertEqual(before_runtime, digest_tree(self.consumer / ".policyrelay"))
        self.assertEqual("main", load_configuration(self.consumer).branch)

    def test_configuration_rejects_credential_url_and_unsafe_branch_without_echo(self) -> None:
        with self.assertRaises(InstallError) as caught:
            install(self.consumer, "https://SECRET@example.invalid/repo", "main")
        self.assertNotIn("SECRET", str(caught.exception))
        with self.assertRaises(InstallError):
            install(self.consumer, str(self.upstream), "--upload-pack=bad")


class SessionStartTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.consumer = self.root / "consumer"
        self.consumer.mkdir()
        (self.consumer / "unrelated.bin").write_bytes(b"preserve\x00me")
        subprocess.run(
            ["git", "init", "--quiet", "--initial-branch", "main", str(self.consumer)],
            check=True,
            capture_output=True,
        )
        git(self.consumer, "config", "user.email", "tests@example.invalid")
        git(self.consumer, "config", "user.name", "PolicyRelay Tests")
        git(self.consumer, "add", "unrelated.bin")
        git(self.consumer, "commit", "--quiet", "-m", "consumer fixture")
        self.upstream = create_upstream(self.root)
        install(self.consumer, str(self.upstream), "main")

    @property
    def managed(self) -> Path:
        return self.consumer / "security" / "PolicyRelay"

    def test_successful_first_sync_update_stale_removal_and_upstream_unchanged(self) -> None:
        consumer_head = git(self.consumer, "rev-parse", "HEAD").stdout
        consumer_config = (self.consumer / ".git" / "config").read_bytes()
        consumer_remotes = git(self.consumer, "remote", "-v").stdout
        first = session_start(self.consumer)
        self.assertEqual("activated", first.status)
        self.assertEqual(digest_tree(self.upstream / "bundle" / "payload"), digest_tree(self.managed))
        self.assertFalse((self.managed / "manifest.json").exists())
        self.assertFalse((self.managed / "wrapper.txt").exists())
        commit_update(self.upstream)
        upstream_head = git(self.upstream, "rev-parse", "HEAD").stdout
        upstream_status = git(self.upstream, "status", "--porcelain=v1").stdout
        upstream_config = (self.upstream / ".git" / "config").read_bytes()
        upstream_remotes = git(self.upstream, "remote", "-v").stdout
        second = session_start(self.consumer)
        self.assertEqual("activated", second.status)
        self.assertFalse((self.managed / "guidance" / "vulnerability-triage.md").exists())
        self.assertEqual(digest_tree(self.upstream / "bundle" / "payload"), digest_tree(self.managed))
        self.assertEqual(b"preserve\x00me", (self.consumer / "unrelated.bin").read_bytes())
        self.assertEqual(upstream_head, git(self.upstream, "rev-parse", "HEAD").stdout)
        self.assertEqual(upstream_status, git(self.upstream, "status", "--porcelain=v1").stdout)
        self.assertEqual(upstream_config, (self.upstream / ".git" / "config").read_bytes())
        self.assertEqual(upstream_remotes, git(self.upstream, "remote", "-v").stdout)
        self.assertEqual(consumer_head, git(self.consumer, "rev-parse", "HEAD").stdout)
        self.assertEqual(consumer_config, (self.consumer / ".git" / "config").read_bytes())
        self.assertEqual(consumer_remotes, git(self.consumer, "remote", "-v").stdout)

    def test_installed_session_command_runs_without_source_pythonpath(self) -> None:
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        result = subprocess.run(
            [str(self.consumer / ".policyrelay" / "session-start")],
            cwd=self.consumer,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"^OK status=activated .* routes=2\n$")

    def test_local_upstream_pack_objects_hook_is_not_executed(self) -> None:
        marker = self.root / "hook-executed"
        hook = self.root / "untrusted-pack-hook"
        hook.write_text(
            "#!/bin/sh\n"
            f"printf executed > {marker}\n"
            "exec git pack-objects \"$@\"\n",
            encoding="utf-8",
        )
        hook.chmod(0o700)
        git(self.upstream, "config", "uploadpack.packObjectsHook", str(hook))
        result = session_start(self.consumer)
        self.assertEqual("activated", result.status)
        self.assertFalse(marker.exists())

    def test_missing_source_branch_and_bundle_fail_closed(self) -> None:
        session_start(self.consumer)
        accepted = digest_tree(self.managed)
        cases: list[tuple[str, str, str]] = []
        cases.append(("missing-source", str(self.root / "missing"), "main"))
        cases.append(("missing-branch", str(self.upstream), "missing"))
        git(self.upstream, "tag", "tag-only")
        cases.append(("tag-is-not-branch", str(self.upstream), "tag-only"))
        no_bundle_root = self.root / "no-bundle-root"
        no_bundle_root.mkdir()
        no_bundle = create_upstream(no_bundle_root, include_bundle=False)
        cases.append(("missing-bundle", str(no_bundle), "main"))
        malformed_root = self.root / "malformed-bundle-root"
        malformed_root.mkdir()
        malformed_bundle = create_upstream(malformed_root, include_bundle=False)
        (malformed_bundle / "bundle").write_bytes(b"not a directory")
        git(malformed_bundle, "add", "bundle")
        git(malformed_bundle, "commit", "--quiet", "-m", "malformed bundle")
        cases.append(("malformed-bundle", str(malformed_bundle), "main"))
        for name, upstream, branch in cases:
            with self.subTest(name=name):
                install(self.consumer, upstream, branch)
                with self.assertRaises((LifecycleError, SyncError)):
                    session_start(self.consumer)
                self.assertEqual(accepted, digest_tree(self.managed))

    def test_malformed_and_symlink_configuration_fail_without_acquisition(self) -> None:
        session_start(self.consumer)
        accepted = digest_tree(self.managed)
        config = self.consumer / ".policyrelay" / "config.json"
        config.write_bytes(b'{"upstream":"SECRET","upstream":"duplicate"}')
        with self.assertRaises(LifecycleError) as caught:
            session_start(self.consumer)
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertEqual(accepted, digest_tree(self.managed))
        config.unlink()
        outside = self.root / "outside-config"
        outside.write_text('{}', encoding="utf-8")
        config.symlink_to(outside)
        with self.assertRaises(LifecycleError):
            session_start(self.consumer)
        self.assertEqual(accepted, digest_tree(self.managed))

    def test_cli_failure_is_bounded_and_does_not_echo_upstream_or_git_output(self) -> None:
        secret_location = str(self.root / ("SECRET-" + ("x" * 200)))
        install(self.consumer, secret_location, "main")
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(RUNTIME_SCRIPTS)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "policyrelay",
                "session-start",
                "--consumer-root",
                str(self.consumer),
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(1, result.returncode)
        self.assertLess(len(result.stderr), 1000)
        self.assertNotIn("SECRET", result.stderr)

    def test_invalid_bundle_and_lifecycle_failures_preserve_last_accepted(self) -> None:
        session_start(self.consumer)
        accepted = digest_tree(self.managed)
        manifest = self.upstream / "bundle" / "manifest.json"
        manifest.write_text("{SECRET-" + ("x" * 50_000), encoding="utf-8")
        git(self.upstream, "add", "bundle/manifest.json")
        git(self.upstream, "commit", "--quiet", "-m", "invalid")
        with self.assertRaises(SyncError) as caught:
            session_start(self.consumer)
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertEqual(accepted, digest_tree(self.managed))
        for point in ("acquisition-before-clone", "acquisition-after-clone", "synchronization-before-core"):
            with self.subTest(point=point):
                with self.assertRaises(LifecycleError):
                    session_start(self.consumer, fault_injector=fail_at(point))
                self.assertEqual(accepted, digest_tree(self.managed))

    def test_injected_core_staging_and_activation_failure_preserve_tree(self) -> None:
        session_start(self.consumer)
        accepted = digest_tree(self.managed)
        commit_update(self.upstream)
        for point in ("staging-after-snapshot", "activation-after-commit"):
            with self.subTest(point=point):
                with self.assertRaises(SyncError):
                    session_start(self.consumer, sync_fault_injector=fail_at(point))
                self.assertEqual(accepted, digest_tree(self.managed))

    def test_failed_first_run_leaves_managed_tree_absent(self) -> None:
        fresh = self.root / "fresh"
        fresh.mkdir()
        install(fresh, str(self.root / "missing"), "main")
        with self.assertRaises(LifecycleError):
            session_start(fresh)
        self.assertFalse((fresh / "security" / "PolicyRelay").exists())


if __name__ == "__main__":
    unittest.main()
