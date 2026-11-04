from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from policyrelay import SyncError, synchronize

from .support import ROOT, RUNTIME_SCRIPTS, copy_bundle, digest_tree, mutate_manifest


class InjectedFailure(RuntimeError):
    pass


def fail_at(expected: str):
    def inject(actual: str) -> None:
        if actual == expected:
            raise InjectedFailure(expected)
    return inject


def make_update(bundle: Path) -> None:
    guidance = bundle / "payload" / "guidance"
    (guidance / "vulnerability-triage.md").unlink()
    secure = guidance / "secure-coding.md"
    secure.write_text(secure.read_text() + "\nUpdate marker.\n", encoding="utf-8")
    (bundle / "payload" / "index.md").write_text(
        "# PolicyRelay guidance\n\n"
        "Choose the route matching the task.\n\n"
        "- [secure-coding](guidance/secure-coding.md) — changing code\n",
        encoding="utf-8",
    )
    def mutation(value: dict) -> None:
        value["bundleRevision"] = "2026-08-27.2"
        value["routes"] = value["routes"][:1]
    mutate_manifest(bundle, mutation)


class SynchronizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = copy_bundle(self.root / "candidate")
        self.consumer = self.root / "consumer"
        self.consumer.mkdir()
        (self.consumer / "README.txt").write_bytes(b"unrelated\x00data")

    @property
    def managed(self) -> Path:
        return self.consumer / "security" / "PolicyRelay"

    def test_successful_first_activation_materializes_exact_payload_only(self) -> None:
        security = self.consumer / "security"
        security.mkdir()
        (security / "unrelated.txt").write_bytes(b"keep me")
        result = synchronize(self.candidate, self.consumer)
        self.assertEqual("activated", result.status)
        self.assertEqual(digest_tree(self.candidate / "payload"), digest_tree(self.managed))
        self.assertFalse((self.managed / "manifest.json").exists())
        self.assertFalse((self.managed / "payload").exists())
        self.assertEqual(b"unrelated\x00data", (self.consumer / "README.txt").read_bytes())
        self.assertEqual(b"keep me", (security / "unrelated.txt").read_bytes())

    def test_valid_update_is_atomic_and_removes_stale_files(self) -> None:
        synchronize(self.candidate, self.consumer)
        old_digest = digest_tree(self.managed)
        make_update(self.candidate)
        result = synchronize(self.candidate, self.consumer)
        self.assertEqual("activated", result.status)
        self.assertNotEqual(old_digest, digest_tree(self.managed))
        self.assertEqual(digest_tree(self.candidate / "payload"), digest_tree(self.managed))
        self.assertFalse((self.managed / "guidance" / "vulnerability-triage.md").exists())

    def test_identical_repeat_is_idempotent_without_replacing_target(self) -> None:
        synchronize(self.candidate, self.consumer)
        before = self.managed.stat().st_ino
        result = synchronize(self.candidate, self.consumer)
        self.assertEqual("unchanged", result.status)
        self.assertEqual(before, self.managed.stat().st_ino)

    def test_malformed_replacement_preserves_last_accepted_bytes(self) -> None:
        synchronize(self.candidate, self.consumer)
        accepted = digest_tree(self.managed)
        (self.candidate / "manifest.json").write_text("{malformed SECRET-CONTENT")
        with self.assertRaisesRegex(SyncError, "candidate-rejected") as caught:
            synchronize(self.candidate, self.consumer)
        self.assertEqual(accepted, digest_tree(self.managed))
        self.assertNotIn("SECRET-CONTENT", str(caught.exception))

    def test_representative_contract_rejections_preserve_last_accepted_bytes(self) -> None:
        synchronize(self.candidate, self.consumer)
        accepted = digest_tree(self.managed)

        def unsupported(bundle: Path) -> None:
            mutate_manifest(bundle, lambda value: value.__setitem__("contractVersion", "2.0"))

        def escaping_link(bundle: Path) -> None:
            path = bundle / "payload" / "guidance" / "secure-coding.md"
            path.write_text(path.read_text() + "\n[outside](../../outside.md)\n")

        def encoded_link(bundle: Path) -> None:
            path = bundle / "payload" / "guidance" / "secure-coding.md"
            path.write_text(path.read_text() + "\n[outside](%2e%2e/outside.md)\n")

        def escaping_route(bundle: Path) -> None:
            mutate_manifest(
                bundle,
                lambda value: value["routes"][0].__setitem__("entrypoint", "../outside.md"),
            )

        def invalid_utf8(bundle: Path) -> None:
            (bundle / "payload" / "index.md").write_bytes(b"\xff")

        cases = {
            "unsupported": unsupported,
            "escaping-link": escaping_link,
            "encoded-link": encoded_link,
            "escaping-route": escaping_route,
            "invalid-utf8": invalid_utf8,
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                bundle = copy_bundle(self.root / f"bad-{name}")
                mutation(bundle)
                with self.assertRaises(SyncError):
                    synchronize(bundle, self.consumer)
                self.assertEqual(accepted, digest_tree(self.managed))

    def test_failed_first_run_leaves_managed_target_absent(self) -> None:
        mutate_manifest(self.candidate, lambda value: value.__setitem__("contractVersion", "9.9"))
        with self.assertRaises(SyncError):
            synchronize(self.candidate, self.consumer)
        self.assertFalse(self.managed.exists())

    def test_candidate_symlink_is_never_followed(self) -> None:
        path = self.candidate / "payload" / "guidance" / "secure-coding.md"
        path.unlink()
        path.symlink_to(self.consumer / "README.txt")
        with self.assertRaises(SyncError) as caught:
            synchronize(self.candidate, self.consumer)
        self.assertEqual(("staging", "snapshot-failed"), (caught.exception.phase, caught.exception.code))
        self.assertFalse(self.managed.exists())

    def test_consumer_security_symlink_is_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.consumer / "security").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SyncError):
            synchronize(self.candidate, self.consumer)
        self.assertEqual([], list(outside.iterdir()))

    def test_lock_symlink_is_rejected_without_touching_target(self) -> None:
        security = self.consumer / "security"
        security.mkdir()
        outside = self.root / "outside-lock"
        outside.write_bytes(b"preserve")
        (security / ".PolicyRelay.lock").symlink_to(outside)
        with self.assertRaises(SyncError):
            synchronize(self.candidate, self.consumer)
        self.assertEqual(b"preserve", outside.read_bytes())
        self.assertFalse(self.managed.exists())

    def test_each_injected_transition_failure_preserves_accepted_tree(self) -> None:
        synchronize(self.candidate, self.consumer)
        make_update(self.candidate)
        accepted = digest_tree(self.managed)
        points = {
            "staging-after-snapshot": "staging",
            "parse-before-validation": "parse",
            "validation-after-checks": "validation",
            "materialization-after-copy": "staging",
            "activation-before-commit": "activation",
            "activation-after-commit": "activation",
        }
        for point, expected_phase in points.items():
            with self.subTest(point=point):
                with self.assertRaises(SyncError) as caught:
                    synchronize(self.candidate, self.consumer, fault_injector=fail_at(point))
                self.assertEqual(expected_phase, caught.exception.phase)
                self.assertEqual(accepted, digest_tree(self.managed))

    def test_injected_activation_failure_on_first_run_rolls_back_to_absent(self) -> None:
        with self.assertRaises(SyncError):
            synchronize(
                self.candidate,
                self.consumer,
                fault_injector=fail_at("activation-after-commit"),
            )
        self.assertFalse(self.managed.exists())

    def test_cli_has_deterministic_success_and_bounded_failure_output(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(RUNTIME_SCRIPTS)
        command = [
            sys.executable,
            "-m",
            "policyrelay",
            "sync",
            "--candidate",
            str(self.candidate),
            "--consumer-root",
            str(self.consumer),
        ]
        success = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
        self.assertEqual(0, success.returncode, success.stderr)
        self.assertRegex(success.stdout, r"^OK status=activated .* routes=2\n$")
        (self.candidate / "manifest.json").write_text('{"SECRET-' + ("x" * 50_000))
        failure = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True)
        self.assertEqual(1, failure.returncode)
        self.assertLess(len(failure.stderr), 8_000)
        self.assertNotIn("SECRET", failure.stderr)

    def test_accepted_positional_sync_cli_remains_available(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(RUNTIME_SCRIPTS)
        result = subprocess.run(
            [sys.executable, "-m", "policyrelay", str(self.candidate), str(self.consumer)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout, r"^OK status=activated .* routes=2\n$")


if __name__ == "__main__":
    unittest.main()
