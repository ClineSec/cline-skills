from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from validate_bundle import (
    MAX_CLI_DIAGNOSTIC_CHARS,
    MAX_DIAGNOSTIC_LINE_CHARS,
    ValidationError,
    validate_bundle,
)


ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / "fixtures" / "reference-bundle"
VALIDATOR = ROOT.parents[1] / "skills" / "policy-relay-distill" / "scripts" / "validate_bundle.py"


class BundleValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name) / "bundle"
        shutil.copytree(REFERENCE, self.bundle)

    def errors(self) -> list[ValidationError]:
        return validate_bundle(self.bundle)

    def assert_has_code(self, errors: list[ValidationError], code: str) -> None:
        self.assertIn(code, {error.code for error in errors}, [error.render() for error in errors])

    def mutate_manifest(self, mutation: Callable[[dict[str, Any]], None]) -> None:
        path = self.bundle / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        mutation(manifest)
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def mutate_metadata(self, relative: str, mutation: Callable[[dict[str, Any]], None]) -> None:
        path = self.bundle / relative
        text = path.read_text(encoding="utf-8")
        closing = text.index("\n---\n", 4)
        metadata = json.loads(text[4:closing])
        mutation(metadata)
        replacement = "---\n" + json.dumps(metadata, indent=2) + text[closing:]
        path.write_text(replacement, encoding="utf-8")

    def test_reference_bundle_is_valid(self) -> None:
        self.assertEqual([], self.errors())

    def test_cli_accepts_reference_bundle(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.bundle)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("VALID contractVersion=1.0 routes=2\n", result.stdout)
        self.assertEqual("", result.stderr)

    def test_cli_diagnostics_do_not_expose_oversized_route_task(self) -> None:
        secret_marker = "secret-diagnostic-"
        oversized_task = secret_marker + ("x" * 50_000)
        self.mutate_manifest(
            lambda manifest: manifest["routes"][0].__setitem__("task", oversized_task)
        )

        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.bundle)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn(secret_marker, result.stderr)
        self.assertLessEqual(len(result.stderr), MAX_CLI_DIAGNOSTIC_CHARS)
        self.assertTrue(
            all(
                len(line) <= MAX_DIAGNOSTIC_LINE_CHARS
                for line in result.stderr.splitlines()
                if line.startswith("ERROR ")
            )
        )

    def test_cli_omits_excess_diagnostics_within_total_bound(self) -> None:
        self.mutate_manifest(
            lambda manifest: manifest.__setitem__("routes", [None] * 1_000)
        )

        result = subprocess.run(
            [sys.executable, str(VALIDATOR), str(self.bundle)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(1, result.returncode)
        self.assertLessEqual(len(result.stderr), MAX_CLI_DIAGNOSTIC_CHARS)
        self.assertIn("ERROR diagnostic-limit [.]: additional diagnostics omitted\n", result.stderr)
        self.assertRegex(result.stderr, r"INVALID errors=\d+\n$")

    def test_one_route_bundle_with_a_different_task_is_valid(self) -> None:
        source = self.bundle / "payload" / "guidance" / "secure-coding.md"
        target = self.bundle / "payload" / "guidance" / "change-review.md"
        text = source.read_text(encoding="utf-8")
        text = text.replace('"task": "secure-coding"', '"task": "change-review"')
        text = text.replace('"title": "Secure coding"', '"title": "Change review"')
        target.write_text(text.replace("# Secure coding", "# Change review"), encoding="utf-8")
        source.unlink()
        (self.bundle / "payload" / "guidance" / "vulnerability-triage.md").unlink()
        self.mutate_manifest(
            lambda manifest: manifest.__setitem__(
                "routes",
                [{"task": "change-review", "entrypoint": "guidance/change-review.md"}],
            )
        )
        (self.bundle / "payload" / "index.md").write_text(
            "# PolicyRelay guidance\n\n"
            "Choose the route matching the task and load only that document.\n\n"
            "- [change-review](guidance/change-review.md) — reviewing a proposed change\n",
            encoding="utf-8",
        )

        self.assertEqual([], self.errors())

    def test_missing_root_index_is_rejected(self) -> None:
        (self.bundle / "payload" / "index.md").unlink()
        self.assert_has_code(self.errors(), "root-index-missing")

    def test_root_index_must_be_a_regular_file(self) -> None:
        path = self.bundle / "payload" / "index.md"
        path.unlink()
        path.mkdir()
        self.assert_has_code(self.errors(), "file-type")

    def test_symlinked_guidance_is_rejected_without_following_it(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        outside = Path(self.temporary.name) / "outside.md"
        outside.write_bytes(b"\xff")
        path.unlink()
        path.symlink_to(outside)
        errors = self.errors()
        self.assert_has_code(errors, "symlink-forbidden")
        self.assertNotIn("utf8", {error.code for error in errors})

    def test_broken_local_link_is_rejected(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text(encoding="utf-8") + "\n[missing](missing.md)\n", encoding="utf-8")
        self.assert_has_code(self.errors(), "link-broken")

    def test_escaping_local_link_is_rejected(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text(encoding="utf-8") + "\n[outside](../../outside.md)\n", encoding="utf-8")
        self.assert_has_code(self.errors(), "link-escape")

    def test_unsupported_contract_version_is_rejected(self) -> None:
        self.mutate_manifest(lambda manifest: manifest.__setitem__("contractVersion", "2.0"))
        self.assert_has_code(self.errors(), "unsupported-version")

    def test_malformed_provenance_is_rejected(self) -> None:
        def remove_locator(metadata: dict[str, Any]) -> None:
            del metadata["provenance"][0]["sourceLocator"]

        self.mutate_metadata(
            "payload/guidance/secure-coding.md",
            remove_locator,
        )
        self.assert_has_code(self.errors(), "provenance-malformed")

    def test_empty_route_table_is_rejected(self) -> None:
        self.mutate_manifest(lambda manifest: manifest.__setitem__("routes", []))
        self.assert_has_code(self.errors(), "route-missing")

    def test_duplicate_task_route_is_rejected(self) -> None:
        def duplicate_task(manifest: dict[str, Any]) -> None:
            manifest["routes"][1]["task"] = manifest["routes"][0]["task"]

        self.mutate_manifest(duplicate_task)
        self.assert_has_code(self.errors(), "route-ambiguous")

    def test_duplicate_entrypoint_route_is_rejected(self) -> None:
        def duplicate_entrypoint(manifest: dict[str, Any]) -> None:
            manifest["routes"][1]["entrypoint"] = manifest["routes"][0]["entrypoint"]

        self.mutate_manifest(duplicate_entrypoint)
        self.assert_has_code(self.errors(), "route-ambiguous")

    def test_missing_declared_route_target_is_rejected(self) -> None:
        (self.bundle / "payload" / "guidance" / "vulnerability-triage.md").unlink()
        self.assert_has_code(self.errors(), "route-target-missing")

    def test_index_route_mismatch_is_rejected(self) -> None:
        path = self.bundle / "payload" / "index.md"
        text = path.read_text(encoding="utf-8").replace(
            "[secure-coding]", "[secure-review]"
        )
        path.write_text(text, encoding="utf-8")
        self.assert_has_code(self.errors(), "index-route-ambiguous")

    def test_diagnostics_are_deterministically_sorted(self) -> None:
        (self.bundle / "payload" / "index.md").unlink()
        self.mutate_manifest(lambda manifest: manifest.__setitem__("contractVersion", "9.9"))
        errors = self.errors()
        self.assertEqual(sorted(errors), errors)
        self.assertEqual(errors, self.errors())


if __name__ == "__main__":
    unittest.main()
