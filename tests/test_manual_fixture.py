from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "prepare-manual-verification.py"


class ManualFixtureTests(unittest.TestCase):
    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER), *arguments],
            text=True,
            capture_output=True,
            check=False,
            timeout=90,
        )

    def test_prepare_advance_failure_fixture_and_restore_are_disposable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="team skills manual helper ") as temporary:
            parent = Path(temporary)
            fixture = parent / "new fixture"
            prepared = self.run_helper("prepare", str(fixture))
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self.assertIn("Human Claude Code, Codex, Cursor, and WSL results remain PENDING", prepared.stdout)

            metadata = json.loads((fixture / "fixture.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["root"], str(fixture.resolve()))
            self.assertEqual(metadata["expected"]["human_results"], "PENDING")
            self.assertIn("PENDING", (fixture / "RESULTS.md").read_text(encoding="utf-8"))
            self.assertTrue((fixture / "home" / ".agents" / "skills" / "common-skill").exists())
            generated = fixture / "home" / ".claude" / "skills" / "second-common-skill" / "SKILL.md"
            self.assertIn("name: second-common-skill", generated.read_text(encoding="utf-8"))
            transcript = (fixture / "evidence" / "install-transcript.txt").read_text(
                encoding="utf-8"
            )
            self.assertIn(
                "warning: catalog manual-shared-catalog-id skill common-skill skipped", transcript
            )

            refused = self.run_helper("prepare", str(fixture))
            self.assertEqual(refused.returncode, 2)
            self.assertIn("refusing to prepare over an existing path", refused.stderr)

            advanced = self.run_helper("advance", str(fixture), "first", "verified-v2")
            self.assertEqual(advanced.returncode, 0, advanced.stderr)
            metadata = json.loads((fixture / "fixture.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["catalogs"]["first"]["marker"], "verified-v2")

            unreachable = self.run_helper("origin", str(fixture), "first", "unreachable")
            self.assertEqual(unreachable.returncode, 0, unreachable.stderr)
            instance_repo = Path(metadata["catalogs"]["first"]["instance"]) / "repo"
            configured = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=instance_repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(configured.returncode, 0, configured.stderr)
            self.assertIn("manual-user:manual-secret", configured.stdout)

            restored = self.run_helper("origin", str(fixture), "first", "restore")
            self.assertEqual(restored.returncode, 0, restored.stderr)
            configured = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=instance_repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(configured.stdout.strip(), metadata["catalogs"]["first"]["origin"])

            # The process environment and normal home remain outside the fixture helper's scope.
            self.assertNotEqual(Path(os.environ.get("HOME", parent)).resolve(), fixture / "home")
            # Final manual removal legitimately deletes managed instance paths before cleanup.
            (fixture / "state" / "catalogs").rename(fixture / "state" / "removed-catalogs")
            cleaned = self.run_helper("cleanup", str(fixture))
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertFalse(fixture.exists())
            self.assertTrue(parent.is_dir())

    def test_mutated_or_ambiguous_ownership_metadata_cannot_redirect_operations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="team skills manual ownership ") as temporary:
            parent = Path(temporary)
            fixture = parent / "fixture"
            prepared = self.run_helper("prepare", str(fixture))
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            metadata_path = fixture / "fixture.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            original_work = Path(metadata["catalogs"]["first"]["work"])
            original_skill = original_work / "skills" / "common-skill" / "SKILL.md"
            original_bytes = original_skill.read_bytes()

            metadata["catalogs"]["first"]["work"] = metadata["catalogs"]["second"]["work"]
            metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            redirected = self.run_helper("advance", str(fixture), "first", "redirected")
            self.assertEqual(redirected.returncode, 2)
            self.assertIn("outside the owned fixture", redirected.stderr)
            self.assertEqual(original_skill.read_bytes(), original_bytes)

            duplicate = metadata_path.read_text(encoding="utf-8").replace(
                '"schema_version": 1,', '"schema_version": 1,\n  "schema_version": 1,', 1
            )
            metadata_path.write_text(duplicate, encoding="utf-8")
            ambiguous = self.run_helper("show", str(fixture))
            self.assertEqual(ambiguous.returncode, 2)
            self.assertIn("duplicate key 'schema_version'", ambiguous.stderr)


if __name__ == "__main__":
    unittest.main()
