from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate.py"
CREATOR_PATH = ROOT / "skills" / "skill-creator" / "scripts" / "create_skill.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("team_skills_validator", VALIDATOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


validator = load_validator()


class FoundationTests(unittest.TestCase):
    def make_catalog(self, directory: Path) -> None:
        manifest = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
        (directory / "catalog.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (directory / "skills").mkdir()
        scripts = directory / "scripts"
        scripts.mkdir()
        for runtime_name in ("team-skills.sh", "team-skills-json.awk", "team-skills.ps1"):
            shutil.copy2(ROOT / "scripts" / runtime_name, scripts / runtime_name)

    def run_creator(self, root: Path, name: str = "release-notes") -> subprocess.CompletedProcess[str]:
        body = root / "body.md"
        body.write_text("# Release notes\n\nSummarize user-visible changes.\n", encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(CREATOR_PATH),
                name,
                "--catalog-root",
                str(root),
                "--description",
                "Draft release notes when a user asks for a changelog summary.",
                "--body-file",
                str(body),
                "--resources",
                "references,scripts",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_repository_validates(self) -> None:
        errors, count, catalog_id = validator.validate_catalog(ROOT)
        self.assertEqual(errors, [])
        self.assertEqual(count, sum(path.is_dir() for path in (ROOT / "skills").iterdir()))
        self.assertEqual(catalog_id, "cline-skills")

    def test_manifest_declares_blank_default_prefix(self) -> None:
        manifest = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "schemas" / "catalog.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["skills_directory"], "skills")
        self.assertEqual(manifest["default_prefix"], "")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(manifest))
        self.assertEqual(set(schema["properties"]), set(manifest))

    def test_effective_names_preserve_parent_name_contract(self) -> None:
        self.assertEqual(validator.effective_skill_name("", "skill-creator"), "skill-creator")
        self.assertEqual(
            validator.effective_skill_name("acme", "skill-creator"), "acme-skill-creator"
        )
        with self.assertRaisesRegex(ValueError, "exceeds 64"):
            validator.effective_skill_name("a" * 40, "b" * 24)

    def test_operational_code_has_no_baked_host_owner_or_upstream(self) -> None:
        operational_paths = (
            ROOT / "scripts" / "team-skills.sh",
            ROOT / "scripts" / "team-skills.ps1",
            ROOT / "scripts" / "team-skills-json.awk",
        )
        forbidden = ("appsecthings", "github.com", "raw.githubusercontent.com", "your-org")
        for path in operational_paths:
            text = path.read_text(encoding="utf-8").lower()
            for value in forbidden:
                self.assertNotIn(value, text, f"{path} contains baked upstream value {value}")

    def test_creator_scaffolds_a_complete_portable_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_catalog(root)
            result = self.run_creator(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            skill_dir = root / "skills" / "release-notes"
            properties = validator.read_skill(skill_dir)
            self.assertEqual(properties.name, "release-notes")
            self.assertTrue((skill_dir / "references").is_dir())
            self.assertTrue((skill_dir / "scripts").is_dir())
            errors, count, _ = validator.validate_catalog(root)
            self.assertEqual(errors, [])
            self.assertEqual(count, 1)

    def test_creator_refuses_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_catalog(root)
            first = self.run_creator(root)
            second = self.run_creator(root)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 2)
            self.assertIn("refusing to overwrite", second.stderr)

    def test_validator_rejects_name_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_catalog(root)
            skill_dir = root / "skills" / "portable-name"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: another-name\n"
                "description: A useful description.\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )
            errors, _, _ = validator.validate_catalog(root)
            self.assertTrue(any("must match parent 'portable-name'" in error for error in errors))

    def test_validator_and_creator_reject_duplicate_manifest_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_catalog(root)
            manifest = root / "catalog.json"
            source = manifest.read_text(encoding="utf-8")
            source = source.replace(
                '  "display_name": "Cline Skills",',
                '  "display_name": "first",\n  "\\u0064isplay_name": "Cline Skills",',
            )
            manifest.write_text(source, encoding="utf-8")
            errors, _, _ = validator.validate_catalog(root)
            self.assertTrue(any("duplicate JSON object key" in error for error in errors))
            created = self.run_creator(root)
            self.assertEqual(created.returncode, 2)
            self.assertIn("duplicate JSON object key", created.stderr)

    def test_validator_rejects_product_specific_frontmatter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_catalog(root)
            skill_dir = root / "skills" / "portable-name"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                "---\n"
                "name: portable-name\n"
                "description: A useful description.\n"
                "paths: '**/*.py'\n"
                "---\n\n"
                "# Instructions\n",
                encoding="utf-8",
            )
            errors, _, _ = validator.validate_catalog(root)
            self.assertTrue(any("nonportable frontmatter key 'paths'" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
