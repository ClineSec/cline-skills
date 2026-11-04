from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


class IntegratedMvpProof(unittest.TestCase):
    """One end-to-end proof of the charter's disposable two-catalog workflow."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.name == "nt" and not POWERSHELL:
            raise unittest.SkipTest("native PowerShell is required on Windows")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="team skills integrated mvp ")
        self.base = Path(self.temporary.name)
        self.home = self.base / "disposable home"
        self.state = self.base / "state root"
        self.agents = self.home / ".agents" / "skills"
        self.claude = self.home / ".claude" / "skills"
        self.hook_files = {
            "claude": self.home / "config roots" / "claude" / "settings.json",
            "codex": self.home / "config roots" / "codex" / "hooks.json",
            "cursor": self.home / "config roots" / "cursor" / "hooks.json",
        }
        self.home.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "LOCALAPPDATA": str(self.home / "AppData" / "Local"),
                "TEAM_SKILLS_STATE_ROOT": str(self.state),
                "TEAM_SKILLS_AGENTS_ROOT": str(self.agents),
                "TEAM_SKILLS_CLAUDE_ROOT": str(self.claude),
                "TEAM_SKILLS_CLAUDE_HOOKS_FILE": str(self.hook_files["claude"]),
                "TEAM_SKILLS_CODEX_HOOKS_FILE": str(self.hook_files["codex"]),
                "TEAM_SKILLS_CURSOR_HOOKS_FILE": str(self.hook_files["cursor"]),
                "GIT_CONFIG_NOSYSTEM": "1",
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=self.env, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def make_catalog(self, label: str, version: str) -> tuple[Path, Path]:
        work = self.base / f"{label} work"
        origin = self.base / f"{label} origin.git"
        skill = work / "skills" / "common-skill"
        skill.mkdir(parents=True)
        manifest = {
            "$schema": "./schemas/catalog.schema.json",
            "schema_version": 1,
            "catalog_id": "same-catalog-id",
            "display_name": label,
            "skills_directory": "skills",
            "default_prefix": "",
        }
        (work / "catalog.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (skill / "SKILL.md").write_text(
            "---\nname: common-skill\ndescription: Integrated MVP fixture.\n---\n\n"
            f"# {label} {version}\n",
            encoding="utf-8",
        )
        runtime = work / "scripts"
        runtime.mkdir()
        for runtime_name in ("team-skills.sh", "team-skills-json.awk", "team-skills.ps1"):
            shutil.copy2(ROOT / "scripts" / runtime_name, runtime / runtime_name)
        self.git("init", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Integrated MVP Test", cwd=work)
        self.git("config", "user.email", "mvp@example.invalid", cwd=work)
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", f"{label} {version}", cwd=work)
        self.git("init", "--bare", str(origin))
        self.git("remote", "add", "origin", str(origin), cwd=work)
        self.git("push", "-u", "origin", "main", cwd=work)
        self.git("symbolic-ref", "HEAD", "refs/heads/main", cwd=origin)
        return work, origin

    def run_runtime(self, action: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        if os.name == "nt":
            command = [
                POWERSHELL or "powershell",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROOT / "scripts" / "team-skills.ps1"),
                action,
                *arguments,
            ]
        else:
            command = ["sh", str(ROOT / "scripts" / "team-skills.sh"), action, *arguments]
        return subprocess.run(
            command, env=self.env, text=True, capture_output=True, check=False, timeout=60
        )

    def install(self, origin: Path, prefix: str | None = None) -> subprocess.CompletedProcess[str]:
        arguments = [str(origin)]
        if prefix is not None:
            arguments.extend(["-Prefix" if os.name == "nt" else "--prefix", prefix])
        arguments.append("-SetupAutoUpdate" if os.name == "nt" else "--setup-auto-update")
        return self.run_runtime("install", *arguments)

    def remove(self, origin: Path, prefix: str | None = None) -> subprocess.CompletedProcess[str]:
        arguments = [str(origin)]
        if prefix is not None:
            arguments.extend(["-Prefix" if os.name == "nt" else "--prefix", prefix])
        return self.run_runtime("remove", *arguments)

    def read_json(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8-sig"))

    def command_values(self, value: Any) -> list[str]:
        commands: list[str] = []
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "command" and isinstance(child, str):
                    commands.append(child)
                else:
                    commands.extend(self.command_values(child))
        elif isinstance(value, list):
            for child in value:
                commands.extend(self.command_values(child))
        return commands

    def instance_by_origin(self) -> dict[str, Path]:
        instances = list((self.state / "catalogs").iterdir())
        return {
            self.git("remote", "get-url", "origin", cwd=instance / "repo").stdout.strip(): instance
            for instance in instances
        }

    def advance(self, work: Path, old: str, new: str) -> None:
        skill = work / "skills" / "common-skill" / "SKILL.md"
        skill.write_text(skill.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", new.removeprefix("# "), cwd=work)
        self.git("push", cwd=work)

    def seed_foreign_configuration(self) -> None:
        values = {
            "claude": {
                "permissions": {"allow": ["Read"]},
                "hooks": {"PreToolUse": [{"hooks": [{"command": "foreign-claude"}]}]},
            },
            "codex": {
                "description": "Keep this unrelated Codex configuration",
                "hooks": {
                    "Other": [
                        {
                            "matcher": "startup",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "foreign-codex",
                                    "async": True,
                                }
                            ],
                        }
                    ]
                },
            },
            "cursor": {
                "version": 1,
                "hooks": {
                    "sessionStart": [{"command": "foreign-cursor"}],
                    "workspaceOpen": [{"command": "foreign-workspace"}],
                },
            },
        }
        for product, path in self.hook_files.items():
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(values[product]), encoding="utf-8")

    def assert_foreign_configuration(self) -> None:
        claude = self.read_json(self.hook_files["claude"])
        codex = self.read_json(self.hook_files["codex"])
        cursor = self.read_json(self.hook_files["cursor"])
        self.assertEqual(claude["permissions"], {"allow": ["Read"]})
        self.assertIn("foreign-claude", self.command_values(claude))
        self.assertEqual(codex["description"], "Keep this unrelated Codex configuration")
        self.assertIn("foreign-codex", self.command_values(codex))
        self.assertEqual(cursor["hooks"]["workspaceOpen"], [{"command": "foreign-workspace"}])
        self.assertIn("foreign-cursor", self.command_values(cursor))

    def test_disposable_two_catalog_mvp_end_to_end(self) -> None:
        self.seed_foreign_configuration()
        first_work, first_origin = self.make_catalog("First catalog", "v1")
        _, second_origin = self.make_catalog("Second catalog", "v1")

        first = self.install(first_origin)
        self.assertEqual(first.returncode, 0, first.stderr)
        repeated = self.install(first_origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        first_bytes = {
            root: (root / "common-skill" / "SKILL.md").read_bytes()
            for root in (self.agents, self.claude)
        }

        collision = self.install(second_origin)
        self.assertEqual(collision.returncode, 0, collision.stderr)
        self.assertIn("warning: catalog same-catalog-id skill common-skill skipped", collision.stderr)
        for root in (self.agents, self.claude):
            self.assertEqual(
                (root / "common-skill" / "SKILL.md").read_bytes(), first_bytes[root]
            )

        prefixed = self.install(second_origin, "second")
        self.assertEqual(prefixed.returncode, 0, prefixed.stderr)
        for root in (self.agents, self.claude):
            generated = root / "second-common-skill"
            self.assertTrue(generated.exists())
            text = (generated / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("name: second-common-skill", text)
            self.assertIn("# Second catalog v1", text)

        instances = self.instance_by_origin()
        self.assertEqual(set(instances), {str(first_origin), str(second_origin)})
        first_instance = instances[str(first_origin)]
        second_instance = instances[str(second_origin)]
        self.assertNotEqual(first_instance.name, second_instance.name)

        second_view_before = (self.agents / "second-common-skill" / "SKILL.md").read_bytes()
        second_head_before = self.git("rev-parse", "HEAD", cwd=second_instance / "repo").stdout
        self.advance(first_work, "# First catalog v1", "# First catalog v2")
        self.env.update({"TEAM_SKILLS_THROTTLE_SECONDS": "0", "TEAM_SKILLS_NOW": "2000000000"})
        updated = self.run_runtime("update-instance", first_instance.name)
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertIn(
            "# First catalog v2",
            (self.agents / "common-skill" / "SKILL.md").read_text(encoding="utf-8"),
        )
        self.assertEqual(
            (self.agents / "second-common-skill" / "SKILL.md").read_bytes(), second_view_before
        )
        self.assertEqual(
            self.git("rev-parse", "HEAD", cwd=second_instance / "repo").stdout,
            second_head_before,
        )
        self.assertFalse((second_instance / "last-success").exists())

        # The URL-free hook path fails open, retains v2, redacts credentials, then retries cleanly.
        secret_origin = "file://fixture-user:fixture-password@/definitely/missing/catalog.git"
        self.git("remote", "set-url", "origin", secret_origin, cwd=first_instance / "repo")
        self.env["TEAM_SKILLS_NOW"] = "2000000001"
        self.env["TEAM_SKILLS_TEST_FOREGROUND"] = "1"
        failed_open = self.run_runtime("hook", first_instance.name)
        self.assertEqual(failed_open.returncode, 0, failed_open.stderr)
        log = (first_instance / "last-update.log").read_text(encoding="utf-8-sig")
        self.assertIn("configured origin identity changed", log)
        self.assertNotIn("fixture-user", log)
        self.assertNotIn("fixture-password", log)
        self.assertIn(
            "# First catalog v2",
            (self.claude / "common-skill" / "SKILL.md").read_text(encoding="utf-8"),
        )

        self.git("remote", "set-url", "origin", str(first_origin), cwd=first_instance / "repo")
        self.advance(first_work, "# First catalog v2", "# First catalog v3")
        self.env["TEAM_SKILLS_NOW"] = "2000000002"
        retried = self.run_runtime("update-instance", first_instance.name)
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn(
            "# First catalog v3",
            (self.agents / "common-skill" / "SKILL.md").read_text(encoding="utf-8"),
        )

        # Each exact owned command occurs once after repeated installs; all foreign data survived.
        self.assertEqual(self.install(second_origin, "second").returncode, 0)
        for instance in (first_instance, second_instance):
            for product, config_path in self.hook_files.items():
                owner_lines = (instance / "hooks" / f"{product}.owner").read_text(
                    encoding="utf-8-sig"
                ).splitlines()
                self.assertGreaterEqual(len(owner_lines), 2)
                self.assertEqual(self.command_values(self.read_json(config_path)).count(owner_lines[1]), 1)
        self.assert_foreign_configuration()

        self.assertEqual(self.remove(second_origin).returncode, 0)
        removed_final = self.remove(second_origin, "second")
        self.assertEqual(removed_final.returncode, 0, removed_final.stderr)
        self.assertFalse(second_instance.exists())
        self.assertFalse((self.agents / "second-common-skill").exists())
        self.assertIn(
            "# First catalog v3",
            (self.claude / "common-skill" / "SKILL.md").read_text(encoding="utf-8"),
        )
        for product, config_path in self.hook_files.items():
            remaining = self.command_values(self.read_json(config_path))
            first_command = (first_instance / "hooks" / f"{product}.owner").read_text(
                encoding="utf-8-sig"
            ).splitlines()[1]
            self.assertEqual(remaining.count(first_command), 1)
        self.assert_foreign_configuration()


if __name__ == "__main__":
    unittest.main()
