from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "team-skills.ps1"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "native PowerShell tests run on Windows CI")
class PowerShellInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="team skills ")
        self.base = Path(self.temporary.name)
        self.home = self.base / "disposable home"
        self.state = self.base / "state root"
        self.agents = self.home / ".agents" / "skills"
        self.claude = self.home / ".claude" / "skills"
        self.claude_hooks = self.home / "config roots" / "claude" / "settings.json"
        self.codex_hooks = self.home / "config roots" / "codex" / "hooks.json"
        self.cursor_hooks = self.home / "config roots" / "cursor" / "hooks.json"
        self.home.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            {
                "USERPROFILE": str(self.home),
                "LOCALAPPDATA": str(self.home / "AppData" / "Local"),
                "TEAM_SKILLS_STATE_ROOT": str(self.state),
                "TEAM_SKILLS_AGENTS_ROOT": str(self.agents),
                "TEAM_SKILLS_CLAUDE_ROOT": str(self.claude),
                "TEAM_SKILLS_CLAUDE_HOOKS_FILE": str(self.claude_hooks),
                "TEAM_SKILLS_CODEX_HOOKS_FILE": str(self.codex_hooks),
                "TEAM_SKILLS_CURSOR_HOOKS_FILE": str(self.cursor_hooks),
                "GIT_CONFIG_NOSYSTEM": "1",
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, check=False, env=self.env
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def make_catalog(self, label: str, body: str) -> tuple[Path, Path]:
        work = self.base / f"{label} work"
        origin = self.base / f"{label} origin.git"
        work.mkdir()
        manifest = {
            "$schema": "./schemas/catalog.schema.json",
            "schema_version": 1,
            "catalog_id": "shared-catalog-id",
            "display_name": label,
            "skills_directory": "skills",
            "default_prefix": "",
        }
        (work / "catalog.json").write_text(json.dumps(manifest, indent=2) + "\n")
        skill = work / "skills" / "common-skill"
        (skill / "references").mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            "---\nname: common-skill\ndescription: A fixture skill.\n---\n\n" + body + "\n",
            encoding="utf-8",
        )
        (skill / "references" / "fixture.txt").write_bytes(b"fixture bytes\r\n")
        runtime = work / "scripts"
        runtime.mkdir()
        shutil.copy2(INSTALLER, runtime / "team-skills.ps1")
        shutil.copy2(ROOT / "scripts" / "team-skills.sh", runtime / "team-skills.sh")
        shutil.copy2(ROOT / "scripts" / "team-skills-json.awk", runtime / "team-skills-json.awk")
        self.git("init", "--initial-branch=main", str(work))
        self.git("config", "user.name", "Installer Test", cwd=work)
        self.git("config", "user.email", "installer@example.invalid", cwd=work)
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "fixture catalog", cwd=work)
        self.git("init", "--bare", str(origin))
        self.git("remote", "add", "origin", str(origin), cwd=work)
        self.git("push", "-u", "origin", "main", cwd=work)
        self.git("symbolic-ref", "HEAD", "refs/heads/main", cwd=origin)
        return work, origin

    def run_installer(
        self, action: str, origin: Path | str, *extra: str, auto_update: bool = True
    ) -> subprocess.CompletedProcess[str]:
        assert POWERSHELL
        # Most lifecycle tests exercise an installation with hooks. Opt-in behavior is tested with
        # auto_update=False, which runs exactly the arguments given.
        if action == "install" and auto_update:
            extra = (*extra, "-SetupAutoUpdate")
        return subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(INSTALLER),
                action,
                str(origin),
                *extra,
            ],
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
        )

    def run_updater(self, action: str = "update-all", *extra: str) -> subprocess.CompletedProcess[str]:
        assert POWERSHELL
        return subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(INSTALLER),
                action,
                *extra,
            ],
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
            timeout=30,
        )

    def remove_junction(self, path: Path) -> None:
        # os.rmdir maps to RemoveDirectoryW and removes the junction, not its target.
        os.rmdir(path)

    def read_hook_config(self, product: str) -> dict:
        paths = {
            "claude": self.claude_hooks,
            "codex": self.codex_hooks,
            "cursor": self.cursor_hooks,
        }
        return json.loads(paths[product].read_text(encoding="utf-8-sig"))

    def owned_hook_commands(self, instance: Path | None = None) -> dict[str, str]:
        if instance is None:
            instance = next((self.state / "catalogs").iterdir())
        return {
            product: (instance / "hooks" / f"{product}.owner")
            .read_text(encoding="utf-8-sig")
            .splitlines()[1]
            for product in ("claude", "codex", "cursor")
        }

    def protect_and_read_acl(self, path: Path) -> str:
        assert POWERSHELL
        environment = self.env.copy()
        environment["TEAM_SKILLS_TEST_ACL_PATH"] = str(path)
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$ErrorActionPreference = 'Stop'; "
                "$sections = [System.Security.AccessControl.AccessControlSections]::Access; "
                "$acl = [System.IO.File]::GetAccessControl($env:TEAM_SKILLS_TEST_ACL_PATH, $sections); "
                "$acl.SetAccessRuleProtection($true, $true); "
                "[System.IO.File]::SetAccessControl($env:TEAM_SKILLS_TEST_ACL_PATH, $acl); "
                "$actual = [System.IO.File]::GetAccessControl($env:TEAM_SKILLS_TEST_ACL_PATH, $sections); "
                "$actual.GetSecurityDescriptorSddlForm($sections)",
            ],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().splitlines()[-1]

    def read_acl(self, path: Path) -> str:
        assert POWERSHELL
        environment = self.env.copy()
        environment["TEAM_SKILLS_TEST_ACL_PATH"] = str(path)
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$ErrorActionPreference = 'Stop'; "
                "$sections = [System.Security.AccessControl.AccessControlSections]::Access; "
                "$acl = [System.IO.File]::GetAccessControl($env:TEAM_SKILLS_TEST_ACL_PATH, $sections); "
                "$acl.GetSecurityDescriptorSddlForm($sections)",
            ],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().splitlines()[-1]

    def test_hook_registration_preserves_foreign_config_and_is_idempotent(self) -> None:
        _, origin = self.make_catalog("hooks", "# Hooks")
        for path in (self.claude_hooks, self.codex_hooks, self.cursor_hooks):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.claude_hooks.write_text(
            json.dumps(
                {
                    "foreign": {"preserve": True},
                    "hooks": {"PreToolUse": [{"hooks": [{"command": "foreign-claude"}]}]},
                }
            ),
            encoding="utf-8",
        )
        self.codex_hooks.write_text(
            json.dumps(
                {
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
                }
            ),
            encoding="utf-8",
        )
        self.cursor_hooks.write_text(
            json.dumps(
                {
                    "version": 1,
                    "foreign": [1, 2, 3],
                    "hooks": {"workspaceOpen": [{"command": "keep-workspace"}]},
                }
            ),
            encoding="utf-8",
        )

        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        commands = self.owned_hook_commands()
        claude = self.read_hook_config("claude")
        codex = self.read_hook_config("codex")
        cursor = self.read_hook_config("cursor")
        self.assertEqual(claude["foreign"], {"preserve": True})
        self.assertEqual(claude["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "foreign-claude")
        self.assertEqual(claude["hooks"]["SessionStart"][0]["matcher"], "startup|clear")
        self.assertEqual(claude["hooks"]["SessionStart"][0]["hooks"][0]["command"], commands["claude"])
        self.assertTrue(claude["hooks"]["SessionStart"][0]["hooks"][0]["async"])
        self.assertEqual(codex["description"], "Keep this unrelated Codex configuration")
        self.assertEqual(
            codex["hooks"]["Other"][0]["hooks"][0]["command"], "foreign-codex"
        )
        self.assertEqual(codex["hooks"]["SessionStart"][0]["matcher"], "startup|clear")
        self.assertEqual(codex["hooks"]["SessionStart"][0]["hooks"][0]["command"], commands["codex"])
        self.assertEqual(cursor["hooks"]["workspaceOpen"], [{"command": "keep-workspace"}])
        self.assertEqual(cursor["hooks"]["sessionStart"], [{"command": commands["cursor"]}])
        before = {
            product: json.dumps(self.read_hook_config(product), sort_keys=True)
            for product in ("claude", "codex", "cursor")
        }
        repeated = self.run_installer("install", origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(
            before,
            {
                product: json.dumps(self.read_hook_config(product), sort_keys=True)
                for product in ("claude", "codex", "cursor")
            },
        )

    def test_hook_config_acls_survive_install_reinstall_and_removal(self) -> None:
        _, origin = self.make_catalog("protected-hooks", "# Protected hooks")
        hook_paths = {
            "claude": self.claude_hooks,
            "codex": self.codex_hooks,
            "cursor": self.cursor_hooks,
        }
        expected_acls = {}
        for product, path in hook_paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            baseline = (
                {"description": "protected-codex"}
                if product == "codex"
                else {"foreign": product}
            )
            path.write_text(json.dumps(baseline) + "\n", encoding="utf-8")
            expected_acls[product] = self.protect_and_read_acl(path)

        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for product, path in hook_paths.items():
            self.assertEqual(self.read_acl(path), expected_acls[product])

        repeated = self.run_installer("install", origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        for product, path in hook_paths.items():
            self.assertEqual(self.read_acl(path), expected_acls[product])

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        for product, path in hook_paths.items():
            value = self.read_hook_config(product)
            self.assertNotIn("hooks", value)
            if product == "codex":
                self.assertEqual(value["description"], "protected-codex")
            else:
                self.assertEqual(value["foreign"], product)
            self.assertEqual(self.read_acl(path), expected_acls[product])

    def test_new_hook_configs_are_removed_with_the_final_catalog(self) -> None:
        _, origin = self.make_catalog("new-hook-files", "# New hook files")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for path in (self.claude_hooks, self.codex_hooks, self.cursor_hooks):
            self.assertTrue(path.is_file())

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        for path in (self.claude_hooks, self.codex_hooks, self.cursor_hooks):
            self.assertFalse(path.exists())

    def test_two_catalog_hooks_coexist_and_one_removal_is_exact(self) -> None:
        _, first_origin = self.make_catalog("first-hooks", "# First hooks")
        _, second_origin = self.make_catalog("second-hooks", "# Second hooks")
        self.cursor_hooks.parent.mkdir(parents=True)
        self.cursor_hooks.write_text(
            json.dumps({"hooks": {"sessionStart": [{"command": "foreign"}]}}),
            encoding="utf-8",
        )
        self.assertEqual(self.run_installer("install", first_origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", second_origin, "-Prefix", "second").returncode, 0
        )
        instances = list((self.state / "catalogs").iterdir())
        commands = {
            instance.name: self.owned_hook_commands(instance)["cursor"] for instance in instances
        }
        before = [entry["command"] for entry in self.read_hook_config("cursor")["hooks"]["sessionStart"]]
        self.assertEqual(set(before), {"foreign", *commands.values()})

        removed = self.run_installer("remove", first_origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        after = [entry["command"] for entry in self.read_hook_config("cursor")["hooks"]["sessionStart"]]
        self.assertIn("foreign", after)
        self.assertEqual(len([command for command in commands.values() if command in after]), 1)
        for product in ("claude", "codex", "cursor"):
            serialized = json.dumps(self.read_hook_config(product))
            self.assertNotIn(commands[next(key for key, value in commands.items() if value not in after)], serialized)

        removed_second = self.run_installer("remove", second_origin, "-Prefix", "second")
        self.assertEqual(removed_second.returncode, 0, removed_second.stderr)
        self.assertFalse(self.claude_hooks.exists())
        self.assertFalse(self.codex_hooks.exists())
        self.assertEqual(
            self.read_hook_config("cursor"),
            {"hooks": {"sessionStart": [{"command": "foreign"}]}},
        )

    def test_malformed_hook_config_refuses_install_without_overwrite(self) -> None:
        _, origin = self.make_catalog("malformed-hooks", "# Hooks")
        self.claude_hooks.parent.mkdir(parents=True)
        malformed = b'{"hooks":'
        self.claude_hooks.write_bytes(malformed)
        refused = self.run_installer("install", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("malformed, unsupported", refused.stderr)
        self.assertEqual(self.claude_hooks.read_bytes(), malformed)
        self.assertFalse(self.codex_hooks.exists())
        self.assertFalse(self.cursor_hooks.exists())

    def test_product_invalid_codex_root_refuses_install_without_overwrite(self) -> None:
        _, origin = self.make_catalog("invalid-codex-root", "# Hooks")
        self.codex_hooks.parent.mkdir(parents=True)
        invalid_values = (
            b'{ "foreign": true, "hooks": {"Other": []} }\r\n',
            b'{"description":7,"hooks":{}}\r\n',
        )
        for original in invalid_values:
            with self.subTest(original=original):
                self.codex_hooks.write_bytes(original)
                expected_acl = self.protect_and_read_acl(self.codex_hooks)

                refused = self.run_installer("install", origin)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("codex hook configuration is malformed, unsupported", refused.stderr)
                self.assertEqual(self.codex_hooks.read_bytes(), original)
                self.assertEqual(self.read_acl(self.codex_hooks), expected_acl)
                self.assertFalse(self.claude_hooks.exists())
                self.assertFalse(self.cursor_hooks.exists())
                self.assertFalse((self.agents / "common-skill").exists())

    def test_ambiguous_or_resource_exhausting_hook_json_is_refused_without_overwrite(self) -> None:
        _, origin = self.make_catalog("adversarial-hooks", "# Hooks")
        self.claude_hooks.parent.mkdir(parents=True)
        attacks = (
            b'{"foreign":1,"\\u0066oreign":2}',
            b'{"foreign":1,"FOREIGN":2}',
            ('{"a":' * 65 + '1' + '}' * 65).encode("utf-8"),
            ('{"value":"' + ('a' * 1048576) + '"}').encode("utf-8"),
        )
        for attack in attacks:
            with self.subTest(length=len(attack), prefix=attack[:32]):
                self.claude_hooks.write_bytes(attack)
                refused = self.run_installer("install", origin)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("malformed, unsupported", refused.stderr)
                self.assertEqual(self.claude_hooks.read_bytes(), attack)
                self.assertFalse(self.codex_hooks.exists())
                self.assertFalse(self.cursor_hooks.exists())

    def test_duplicate_manifest_key_is_rejected_before_bootstrap_install(self) -> None:
        work, origin = self.make_catalog("duplicate-manifest", "# Manifest")
        manifest = work / "catalog.json"
        source = manifest.read_text(encoding="utf-8")
        source = source.replace(
            '  "display_name": "duplicate-manifest",',
            '  "display_name": "first",\n  "\\u0064isplay_name": "duplicate-manifest",',
        )
        manifest.write_text(source, encoding="utf-8")
        self.git("add", "catalog.json", cwd=work)
        self.git("commit", "-m", "duplicate manifest key", cwd=work)
        self.git("push", cwd=work)

        refused = self.run_installer("install", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("not a valid catalog", refused.stderr)
        self.assertFalse((self.state / "catalogs").exists())

    def test_hook_command_handles_unicode_spaces_and_shell_metacharacters(self) -> None:
        self.state = self.base / "state root § & 'quoted'"
        self.env["TEAM_SKILLS_STATE_ROOT"] = str(self.state)
        _, origin = self.make_catalog("quoted-hooks", "# Hooks")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        command = self.owned_hook_commands()["claude"]
        self.assertIn("-EncodedCommand", command)
        self.assertNotIn(str(self.state), command)
        for product in ("claude", "codex", "cursor"):
            self.assertIn(command, json.dumps(self.read_hook_config(product)))

    def test_two_origins_collision_prefix_idempotence_and_safe_remove(self) -> None:
        _, first_origin = self.make_catalog("first", "# First catalog")
        _, second_origin = self.make_catalog("second", "# Second catalog")

        first = self.run_installer("install", first_origin)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_exposure = self.agents / "common-skill"
        self.assertIn("# First catalog", (first_exposure / "SKILL.md").read_text())

        repeated = self.run_installer("install", first_origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(len(list((self.state / "catalogs").iterdir())), 1)

        collision = self.run_installer("install", second_origin)
        self.assertEqual(collision.returncode, 0, collision.stderr)
        self.assertIn("warning", collision.stderr.lower())
        self.assertIn("common-skill skipped", collision.stderr)
        self.assertIn("# First catalog", (first_exposure / "SKILL.md").read_text())

        prefixed = self.run_installer("install", second_origin, "-Prefix", "second")
        self.assertEqual(prefixed.returncode, 0, prefixed.stderr)
        prefixed_exposure = self.claude / "second-common-skill"
        prefixed_text = (prefixed_exposure / "SKILL.md").read_text()
        self.assertIn("name: second-common-skill", prefixed_text)
        self.assertIn("# Second catalog", prefixed_text)
        self.assertEqual(
            (prefixed_exposure / "references" / "fixture.txt").read_bytes(), b"fixture bytes\r\n"
        )

        changed = self.claude / "common-skill"
        self.remove_junction(changed)
        changed.mkdir()
        marker = changed / "user-owned.txt"
        marker.write_bytes(b"preserve me byte-for-byte\r\n")
        removed = self.run_installer("remove", first_origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse(first_exposure.exists())
        self.assertEqual(marker.read_bytes(), b"preserve me byte-for-byte\r\n")
        self.assertIn("not removing changed path", removed.stderr)
        self.assertTrue(prefixed_exposure.exists())

    def test_owned_state_reparse_substitution_fails_without_removal(self) -> None:
        _, origin = self.make_catalog("owned-state-link", "# Owned state")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = next((self.state / "catalogs").iterdir())
        install_root = instance / "installs" / "_default"
        relocated = self.base / "relocated install state"
        install_root.rename(relocated)
        subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(install_root), str(relocated)],
            check=True,
            capture_output=True,
            text=True,
        )
        before_hooks = {
            product: (instance / "hooks" / f"{product}.owner").read_bytes()
            for product in ("claude", "codex", "cursor")
        }

        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("installation view is not an owned directory", refused.stderr)
        self.assertTrue((self.agents / "common-skill").exists())
        self.assertTrue(relocated.is_dir())
        for product, previous in before_hooks.items():
            self.assertEqual((instance / "hooks" / f"{product}.owner").read_bytes(), previous)

    def test_invalid_update_retains_last_known_good_and_output_hides_credentials(self) -> None:
        work, origin = self.make_catalog("update", "# Known good")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        exposed = self.agents / "common-skill" / "SKILL.md"
        original = exposed.read_bytes()

        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace(
                "name: common-skill", "name: mismatched-name"
            ),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "malformed update", cwd=work)
        self.git("push", cwd=work)
        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("keeping the last known-good installation", failed.stderr)
        self.assertEqual(exposed.read_bytes(), original)

        secret_url = "file://fixture-user:fixture-password@/definitely/missing/catalog.git"
        clone_failure = self.run_installer("install", secret_url)
        self.assertNotEqual(clone_failure.returncode, 0)
        combined = clone_failure.stdout + clone_failure.stderr
        self.assertNotIn("fixture-user", combined)
        self.assertNotIn("fixture-password", combined)
        self.assertIn("unable to clone the supplied repository", combined)

    def test_fast_forward_origin_change_is_rejected_with_remove_reinstall_recovery(self) -> None:
        work, initial_origin = self.make_catalog("initial", "# Initial origin")
        replacement_origin = self.base / "replacement origin.git"
        self.git("clone", "--bare", str(initial_origin), str(replacement_origin))
        skill = work / "skills" / "common-skill" / "SKILL.md"
        skill.write_text(skill.read_text().replace("# Initial origin", "# Replacement origin"))
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "fast-forward replacement", cwd=work)
        self.git("push", str(replacement_origin), "HEAD:main", cwd=work)
        installed = self.run_installer("install", initial_origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)

        instance_roots = list((self.state / "catalogs").iterdir())
        self.assertEqual(len(instance_roots), 1)
        managed_repo = instance_roots[0] / "repo"
        self.git("remote", "set-url", "origin", str(replacement_origin), cwd=managed_repo)

        reconciled = self.run_installer("install", initial_origin)
        self.assertNotEqual(reconciled.returncode, 0)
        self.assertIn("configured origin identity changed", reconciled.stderr)
        self.assertIn("# Initial origin", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual(list((self.state / "catalogs").iterdir()), instance_roots)

        removed = self.run_installer("remove", initial_origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse(self.agents.joinpath("common-skill").exists())
        reinstalled = self.run_installer("install", replacement_origin)
        self.assertEqual(reinstalled.returncode, 0, reinstalled.stderr)
        self.assertIn("# Replacement origin", (self.agents / "common-skill" / "SKILL.md").read_text())

    def test_remote_default_head_movement_is_followed_without_stale_tracking_ref(self) -> None:
        work, origin = self.make_catalog("default-head", "# Initial branch")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        self.git("switch", "-c", "next", cwd=work)
        skill = work / "skills" / "common-skill" / "SKILL.md"
        skill.write_text(skill.read_text().replace("# Initial branch", "# New default branch"))
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "move default head", cwd=work)
        self.git("push", "-u", "origin", "next", cwd=work)
        self.git("symbolic-ref", "HEAD", "refs/heads/next", cwd=origin)

        updated = self.run_installer("install", origin)
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertIn("# New default branch", (self.agents / "common-skill" / "SKILL.md").read_text())

    def test_invalid_fetched_lifecycle_runtime_cannot_advance_managed_clone(self) -> None:
        work, origin = self.make_catalog("runtime", "# Known good runtime")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        managed = instance / "repo"
        previous = self.git("rev-parse", "HEAD", cwd=managed).stdout.strip()
        runtime = work / "scripts" / "team-skills.ps1"
        runtime.write_text("param([string]$Broken\r\n", encoding="utf-8")
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "malformed lifecycle candidate", cwd=work)
        self.git("push", cwd=work)

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("fetched catalog is invalid", failed.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=managed).stdout.strip(), previous)
        self.assertIn("# Known good runtime", (self.agents / "common-skill" / "SKILL.md").read_text())

    def test_late_exposure_race_rolls_back_generation_and_ownership(self) -> None:
        work, origin = self.make_catalog("race", "# Known good")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        original = (self.agents / "common-skill" / "SKILL.md").read_bytes()

        common_skill = work / "skills" / "common-skill" / "SKILL.md"
        common_skill.write_text(
            common_skill.read_text(encoding="utf-8").replace("# Known good", "# Candidate"),
            encoding="utf-8",
        )
        # Creating several planned junctions makes the post-activation race deterministic on CI.
        for index in range(24):
            skill_name = f"a{index:02d}-filler-skill"
            skill = work / "skills" / skill_name
            skill.mkdir()
            (skill / "SKILL.md").write_text(
                f"---\nname: {skill_name}\ndescription: Race fixture.\n---\n\n# Filler\n",
                encoding="utf-8",
            )
        raced_skill = work / "skills" / "zz-race-skill"
        raced_skill.mkdir()
        (raced_skill / "SKILL.md").write_text(
            "---\nname: zz-race-skill\ndescription: Raced fixture.\n---\n\n# Raced\n",
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "valid raced candidate", cwd=work)
        self.git("push", cwd=work)

        race_path = self.agents / "zz-race-skill"
        race_created = threading.Event()
        stop_racer = threading.Event()

        def race_after_activation() -> None:
            while not stop_racer.is_set():
                try:
                    if b"# Candidate" in (self.agents / "common-skill" / "SKILL.md").read_bytes():
                        race_path.write_bytes(b"race winner\r\n")
                        race_created.set()
                        return
                except (FileNotFoundError, OSError):
                    pass
                time.sleep(0.001)

        racer = threading.Thread(target=race_after_activation, daemon=True)
        racer.start()
        failed = self.run_installer("install", origin)
        stop_racer.set()
        racer.join(timeout=5)

        self.assertTrue(race_created.is_set(), "test racer did not observe candidate activation")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cannot expose skill zz-race-skill", failed.stderr)
        self.assertEqual(race_path.read_bytes(), b"race winner\r\n")
        self.assertEqual((self.agents / "common-skill" / "SKILL.md").read_bytes(), original)

        install_root = next((self.state / "catalogs").iterdir()) / "installs" / "_default"
        self.assertIn("# Known good", (install_root / "current" / "common-skill" / "SKILL.md").read_text())
        self.assertFalse((install_root / "ownership" / "agents" / "zz-race-skill.owner").exists())
        for index in range(24):
            skill_name = f"a{index:02d}-filler-skill"
            self.assertFalse((self.agents / skill_name).exists())
            self.assertFalse((self.claude / skill_name).exists())
        for product_root, product in ((self.agents, "agents"), (self.claude, "claude")):
            owner_file = install_root / "ownership" / product / "common-skill.owner"
            self.assertTrue(owner_file.is_file())
            self.assertTrue((product_root / "common-skill").exists())

        race_path.unlink()
        rerun = self.run_installer("install", origin)
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("# Candidate", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertIn("# Raced", (self.claude / "zz-race-skill" / "SKILL.md").read_text())

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertFalse((self.claude / "zz-race-skill").exists())

    def test_remove_rejects_malformed_skill_ownership_before_mutation(self) -> None:
        _, origin = self.make_catalog("remove-owner", "# Remove owner validation")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        owner = instance / "installs" / "_default" / "ownership" / "agents" / "common-skill.owner"
        original_owner = owner.read_bytes()
        hooks = {
            path: path.read_bytes()
            for path in (self.claude_hooks, self.codex_hooks, self.cursor_hooks)
        }
        owner.unlink()
        owner.mkdir()

        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("agents skill ownership state is invalid", refused.stderr)
        self.assertTrue((self.agents / "common-skill").exists())
        self.assertTrue((self.claude / "common-skill").exists())
        for path, previous in hooks.items():
            self.assertEqual(path.read_bytes(), previous)

        owner.rmdir()
        owner.write_bytes(original_owner + b"unexpected\r\n")
        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("agents skill ownership state is invalid", refused.stderr)
        self.assertTrue((self.agents / "common-skill").exists())

        owner.write_bytes(original_owner)
        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)

    def test_url_free_update_reconciles_all_prefixes_at_one_candidate(self) -> None:
        work, initial_origin = self.make_catalog("all-prefixes", "# Initial")
        self.assertEqual(self.run_installer("install", initial_origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", initial_origin, "-Prefix", "fork").returncode, 0
        )

        instance = next((self.state / "catalogs").iterdir())
        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace("# Initial", "# Updated"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "update every prefix", cwd=work)
        self.git("push", cwd=work)
        self.env.update({"TEAM_SKILLS_NOW": "2000000000", "TEAM_SKILLS_THROTTLE_SECONDS": "0"})
        updated = self.run_updater()
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertIn("# Updated", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertIn(
            "# Updated", (self.claude / "fork-common-skill" / "SKILL.md").read_text()
        )
        self.assertEqual((instance / "last-success").read_text().strip(), "2000000000")

        # The updater discovers owned state and does not receive the bootstrap URL.
        self.assertTrue(work.is_dir())
        retried = self.run_updater()
        self.assertEqual(retried.returncode, 0, retried.stderr)

    def test_throttle_active_lock_and_stale_lock_recovery(self) -> None:
        _, origin = self.make_catalog("locking", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        managed_repo = instance / "repo"
        self.git("remote", "set-url", "origin", str(self.base / "missing origin"), cwd=managed_repo)

        (instance / "last-success").write_text("2000000000\n", encoding="utf-8")
        self.env.update({"TEAM_SKILLS_NOW": "2000000010", "TEAM_SKILLS_THROTTLE_SECONDS": "100"})
        throttled = self.run_updater("update-instance", instance.name)
        self.assertEqual(throttled.returncode, 0, throttled.stderr)

        (instance / "last-success").unlink()
        lock = instance / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text(f"{os.getpid()}\n2000000000\n", encoding="utf-8")
        locked = self.run_updater()
        self.assertEqual(locked.returncode, 0, locked.stderr)
        self.assertIn("skipped because its update lock is held", locked.stdout)
        self.assertTrue(lock.is_dir())

        shutil.rmtree(lock)
        self.git("remote", "set-url", "origin", str(origin), cwd=managed_repo)
        lock.mkdir()
        (lock / "owner").write_text("2147483000\n100\n", encoding="utf-8")
        self.env.update(
            {
                "TEAM_SKILLS_NOW": "2000000010",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
                "TEAM_SKILLS_STALE_LOCK_SECONDS": "100",
            }
        )
        recovered = self.run_updater()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertFalse(lock.exists())

    def test_remove_refuses_active_update_lock_before_mutation(self) -> None:
        _, origin = self.make_catalog("remove-locked", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        lock = instance / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text(f"{os.getpid()}\n2000000000\n", encoding="utf-8")
        hook_paths = (self.claude_hooks, self.codex_hooks, self.cursor_hooks)
        hooks_before = [path.read_bytes() for path in hook_paths]

        refused = self.run_installer("remove", origin)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("catalog update is in progress", refused.stderr)
        self.assertTrue(instance.is_dir())
        self.assertTrue((self.agents / "common-skill").exists())
        self.assertTrue(lock.is_dir())
        self.assertEqual([path.read_bytes() for path in hook_paths], hooks_before)

    def test_hook_masks_fetch_failure_and_writes_credential_safe_log(self) -> None:
        _, origin = self.make_catalog("hook-failure", "# Known good")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        secret_origin = "file://fixture-user:fixture-password@/definitely/missing/catalog.git"
        self.git("remote", "set-url", "origin", secret_origin, cwd=instance / "repo")
        original = (self.agents / "common-skill" / "SKILL.md").read_bytes()
        self.env.update(
            {
                "TEAM_SKILLS_TEST_FOREGROUND": "1",
                "TEAM_SKILLS_NOW": "2000000000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )

        hooked = self.run_updater("hook", instance.name)
        self.assertEqual(hooked.returncode, 0, hooked.stderr)
        log = (instance / "last-update.log").read_text(encoding="utf-8")
        self.assertIn("configured origin identity changed", log)
        self.assertNotIn("fixture-user", log)
        self.assertNotIn("fixture-password", log)
        self.assertEqual((self.agents / "common-skill" / "SKILL.md").read_bytes(), original)

    def test_concurrent_updates_fetch_once(self) -> None:
        _, origin = self.make_catalog("concurrent", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        command_bin = self.base / "concurrency command bin"
        command_bin.mkdir()
        git_wrapper = command_bin / "git.cmd"
        git_wrapper.write_text(
            "@echo off\r\n"
            "if /I \"%~1\"==\"-C\" if /I \"%~3\"==\"fetch\" (\r\n"
            "  >>\"%TEAM_SKILLS_TEST_FETCH_LOG%\" echo fetch\r\n"
            "  \"%TEAM_SKILLS_TEST_POWERSHELL%\" -NoLogo -NoProfile -NonInteractive "
            "-Command \"Start-Sleep -Seconds 2\"\r\n"
            ")\r\n"
            "\"%TEAM_SKILLS_TEST_REAL_GIT%\" %*\r\n"
            "exit /b %ERRORLEVEL%\r\n",
            encoding="utf-8",
        )
        fetch_log = self.base / "fetch calls.log"
        self.env.update(
            {
                "PATH": str(command_bin) + os.pathsep + self.env["PATH"],
                "TEAM_SKILLS_TEST_REAL_GIT": real_git or "",
                "TEAM_SKILLS_TEST_POWERSHELL": POWERSHELL or "",
                "TEAM_SKILLS_TEST_FETCH_LOG": str(fetch_log),
                "TEAM_SKILLS_NOW": "2000000000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )
        command = [
            POWERSHELL or "powershell",
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(INSTALLER), "update-instance", instance.name,
        ]

        first = subprocess.Popen(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
        )
        deadline = time.monotonic() + 10
        while not fetch_log.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(fetch_log.exists(), "first updater did not reach fetch")
        second = self.run_updater("update-instance", instance.name)
        first_stdout, first_stderr = first.communicate(timeout=20)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.returncode, 0, first_stdout + first_stderr)
        self.assertEqual(fetch_log.read_text(encoding="utf-8").splitlines(), ["fetch"])

    def test_detached_hook_returns_promptly_and_bounds_log(self) -> None:
        _, origin = self.make_catalog("detached", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        runtime = instance / "repo" / "scripts" / "team-skills.ps1"
        source = runtime.read_text(encoding="utf-8")
        needle = (
            'if ($Action -ceq "update-instance") {\n'
            "        $script:UpdateDiagnostics.Clear()"
        )
        replacement = (
            'if ($Action -ceq "update-instance") {\n'
            "        $script:UpdateDiagnostics.Clear()\n"
            "        Start-Sleep -Seconds 3\n"
            "        Write-UpdateDiagnostic ('detached-marker:' + ('x' * 70000))"
        )
        self.assertIn(needle, source)
        runtime.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
        self.env.update(
            {
                "TEAM_SKILLS_NOW": "2000000000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )
        command = [
            POWERSHELL or "powershell",
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(runtime), "hook", instance.name,
        ]

        started = time.monotonic()
        launched = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
            timeout=2,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(launched.returncode, 0, launched.stderr)
        self.assertLess(elapsed, 1.5)

        log = instance / "last-update.log"
        deadline = time.monotonic() + 15
        while (not log.exists() or log.stat().st_size == 0) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(log.exists(), "detached updater did not produce a log")
        self.assertLessEqual(log.stat().st_size, 65536)
        self.assertNotIn("detached-marker", log.read_text(encoding="utf-8"))

    def test_update_all_isolates_failure_and_clean_retry_succeeds(self) -> None:
        first_work, first_origin = self.make_catalog("failure-first", "# First initial")
        second_work, second_origin = self.make_catalog("failure-second", "# Second initial")
        self.assertEqual(self.run_installer("install", first_origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", second_origin, "-Prefix", "second").returncode, 0
        )
        instances = list((self.state / "catalogs").iterdir())
        instance_by_origin = {
            self.git("remote", "get-url", "origin", cwd=instance / "repo").stdout.strip(): instance
            for instance in instances
        }
        first_instance = instance_by_origin[str(first_origin)]
        self.git(
            "remote", "set-url", "origin", str(self.base / "missing origin"),
            cwd=first_instance / "repo",
        )
        second_skill = second_work / "skills" / "common-skill" / "SKILL.md"
        second_skill.write_text(
            second_skill.read_text(encoding="utf-8").replace("# Second initial", "# Second updated"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=second_work)
        self.git("commit", "-m", "update second catalog", cwd=second_work)
        self.git("push", cwd=second_work)
        self.env.update({"TEAM_SKILLS_NOW": "2000000000", "TEAM_SKILLS_THROTTLE_SECONDS": "0"})

        isolated = self.run_updater()
        self.assertNotEqual(isolated.returncode, 0)
        self.assertIn("configured origin identity changed", isolated.stderr)
        self.assertIn(
            "# Second updated", (self.claude / "second-common-skill" / "SKILL.md").read_text()
        )

        self.git("remote", "set-url", "origin", str(first_origin), cwd=first_instance / "repo")
        first_skill = first_work / "skills" / "common-skill" / "SKILL.md"
        first_skill.write_text(
            first_skill.read_text(encoding="utf-8").replace("# First initial", "# First recovered"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=first_work)
        self.git("commit", "-m", "recover first catalog", cwd=first_work)
        self.git("push", cwd=first_work)
        self.env["TEAM_SKILLS_NOW"] = "2000000001"
        retried = self.run_updater()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn("# First recovered", (self.agents / "common-skill" / "SKILL.md").read_text())

    def hook_paths(self) -> dict[str, Path]:
        return {
            "claude": self.claude_hooks,
            "codex": self.codex_hooks,
            "cursor": self.cursor_hooks,
        }

    def advance_catalog(self, work: Path, old: str, new: str) -> None:
        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", new, cwd=work)
        self.git("push", cwd=work)

    def test_plain_install_registers_no_session_hook(self) -> None:
        _, origin = self.make_catalog("plain", "# Plain")
        result = self.run_installer("install", origin, auto_update=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Automatic updates are off", result.stdout)
        self.assertIn("# Plain", (self.agents / "common-skill" / "SKILL.md").read_text())
        for path in self.hook_paths().values():
            self.assertFalse(path.exists())
        instance = next((self.state / "catalogs").iterdir())
        self.assertFalse((instance / "hooks").exists())

    def test_setup_flag_enables_and_plain_rerun_keeps_the_setting(self) -> None:
        work, origin = self.make_catalog("enable-later", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        enabled = self.run_installer("install", origin, "-SetupAutoUpdate", auto_update=False)
        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertIn("Automatic updates are on", enabled.stdout)
        before = {name: path.read_bytes() for name, path in self.hook_paths().items()}
        self.advance_catalog(work, "# Initial", "# Second")

        rerun = self.run_installer("install", origin, auto_update=False)

        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("# Second", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual(
            {name: path.read_bytes() for name, path in self.hook_paths().items()}, before
        )

    def test_remove_auto_update_only_removes_hooks_and_never_fetches(self) -> None:
        work, origin = self.make_catalog("disable", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        self.advance_catalog(work, "# Initial", "# Unwanted")
        # A fetch of this origin would fail, so success proves the path stays offline.
        self.git("remote", "set-url", "origin", str(self.base / "missing origin"), cwd=instance / "repo")

        disabled = self.run_installer("install", origin, "-RemoveAutoUpdate", auto_update=False)

        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertIn("Automatic updates are off", disabled.stdout)
        self.assertIn("# Initial", (self.agents / "common-skill" / "SKILL.md").read_text())
        for path in self.hook_paths().values():
            self.assertFalse(path.exists())
        self.assertFalse((instance / "hooks").exists())
        self.assertFalse((instance / "update.lock").exists())

        repeated = self.run_installer("install", origin, "-RemoveAutoUpdate", auto_update=False)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertIn("already off", repeated.stdout)

    def test_remove_auto_update_requires_an_installed_catalog(self) -> None:
        missing = self.base / "never cloned origin.git"
        result = self.run_installer("install", missing, "-RemoveAutoUpdate", auto_update=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("catalog instance is not installed", result.stderr)

    def test_auto_update_flags_reject_invalid_combinations(self) -> None:
        _, origin = self.make_catalog("flags", "# Initial")
        both = self.run_installer(
            "install", origin, "-SetupAutoUpdate", "-RemoveAutoUpdate", auto_update=False
        )
        self.assertNotEqual(both.returncode, 0)
        self.assertIn("cannot be combined", both.stderr)
        on_remove = self.run_installer("remove", origin, "-SetupAutoUpdate")
        self.assertNotEqual(on_remove.returncode, 0)
        self.assertIn("require the install action", on_remove.stderr)
        with_prefix = self.run_installer(
            "install", origin, "-RemoveAutoUpdate", "-Prefix", "acme", auto_update=False
        )
        self.assertNotEqual(with_prefix.returncode, 0)
        self.assertIn("omit -Prefix", with_prefix.stderr)

    def test_final_remove_of_a_hookless_install_is_clean(self) -> None:
        _, origin = self.make_catalog("hookless-remove", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertEqual(list((self.state / "catalogs").iterdir()), [])

    def test_update_all_ignores_throttle_but_session_update_honors_it(self) -> None:
        work, origin = self.make_catalog("manual-now", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        instance = next((self.state / "catalogs").iterdir())
        self.env["TEAM_SKILLS_NOW"] = "2000000000"
        first = self.run_updater()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("already current at", first.stdout)

        self.advance_catalog(work, "# Initial", "# Second")
        self.env["TEAM_SKILLS_NOW"] = "2000000010"
        session = self.run_updater("update-instance", instance.name)
        self.assertEqual(session.returncode, 0, session.stderr)
        self.assertIn("# Initial", (self.agents / "common-skill" / "SKILL.md").read_text())

        manual = self.run_updater()
        self.assertEqual(manual.returncode, 0, manual.stderr)
        self.assertRegex(manual.stdout, r"updated [0-9a-f]{12} to [0-9a-f]{12}\.")
        self.assertIn("# Second", (self.agents / "common-skill" / "SKILL.md").read_text())


if __name__ == "__main__":
    unittest.main()
