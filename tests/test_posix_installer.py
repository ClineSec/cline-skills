from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "team-skills.sh"


@unittest.skipIf(os.name == "nt", "POSIX installer tests run on POSIX CI workers")
class PosixInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="team skills ")
        self.base = Path(self.temporary.name)
        self.home = self.base / "disposable home"
        self.state = self.base / "state root"
        self.agents = self.home / ".agents" / "skills"
        self.claude = self.home / ".claude" / "skills"
        self.home.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "TEAM_SKILLS_STATE_ROOT": str(self.state),
                "TEAM_SKILLS_AGENTS_ROOT": str(self.agents),
                "TEAM_SKILLS_CLAUDE_ROOT": str(self.claude),
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

    def make_catalog(
        self, label: str, body: str, *, executable_resource: bool = False
    ) -> tuple[Path, Path]:
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
        (skill / "scripts").mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            "---\nname: common-skill\ndescription: A fixture skill.\n---\n\n" + body + "\n",
            encoding="utf-8",
        )
        helper = skill / "scripts" / "helper.sh"
        helper.write_text("#!/bin/sh\nprintf 'fixture\\n'\n", encoding="utf-8")
        runtime = work / "scripts"
        runtime.mkdir()
        shutil.copy2(INSTALLER, runtime / "team-skills.sh")
        shutil.copy2(ROOT / "scripts" / "team-skills-json.awk", runtime / "team-skills-json.awk")
        shutil.copy2(ROOT / "scripts" / "team-skills.ps1", runtime / "team-skills.ps1")
        if executable_resource:
            helper.chmod(helper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
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
        # Most lifecycle tests exercise an installation with hooks. Opt-in behavior is tested with
        # auto_update=False, which runs exactly the arguments given.
        if action == "install" and auto_update:
            extra = (*extra, "--setup-auto-update")
        return subprocess.run(
            ["sh", str(INSTALLER), action, str(origin), *extra],
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
        )

    def run_updater(self, action: str = "update-all", *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(INSTALLER), action, *extra],
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
        )

    def instance_root(self) -> Path:
        roots = list((self.state / "catalogs").iterdir())
        self.assertEqual(len(roots), 1)
        return roots[0]

    def read_hook_config(self, product: str) -> dict:
        paths = {
            "claude": self.home / ".claude" / "settings.json",
            "codex": self.home / ".codex" / "hooks.json",
            "cursor": self.home / ".cursor" / "hooks.json",
        }
        return json.loads(paths[product].read_text(encoding="utf-8"))

    def owned_hook_commands(self) -> dict[str, str]:
        instance = self.instance_root()
        return {
            product: (instance / "hooks" / f"{product}.owner")
            .read_text(encoding="utf-8")
            .splitlines()[1]
            for product in ("claude", "codex", "cursor")
        }

    def test_hook_registration_preserves_foreign_config_and_is_idempotent(self) -> None:
        _, origin = self.make_catalog("hooks", "# Hooks")
        claude_config = self.home / ".claude" / "settings.json"
        codex_config = self.home / ".codex" / "hooks.json"
        cursor_config = self.home / ".cursor" / "hooks.json"
        for path in (claude_config, codex_config, cursor_config):
            path.parent.mkdir(parents=True, exist_ok=True)
        claude_config.write_text(
            json.dumps(
                {
                    "permissions": {"allow": ["Read"]},
                    "hooks": {"PreToolUse": [{"hooks": [{"command": "foreign-claude"}]}]},
                }
            ),
            encoding="utf-8",
        )
        codex_config.write_text(
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
        cursor_config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "sessionStart": [{"command": "foreign-cursor"}],
                        "workspaceOpen": [{"command": "keep-workspace"}],
                    },
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
        self.assertEqual(claude["permissions"], {"allow": ["Read"]})
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
        self.assertEqual(
            cursor["hooks"]["sessionStart"],
            [{"command": "foreign-cursor"}, {"command": commands["cursor"]}],
        )

        repeated = self.run_installer("install", origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        serialized = {
            product: json.dumps(self.read_hook_config(product), sort_keys=True)
            for product in ("claude", "codex", "cursor")
        }
        for product, command in commands.items():
            self.assertEqual(serialized[product].count(command), 1)

    def test_hook_config_modes_survive_install_reinstall_rollback_and_removal(self) -> None:
        _, origin = self.make_catalog("private-hooks", "# Private hooks")
        hook_paths = {
            "claude": self.home / ".claude" / "settings.json",
            "codex": self.home / ".codex" / "hooks.json",
            "cursor": self.home / ".cursor" / "hooks.json",
        }
        for product, path in hook_paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            baseline = (
                {"description": "private-codex"}
                if product == "codex"
                else {"foreign": product}
            )
            path.write_text(json.dumps(baseline) + "\n", encoding="utf-8")
            path.chmod(0o600)

        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for path in hook_paths.values():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        repeated = self.run_installer("install", origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        before_rollback = {product: path.read_bytes() for product, path in hook_paths.items()}
        for path in hook_paths.values():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        command_bin = self.base / "hook owner failure bin"
        command_bin.mkdir()
        real_mv = shutil.which("mv")
        self.assertIsNotNone(real_mv)
        mv_wrapper = command_bin / "mv"
        mv_wrapper.write_text(
            "#!/bin/sh\n"
            "for argument do\n"
            "  case $argument in\n"
            "    */hooks/.claude.owner.*) exit 97 ;;\n"
            "  esac\n"
            "done\n"
            'exec "$TEAM_SKILLS_TEST_REAL_MV" "$@"\n',
            encoding="utf-8",
        )
        mv_wrapper.chmod(0o755)
        original_path = self.env["PATH"]
        self.env["PATH"] = str(command_bin) + os.pathsep + original_path
        self.env["TEAM_SKILLS_TEST_REAL_MV"] = real_mv or ""

        rolled_back = self.run_installer("install", origin)
        self.assertNotEqual(rolled_back.returncode, 0)
        self.assertIn("cannot record claude hook ownership", rolled_back.stderr)
        for product, path in hook_paths.items():
            self.assertEqual(path.read_bytes(), before_rollback[product])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        self.env["PATH"] = original_path
        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        for product, path in hook_paths.items():
            value = self.read_hook_config(product)
            self.assertNotIn("hooks", value)
            if product == "codex":
                self.assertEqual(value["description"], "private-codex")
            else:
                self.assertEqual(value["foreign"], product)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_new_hook_configs_use_private_mode(self) -> None:
        _, origin = self.make_catalog("new-private-hooks", "# Private defaults")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for path in (
            self.home / ".claude" / "settings.json",
            self.home / ".codex" / "hooks.json",
            self.home / ".cursor" / "hooks.json",
        ):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        for product, path in {
            "claude": self.home / ".claude" / "settings.json",
            "codex": self.home / ".codex" / "hooks.json",
            "cursor": self.home / ".cursor" / "hooks.json",
        }.items():
            with self.subTest(product=product):
                self.assertFalse(path.exists())

    def test_two_catalog_hook_entries_coexist_and_one_removal_is_exact(self) -> None:
        _, first_origin = self.make_catalog("first-hooks", "# First hooks")
        _, second_origin = self.make_catalog("second-hooks", "# Second hooks")
        cursor_config = self.home / ".cursor" / "hooks.json"
        cursor_config.parent.mkdir(parents=True)
        cursor_config.write_text(
            json.dumps({"hooks": {"sessionStart": [{"command": "foreign"}]}}),
            encoding="utf-8",
        )
        self.assertEqual(self.run_installer("install", first_origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", second_origin, "--prefix", "second").returncode,
            0,
        )
        instances = sorted((self.state / "catalogs").iterdir())
        commands = {
            instance.name: (instance / "hooks" / "cursor.owner")
            .read_text(encoding="utf-8")
            .splitlines()[1]
            for instance in instances
        }
        before = [entry["command"] for entry in self.read_hook_config("cursor")["hooks"]["sessionStart"]]
        self.assertEqual(before[0], "foreign")
        self.assertEqual(set(before[1:]), set(commands.values()))

        removed = self.run_installer("remove", first_origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        after = [entry["command"] for entry in self.read_hook_config("cursor")["hooks"]["sessionStart"]]
        self.assertEqual(after[0], "foreign")
        self.assertEqual(len(after), 2)
        self.assertIn(next(iter((self.state / "catalogs").iterdir())).name, after[1])
        for product in ("claude", "codex"):
            serialized = json.dumps(self.read_hook_config(product))
            self.assertNotIn(commands[[key for key in commands if key not in after[1]][0]], serialized)
            self.assertIn(after[1], serialized)

        removed_second = self.run_installer("remove", second_origin, "--prefix", "second")
        self.assertEqual(removed_second.returncode, 0, removed_second.stderr)
        self.assertFalse((self.home / ".claude" / "settings.json").exists())
        self.assertFalse((self.home / ".codex" / "hooks.json").exists())
        self.assertEqual(
            self.read_hook_config("cursor"),
            {"hooks": {"sessionStart": [{"command": "foreign"}]}},
        )

    def test_changed_owned_hook_refuses_removal_and_clean_retry_succeeds(self) -> None:
        _, origin = self.make_catalog("changed-hook", "# Hook ownership")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        cursor_path = self.home / ".cursor" / "hooks.json"
        original = cursor_path.read_bytes()
        cursor = json.loads(original)
        cursor["hooks"]["sessionStart"][0]["command"] += " changed"
        cursor_path.write_text(json.dumps(cursor), encoding="utf-8")

        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("no longer owned", refused.stderr)
        self.assertTrue((self.agents / "common-skill").is_symlink())
        self.assertTrue(self.instance_root().is_dir())

        cursor_path.write_bytes(original)
        retried = self.run_installer("remove", origin)
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertEqual(list((self.state / "catalogs").glob("*")), [])

    def test_malformed_hook_config_refuses_install_without_overwrite(self) -> None:
        _, origin = self.make_catalog("malformed-hooks", "# Hooks")
        claude_config = self.home / ".claude" / "settings.json"
        claude_config.parent.mkdir(parents=True)
        malformed = b'{"foreign":"literal\tcontrol"}\n'
        claude_config.write_bytes(malformed)

        installed = self.run_installer("install", origin)
        self.assertNotEqual(installed.returncode, 0)
        self.assertIn("malformed, unsupported", installed.stderr)
        self.assertEqual(claude_config.read_bytes(), malformed)
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertFalse((self.home / ".codex" / "hooks.json").exists())
        self.assertFalse((self.home / ".cursor" / "hooks.json").exists())

    def test_product_invalid_codex_root_refuses_install_without_overwrite(self) -> None:
        _, origin = self.make_catalog("invalid-codex-root", "# Hooks")
        claude_config = self.home / ".claude" / "settings.json"
        codex_config = self.home / ".codex" / "hooks.json"
        claude_config.parent.mkdir(parents=True)
        codex_config.parent.mkdir(parents=True)
        claude_before = b'{"permissions":{"allow":["Read"]}}\n'
        claude_config.write_bytes(claude_before)
        invalid_values = (
            b'{ "foreign": true, "hooks": {"Other": []} }\n',
            b'{"description":7,"hooks":{}}\n',
        )
        for codex_before in invalid_values:
            with self.subTest(codex_before=codex_before):
                codex_config.write_bytes(codex_before)
                codex_config.chmod(0o640)

                refused = self.run_installer("install", origin)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("codex hook configuration is malformed, unsupported", refused.stderr)
                self.assertEqual(claude_config.read_bytes(), claude_before)
                self.assertEqual(codex_config.read_bytes(), codex_before)
                self.assertEqual(stat.S_IMODE(codex_config.stat().st_mode), 0o640)
                self.assertFalse((self.agents / "common-skill").exists())
                self.assertFalse((self.home / ".cursor" / "hooks.json").exists())

    def test_hook_command_quotes_metacharacter_and_unicode_state_path(self) -> None:
        self.state = self.base / "state 🧪 with '$dollar"
        self.env["TEAM_SKILLS_STATE_ROOT"] = str(self.state)
        _, origin = self.make_catalog("quoted-hooks", "# Hooks")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        command = self.owned_hook_commands()["claude"]
        self.assertIn("'\\''", command)
        self.env.update(
            {
                "TEAM_SKILLS_TEST_FOREGROUND": "1",
                "TEAM_SKILLS_NOW": "2000000000",
            }
        )
        invoked = subprocess.run(
            ["sh", "-c", command], text=True, capture_output=True, check=False, env=self.env
        )
        self.assertEqual(invoked.returncode, 0, invoked.stderr)
        self.assertTrue((self.instance_root() / "last-success").is_file())

    def test_two_origins_collision_prefix_idempotence_and_safe_remove(self) -> None:
        _, first_origin = self.make_catalog("first", "# First catalog")
        _, second_origin = self.make_catalog(
            "second", "# Second catalog", executable_resource=True
        )

        first = self.run_installer("install", first_origin)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_link = self.agents / "common-skill"
        self.assertTrue(first_link.is_symlink())
        self.assertIn("# First catalog", (first_link / "SKILL.md").read_text())

        repeated = self.run_installer("install", first_origin)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(len(list((self.state / "catalogs").iterdir())), 1)
        generations = (
            next((self.state / "catalogs").iterdir())
            / "installs"
            / "_default"
            / "generations"
        )
        generation = next(generations.iterdir())
        self.assertEqual(
            sorted(path.relative_to(generation) for path in generation.rglob("*")),
            [
                Path("common-skill"),
                Path("common-skill/SKILL.md"),
                Path("common-skill/scripts"),
                Path("common-skill/scripts/helper.sh"),
            ],
        )

        collision = self.run_installer("install", second_origin)
        self.assertEqual(collision.returncode, 0, collision.stderr)
        self.assertIn("warning: catalog shared-catalog-id skill common-skill skipped", collision.stderr)
        self.assertIn("# First catalog", (first_link / "SKILL.md").read_text())
        self.assertEqual(len(list((self.state / "catalogs").iterdir())), 2)

        prefixed = self.run_installer("install", second_origin, "--prefix", "second")
        self.assertEqual(prefixed.returncode, 0, prefixed.stderr)
        prefixed_link = self.claude / "second-common-skill"
        self.assertTrue(prefixed_link.is_symlink())
        prefixed_text = (prefixed_link / "SKILL.md").read_text()
        self.assertIn("name: second-common-skill", prefixed_text)
        self.assertIn("# Second catalog", prefixed_text)
        helper_mode = (prefixed_link / "scripts" / "helper.sh").stat().st_mode
        self.assertTrue(helper_mode & stat.S_IXUSR)

        # A user replacement at an owned path revokes proof of ownership and survives removal.
        claude_first = self.claude / "common-skill"
        claude_first.unlink()
        claude_first.mkdir()
        marker = claude_first / "user-owned.txt"
        marker.write_bytes(b"preserve me byte-for-byte\n")
        removed = self.run_installer("remove", first_origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse(first_link.exists())
        self.assertFalse(first_link.is_symlink())
        self.assertEqual(marker.read_bytes(), b"preserve me byte-for-byte\n")
        self.assertIn("not removing changed path", removed.stderr)
        self.assertTrue(prefixed_link.is_symlink())

    def test_invalid_fetched_catalog_retains_last_known_good_view(self) -> None:
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

    def test_malformed_json_manifest_cannot_advance_managed_clone(self) -> None:
        work, origin = self.make_catalog("manifest-json", "# Known good manifest")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        managed = self.instance_root() / "repo"
        previous = self.git("rev-parse", "HEAD", cwd=managed).stdout.strip()
        manifest = work / "catalog.json"
        malformed = manifest.read_text(encoding="utf-8").rstrip()
        self.assertTrue(malformed.endswith("}"))
        manifest.write_text(malformed[:-1].rstrip() + ",\n}\n", encoding="utf-8")
        self.git("add", "catalog.json", cwd=work)
        self.git("commit", "-m", "malformed JSON manifest", cwd=work)
        self.git("push", cwd=work)

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("fetched catalog is invalid", failed.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=managed).stdout.strip(), previous)
        self.assertIn(
            "# Known good manifest",
            (self.agents / "common-skill" / "SKILL.md").read_text(),
        )

    def test_structurally_valid_minified_manifest_is_accepted(self) -> None:
        work, origin = self.make_catalog("manifest-format", "# Flexible JSON")
        manifest = work / "catalog.json"
        value = json.loads(manifest.read_text(encoding="utf-8"))
        value["display_name"] = "Café catalog"
        manifest.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
        self.git("add", "catalog.json", cwd=work)
        self.git("commit", "-m", "minify valid manifest", cwd=work)
        self.git("push", cwd=work)

        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertIn("# Flexible JSON", (self.agents / "common-skill" / "SKILL.md").read_text())

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
        managed = self.instance_root() / "repo"
        previous = self.git("rev-parse", "HEAD", cwd=managed).stdout.strip()
        runtime = work / "scripts" / "team-skills.sh"
        runtime.write_text("#!/bin/sh\nif then malformed\n", encoding="utf-8")
        runtime.chmod(0o755)
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "malformed lifecycle candidate", cwd=work)
        self.git("push", cwd=work)

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("fetched catalog is invalid", failed.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=managed).stdout.strip(), previous)
        self.assertIn("# Known good runtime", (self.agents / "common-skill" / "SKILL.md").read_text())

    def test_failed_current_replacement_retains_last_known_good_view(self) -> None:
        work, origin = self.make_catalog("replacement", "# Known good")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        exposed = self.agents / "common-skill" / "SKILL.md"
        original = exposed.read_bytes()

        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace("# Known good", "# Candidate"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "valid candidate", cwd=work)
        self.git("push", cwd=work)

        command_bin = self.base / "injected command bin"
        command_bin.mkdir()
        real_mv = shutil.which("mv")
        self.assertIsNotNone(real_mv)
        mv_wrapper = command_bin / "mv"
        mv_wrapper.write_text(
            "#!/bin/sh\n"
            "last=\n"
            "for argument do last=$argument; done\n"
            "case $last in */current) exit 73 ;; esac\n"
            'exec "$TEAM_SKILLS_TEST_REAL_MV" "$@"\n',
            encoding="utf-8",
        )
        mv_wrapper.chmod(0o755)
        self.env["TEAM_SKILLS_TEST_REAL_MV"] = real_mv or ""
        self.env["PATH"] = str(command_bin) + os.pathsep + self.env["PATH"]

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cannot activate generated view", failed.stderr)
        self.assertEqual(exposed.read_bytes(), original)
        install_root = next((self.state / "catalogs").iterdir()) / "installs" / "_default"
        self.assertEqual(list(install_root.glob(".current.*")), [])

    def test_racing_unrelated_destination_is_not_overwritten(self) -> None:
        work, origin = self.make_catalog("race", "# Known good")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        original = (self.agents / "common-skill" / "SKILL.md").read_bytes()

        common_skill = work / "skills" / "common-skill" / "SKILL.md"
        common_skill.write_text(
            common_skill.read_text(encoding="utf-8").replace("# Known good", "# Candidate"),
            encoding="utf-8",
        )
        new_skill = work / "skills" / "new-skill"
        new_skill.mkdir()
        (new_skill / "SKILL.md").write_text(
            "---\nname: new-skill\ndescription: A new fixture skill.\n---\n\n# New skill\n",
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "add a valid skill", cwd=work)
        self.git("push", cwd=work)

        command_bin = self.base / "racing command bin"
        command_bin.mkdir()
        real_ln = shutil.which("ln")
        self.assertIsNotNone(real_ln)
        ln_wrapper = command_bin / "ln"
        ln_wrapper.write_text(
            "#!/bin/sh\n"
            "last=\n"
            "for argument do last=$argument; done\n"
            "case $last in\n"
            "  */.agents/skills/new-skill)\n"
            "    printf 'race winner\\n' >\"$last\"\n"
            "    ;;\n"
            "esac\n"
            'exec "$TEAM_SKILLS_TEST_REAL_LN" "$@"\n',
            encoding="utf-8",
        )
        ln_wrapper.chmod(0o755)
        self.env["TEAM_SKILLS_TEST_REAL_LN"] = real_ln or ""
        original_path = self.env["PATH"]
        self.env["PATH"] = str(command_bin) + os.pathsep + self.env["PATH"]

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cannot expose skill new-skill", failed.stderr)
        self.assertEqual((self.agents / "new-skill").read_bytes(), b"race winner\n")
        self.assertEqual((self.agents / "common-skill" / "SKILL.md").read_bytes(), original)
        ownership = (
            next((self.state / "catalogs").iterdir())
            / "installs"
            / "_default"
            / "ownership"
            / "agents"
            / "new-skill.owner"
        )
        self.assertFalse(ownership.exists())

        install_root = ownership.parents[2]
        current = install_root / "current"
        self.assertIn("# Known good", (current / "common-skill" / "SKILL.md").read_text())
        for product_root, product in ((self.agents, "agents"), (self.claude, "claude")):
            owner_file = install_root / "ownership" / product / "common-skill.owner"
            self.assertTrue(owner_file.is_file())
            self.assertEqual(os.readlink(product_root / "common-skill"), owner_file.read_text().strip())

        self.env["PATH"] = original_path
        (self.agents / "new-skill").unlink()
        rerun = self.run_installer("install", origin)
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("# Candidate", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertIn("# New skill", (self.claude / "new-skill" / "SKILL.md").read_text())

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        for product_root in (self.agents, self.claude):
            self.assertFalse((product_root / "common-skill").exists())
            self.assertFalse((product_root / "new-skill").exists())

    def test_failed_first_install_removes_partial_catalog_exposures(self) -> None:
        work, origin = self.make_catalog("first-race", "# Initial")
        new_skill = work / "skills" / "new-skill"
        new_skill.mkdir()
        (new_skill / "SKILL.md").write_text(
            "---\nname: new-skill\ndescription: A new fixture skill.\n---\n\n# New skill\n",
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "add second initial skill", cwd=work)
        self.git("push", cwd=work)

        command_bin = self.base / "first install racing bin"
        command_bin.mkdir()
        real_ln = shutil.which("ln")
        self.assertIsNotNone(real_ln)
        ln_wrapper = command_bin / "ln"
        ln_wrapper.write_text(
            "#!/bin/sh\n"
            "last=\n"
            "for argument do last=$argument; done\n"
            "case $last in\n"
            "  */.agents/skills/new-skill)\n"
            "    printf 'first race winner\\n' >\"$last\"\n"
            "    ;;\n"
            "esac\n"
            'exec "$TEAM_SKILLS_TEST_REAL_LN" "$@"\n',
            encoding="utf-8",
        )
        ln_wrapper.chmod(0o755)
        self.env["TEAM_SKILLS_TEST_REAL_LN"] = real_ln or ""
        original_path = self.env["PATH"]
        self.env["PATH"] = str(command_bin) + os.pathsep + original_path

        failed = self.run_installer("install", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cannot expose skill new-skill", failed.stderr)
        self.assertEqual((self.agents / "new-skill").read_bytes(), b"first race winner\n")
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertFalse((self.claude / "common-skill").exists())
        install_root = next((self.state / "catalogs").iterdir()) / "installs" / "_default"
        self.assertFalse((install_root / "current").exists())
        self.assertEqual(list((install_root / "ownership").rglob("*.owner")), [])

        self.env["PATH"] = original_path
        (self.agents / "new-skill").unlink()
        rerun = self.run_installer("install", origin)
        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertTrue((self.agents / "common-skill").is_symlink())
        self.assertTrue((self.claude / "new-skill").is_symlink())

    def test_clone_failure_does_not_print_credentials(self) -> None:
        secret_url = "file://fixture-user:fixture-password@/definitely/missing/catalog.git"
        result = self.run_installer("install", secret_url)
        self.assertNotEqual(result.returncode, 0)
        combined = result.stdout + result.stderr
        self.assertNotIn("fixture-user", combined)
        self.assertNotIn("fixture-password", combined)
        self.assertIn("unable to clone the supplied repository", combined)

    def test_script_accepts_curl_style_standard_input_bootstrap(self) -> None:
        _, origin = self.make_catalog("stdin", "# Standard input bootstrap")
        result = subprocess.run(
            ["sh", "-s", "--", "install", str(origin)],
            input=INSTALLER.read_text(encoding="utf-8"),
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "# Standard input bootstrap",
            (self.agents / "common-skill" / "SKILL.md").read_text(),
        )

    def test_linked_product_roots_can_share_one_portable_skill_store(self) -> None:
        _, origin = self.make_catalog("shared-root", "# Shared root")
        shared = self.home / ".codex" / "skills"
        shared.mkdir(parents=True)
        self.agents.parent.mkdir(parents=True)
        self.claude.parent.mkdir(parents=True)
        self.agents.symlink_to(shared, target_is_directory=True)
        self.claude.symlink_to(shared, target_is_directory=True)

        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        exposure = shared / "common-skill"
        self.assertTrue(exposure.is_symlink())
        self.assertIn("# Shared root", (exposure / "SKILL.md").read_text())

        install_root = self.instance_root() / "installs" / "_default"
        self.assertTrue((install_root / "ownership" / "agents" / "common-skill.owner").is_file())
        self.assertTrue((install_root / "ownership" / "claude" / "common-skill.owner").is_file())

        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse(exposure.exists())
        self.assertFalse(exposure.is_symlink())

    def test_invalid_root_fails_before_clone_or_mutation(self) -> None:
        self.env["TEAM_SKILLS_STATE_ROOT"] = "relative/state"
        result = self.run_installer("install", "/not/used")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an absolute path", result.stderr)
        self.assertFalse((self.base / "relative").exists())

    def test_root_traversal_and_symlink_components_fail_before_clone(self) -> None:
        for unsafe in ("////", str(self.base / "safe" / ".." / "escape")):
            with self.subTest(unsafe=unsafe):
                self.env["TEAM_SKILLS_STATE_ROOT"] = unsafe
                result = self.run_installer("install", "/not/used")
                self.assertNotEqual(result.returncode, 0)
        real = self.base / "real state"
        real.mkdir()
        linked = self.base / "linked state"
        linked.symlink_to(real, target_is_directory=True)
        self.env["TEAM_SKILLS_STATE_ROOT"] = str(linked)
        result = self.run_installer("install", "/not/used")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be a symlink", result.stderr)

    def test_owned_state_symlink_substitutions_fail_without_removal(self) -> None:
        _, origin = self.make_catalog("owned-state-link", "# Owned state")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = self.instance_root()
        install_root = instance / "installs" / "_default"
        relocated = self.base / "relocated install state"
        install_root.rename(relocated)
        install_root.symlink_to(relocated, target_is_directory=True)
        before_hooks = {
            product: (instance / "hooks" / f"{product}.owner").read_bytes()
            for product in ("claude", "codex", "cursor")
        }

        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("installation view is not an owned directory", refused.stderr)
        self.assertTrue((self.agents / "common-skill").is_symlink())
        self.assertTrue(relocated.is_dir())
        for product, previous in before_hooks.items():
            self.assertEqual((instance / "hooks" / f"{product}.owner").read_bytes(), previous)

    def test_future_success_stamp_does_not_suppress_update(self) -> None:
        _, origin = self.make_catalog("future-stamp", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        (instance / "last-success").write_text("2000000100\n", encoding="utf-8")
        self.git("remote", "set-url", "origin", str(self.base / "missing origin"), cwd=instance / "repo")
        self.env["TEAM_SKILLS_NOW"] = "2000000000"

        attempted = self.run_updater()
        self.assertNotEqual(attempted.returncode, 0)
        self.assertIn("configured origin identity changed", attempted.stderr)

    def test_late_remove_failure_restores_committed_hook_edits(self) -> None:
        _, origin = self.make_catalog("remove-rollback", "# Remove rollback")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        hook_paths = (
            self.home / ".claude" / "settings.json",
            self.home / ".codex" / "hooks.json",
            self.home / ".cursor" / "hooks.json",
        )
        installed_hooks = {path: path.read_bytes() for path in hook_paths}
        command_bin = self.base / "remove failure bin"
        command_bin.mkdir()
        real_mv = shutil.which("mv")
        self.assertIsNotNone(real_mv)
        wrapper = command_bin / "mv"
        wrapper.write_text(
            "#!/bin/sh\n"
            "last=\n"
            "for argument do last=$argument; done\n"
            "case $last in */removed-instance) exit 73 ;; esac\n"
            'exec "$TEAM_SKILLS_TEST_REAL_MV" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        original_path = self.env["PATH"]
        self.env.update({
            "PATH": str(command_bin) + os.pathsep + original_path,
            "TEAM_SKILLS_TEST_REAL_MV": real_mv or "",
        })
        failed = self.run_installer("remove", origin)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cannot atomically stage catalog state removal", failed.stderr)
        for path in hook_paths:
            self.assertEqual(path.read_bytes(), installed_hooks[path])
        self.assertTrue((self.agents / "common-skill").is_symlink())
        self.assertTrue((self.claude / "common-skill").is_symlink())
        self.assertTrue(self.instance_root().is_dir())

        self.env["PATH"] = original_path
        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)

    def test_remove_rejects_linked_or_malformed_skill_ownership_before_mutation(self) -> None:
        _, origin = self.make_catalog("remove-owner", "# Remove owner validation")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        owner = instance / "installs" / "_default" / "ownership" / "agents" / "common-skill.owner"
        original_owner = owner.read_bytes()
        hook_paths = (
            self.home / ".claude" / "settings.json",
            self.home / ".codex" / "hooks.json",
            self.home / ".cursor" / "hooks.json",
        )
        installed_hooks = {path: path.read_bytes() for path in hook_paths}
        foreign = self.base / "foreign ownership evidence"
        foreign.write_bytes(original_owner)
        owner.unlink()
        owner.symlink_to(foreign)

        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("agents skill ownership state is invalid", refused.stderr)
        self.assertTrue((self.agents / "common-skill").is_symlink())
        self.assertTrue((self.claude / "common-skill").is_symlink())
        self.assertEqual(foreign.read_bytes(), original_owner)
        for path in hook_paths:
            self.assertEqual(path.read_bytes(), installed_hooks[path])

        owner.unlink()
        owner.write_bytes(original_owner + b"unexpected\n")
        refused = self.run_installer("remove", origin)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("agents skill ownership state is invalid", refused.stderr)
        self.assertTrue((self.agents / "common-skill").is_symlink())

        owner.write_bytes(original_owner)
        removed = self.run_installer("remove", origin)
        self.assertEqual(removed.returncode, 0, removed.stderr)

    def test_url_free_update_reconciles_every_installed_prefix(self) -> None:
        work, origin = self.make_catalog("all-prefixes", "# Initial")
        first = self.run_installer("install", origin)
        self.assertEqual(first.returncode, 0, first.stderr)
        prefixed = self.run_installer("install", origin, "--prefix", "fork")
        self.assertEqual(prefixed.returncode, 0, prefixed.stderr)

        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace("# Initial", "# Updated"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "update every view", cwd=work)
        self.git("push", cwd=work)

        self.env["TEAM_SKILLS_NOW"] = "2000000000"
        updated = self.run_updater()
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertIn("# Updated", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertIn(
            "# Updated", (self.claude / "fork-common-skill" / "SKILL.md").read_text()
        )
        self.assertEqual((self.instance_root() / "last-success").read_text().strip(), "2000000000")

    def test_multi_prefix_update_fetches_once_and_pins_one_candidate(self) -> None:
        work, origin = self.make_catalog("pinned-prefixes", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", origin, "--prefix", "fork").returncode, 0
        )
        skill_file = work / "skills" / "common-skill" / "SKILL.md"
        skill_file.write_text(
            skill_file.read_text(encoding="utf-8").replace("# Initial", "# One candidate"),
            encoding="utf-8",
        )
        self.git("add", ".", cwd=work)
        self.git("commit", "-m", "one pinned candidate", cwd=work)
        self.git("push", cwd=work)

        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        command_bin = self.base / "single fetch command bin"
        command_bin.mkdir()
        wrapper = command_bin / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -C ] && [ \"$3\" = fetch ]; then\n"
            "  printf '%s\\n' fetch >>\"$TEAM_SKILLS_TEST_FETCH_LOG\"\n"
            "fi\n"
            'exec "$TEAM_SKILLS_TEST_REAL_GIT" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
        fetch_log = self.base / "multi-prefix fetch calls.log"
        self.env.update(
            {
                "PATH": str(command_bin) + os.pathsep + self.env["PATH"],
                "TEAM_SKILLS_TEST_REAL_GIT": real_git or "",
                "TEAM_SKILLS_TEST_FETCH_LOG": str(fetch_log),
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )
        updated = self.run_updater()
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertEqual(fetch_log.read_text(encoding="utf-8").splitlines(), ["fetch"])
        self.assertIn("# One candidate", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertIn(
            "# One candidate", (self.claude / "fork-common-skill" / "SKILL.md").read_text()
        )

    def test_throttled_update_and_active_lock_do_not_fetch(self) -> None:
        _, origin = self.make_catalog("throttle", "# Initial")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = self.instance_root()
        (instance / "last-success").write_text("2000000000\n", encoding="utf-8")
        self.git("remote", "set-url", "origin", str(self.base / "missing origin"), cwd=instance / "repo")

        self.env["TEAM_SKILLS_NOW"] = "2000000010"
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

    def test_remove_refuses_active_update_lock_before_mutation(self) -> None:
        _, origin = self.make_catalog("remove-locked", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        lock = instance / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text(f"{os.getpid()}\n2000000000\n", encoding="utf-8")
        exposure = self.agents / "common-skill"
        hooks_before = {
            product: path.read_bytes()
            for product, path in {
                "claude": self.home / ".claude" / "settings.json",
                "codex": self.home / ".codex" / "hooks.json",
                "cursor": self.home / ".cursor" / "hooks.json",
            }.items()
        }

        refused = self.run_installer("remove", origin)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("catalog update is in progress", refused.stderr)
        self.assertTrue(instance.is_dir())
        self.assertTrue(exposure.is_symlink())
        self.assertTrue(lock.is_dir())
        for product, expected in hooks_before.items():
            self.assertEqual(
                (self.home / f".{product}" / ("settings.json" if product == "claude" else "hooks.json")).read_bytes(),
                expected,
            )

    def test_stale_lock_recovers_conservatively(self) -> None:
        _, origin = self.make_catalog("stale", "# Initial")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = self.instance_root()
        lock = instance / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text("99999999\n100\n", encoding="utf-8")
        self.env.update(
            {
                "TEAM_SKILLS_NOW": "10000",
                "TEAM_SKILLS_STALE_LOCK_SECONDS": "1000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )

        recovered = self.run_updater()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertFalse(lock.exists())
        self.assertEqual((instance / "last-success").read_text().strip(), "10000")

    def test_unexpected_stale_lock_contents_are_not_removed(self) -> None:
        _, origin = self.make_catalog("unsafe-stale", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        lock = instance / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text("99999999\n100\n", encoding="utf-8")
        marker = lock / "unexpected"
        marker.write_text("preserve\n", encoding="utf-8")
        self.env.update(
            {
                "TEAM_SKILLS_NOW": "10000",
                "TEAM_SKILLS_STALE_LOCK_SECONDS": "1000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )

        skipped = self.run_updater()
        self.assertEqual(skipped.returncode, 0, skipped.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")
        self.assertFalse((instance / "last-success").exists())

    def test_concurrent_updates_fetch_once(self) -> None:
        _, origin = self.make_catalog("concurrent", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        command_bin = self.base / "concurrency command bin"
        command_bin.mkdir()
        git_wrapper = command_bin / "git"
        git_wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = -C ] && [ \"$3\" = fetch ]; then\n"
            "  printf '%s\\n' fetch >>\"$TEAM_SKILLS_TEST_FETCH_LOG\"\n"
            "  sleep 2\n"
            "fi\n"
            "exec \"$TEAM_SKILLS_TEST_REAL_GIT\" \"$@\"\n",
            encoding="utf-8",
        )
        git_wrapper.chmod(0o755)
        fetch_log = self.base / "fetch calls.log"
        self.env.update(
            {
                "PATH": str(command_bin) + os.pathsep + self.env["PATH"],
                "TEAM_SKILLS_TEST_REAL_GIT": real_git or "",
                "TEAM_SKILLS_TEST_FETCH_LOG": str(fetch_log),
                "TEAM_SKILLS_NOW": "2000000000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )

        first = subprocess.Popen(
            ["sh", str(INSTALLER), "update-instance", instance.name],
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
        instance = self.instance_root()
        runtime = instance / "repo" / "scripts" / "team-skills.sh"
        source = runtime.read_text(encoding="utf-8")
        needle = 'if [ "$ACTION" = update-instance ]; then\n    run_catalog_update'
        replacement = (
            'if [ "$ACTION" = update-instance ]; then\n'
            "    sleep 3\n"
            "    printf 'detached-marker:' >&2\n"
            "    awk 'BEGIN { for (i = 0; i < 40000; i++) printf \"é\"; print \"\" }' >&2\n"
            "    run_catalog_update"
        )
        self.assertIn(needle, source)
        runtime.write_text(source.replace(needle, replacement, 1), encoding="utf-8")
        self.env.update(
            {
                "TEAM_SKILLS_NOW": "2000000000",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
            }
        )

        started = time.monotonic()
        launched = subprocess.run(
            ["sh", str(runtime), "hook", instance.name],
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
            self.run_installer("install", second_origin, "--prefix", "second").returncode, 0
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

    def test_hook_masks_failure_and_credential_safe_log_retains_known_good(self) -> None:
        _, origin = self.make_catalog("hook-failure", "# Known good")
        installed = self.run_installer("install", origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = self.instance_root()
        secret_origin = "file://fixture-user:fixture-password@/definitely/missing/catalog.git"
        self.git("remote", "set-url", "origin", secret_origin, cwd=instance / "repo")
        original = (self.agents / "common-skill" / "SKILL.md").read_bytes()
        self.env.update(
            {
                "TEAM_SKILLS_TEST_FOREGROUND": "1",
                "TEAM_SKILLS_THROTTLE_SECONDS": "0",
                "TEAM_SKILLS_NOW": "2000000000",
            }
        )

        hooked = self.run_updater("hook", instance.name)
        self.assertEqual(hooked.returncode, 0, hooked.stderr)
        log = (instance / "last-update.log").read_text(encoding="utf-8")
        self.assertIn("configured origin identity changed", log)
        self.assertNotIn("fixture-user", log)
        self.assertNotIn("fixture-password", log)
        self.assertEqual((self.agents / "common-skill" / "SKILL.md").read_bytes(), original)

    def test_changed_configured_origin_update_fails_closed_without_bootstrap_url(self) -> None:
        _, initial_origin = self.make_catalog("url-free-initial", "# Initial")
        _, replacement_origin = self.make_catalog("url-free-replacement", "# Replacement")
        installed = self.run_installer("install", initial_origin)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        instance = self.instance_root()
        self.git("remote", "set-url", "origin", str(replacement_origin), cwd=instance / "repo")
        self.env["TEAM_SKILLS_THROTTLE_SECONDS"] = "0"

        updated = self.run_updater()
        self.assertNotEqual(updated.returncode, 0)
        self.assertIn("configured origin identity changed", updated.stderr)
        self.assertIn("# Initial", (self.agents / "common-skill" / "SKILL.md").read_text())

    def hook_paths(self) -> dict[str, Path]:
        return {
            "claude": self.home / ".claude" / "settings.json",
            "codex": self.home / ".codex" / "hooks.json",
            "cursor": self.home / ".cursor" / "hooks.json",
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
        settings = self.hook_paths()["claude"]
        settings.parent.mkdir(parents=True)
        settings.write_bytes(b'{ "theme": "dark" }\n')

        result = self.run_installer("install", origin, auto_update=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Automatic updates are off", result.stdout)
        self.assertIn("# Plain", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual(settings.read_bytes(), b'{ "theme": "dark" }\n')
        self.assertFalse(self.hook_paths()["codex"].exists())
        self.assertFalse(self.hook_paths()["cursor"].exists())
        self.assertFalse((self.instance_root() / "hooks").exists())

    def test_plain_install_ignores_a_malformed_hook_file(self) -> None:
        _, origin = self.make_catalog("plain-malformed", "# Plain")
        settings = self.hook_paths()["claude"]
        settings.parent.mkdir(parents=True)
        settings.write_bytes(b"{ not json\n")

        result = self.run_installer("install", origin, auto_update=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(settings.read_bytes(), b"{ not json\n")

    def test_setup_flag_enables_an_existing_plain_install(self) -> None:
        _, origin = self.make_catalog("enable-later", "# Plain")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        self.assertFalse(self.hook_paths()["claude"].exists())

        enabled = self.run_installer("install", origin, "--setup-auto-update", auto_update=False)

        self.assertEqual(enabled.returncode, 0, enabled.stderr)
        self.assertIn("Automatic updates are on", enabled.stdout)
        commands = self.owned_hook_commands()
        self.assertEqual(
            self.read_hook_config("claude")["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            commands["claude"],
        )

    def test_plain_rerun_updates_skills_without_changing_the_setting(self) -> None:
        work, origin = self.make_catalog("rerun", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        enabled = {name: path.read_bytes() for name, path in self.hook_paths().items()}
        owner = (self.instance_root() / "hooks" / "claude.owner").read_bytes()
        self.advance_catalog(work, "# Initial", "# Second")

        rerun = self.run_installer("install", origin, auto_update=False)

        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("Automatic updates are on", rerun.stdout)
        self.assertIn("# Second", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual(
            {name: path.read_bytes() for name, path in self.hook_paths().items()}, enabled
        )
        self.assertEqual((self.instance_root() / "hooks" / "claude.owner").read_bytes(), owner)

    def test_remove_auto_update_only_removes_hooks_and_never_fetches(self) -> None:
        work, origin = self.make_catalog("disable", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        instance = self.instance_root()
        self.advance_catalog(work, "# Initial", "# Unwanted")
        # A fetch of this origin would fail, so success proves the path stays offline.
        self.git("remote", "set-url", "origin", str(self.base / "missing origin"), cwd=instance / "repo")

        disabled = self.run_installer("install", origin, "--remove-auto-update", auto_update=False)

        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        self.assertIn("Automatic updates are off", disabled.stdout)
        self.assertIn("# Initial", (self.agents / "common-skill" / "SKILL.md").read_text())
        for path in self.hook_paths().values():
            self.assertFalse(path.exists())
        self.assertFalse((instance / "hooks").exists())
        self.assertFalse((instance / "update.lock").exists())

        repeated = self.run_installer("install", origin, "--remove-auto-update", auto_update=False)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertIn("already off", repeated.stdout)

    def test_remove_auto_update_preserves_foreign_config_and_other_catalogs(self) -> None:
        _, first = self.make_catalog("first", "# First")
        _, second = self.make_catalog("second", "# Second")
        settings = self.hook_paths()["claude"]
        settings.parent.mkdir(parents=True)
        settings.write_text(
            json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"hooks": [{"command": "keep"}]}]}}),
            encoding="utf-8",
        )
        self.assertEqual(self.run_installer("install", first).returncode, 0)
        self.assertEqual(self.run_installer("install", second, "--prefix", "second").returncode, 0)

        disabled = self.run_installer("install", first, "--remove-auto-update", auto_update=False)

        self.assertEqual(disabled.returncode, 0, disabled.stderr)
        value = self.read_hook_config("claude")
        self.assertEqual(value["theme"], "dark")
        self.assertEqual(value["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "keep")
        remaining = value["hooks"]["SessionStart"]
        self.assertEqual(len(remaining), 1)
        owners = list((self.state / "catalogs").glob("*/hooks/claude.owner"))
        self.assertEqual(len(owners), 1)
        self.assertEqual(
            remaining[0]["hooks"][0]["command"], owners[0].read_text(encoding="utf-8").splitlines()[1]
        )
        # The other catalog still owns its entry in each file this installation created.
        self.assertTrue(self.hook_paths()["codex"].exists())

    def test_plain_rerun_does_not_restore_a_disabled_hook(self) -> None:
        work, origin = self.make_catalog("stay-off", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        self.assertEqual(
            self.run_installer("install", origin, "--remove-auto-update", auto_update=False).returncode,
            0,
        )
        self.advance_catalog(work, "# Initial", "# Second")

        rerun = self.run_installer("install", origin, auto_update=False)

        self.assertEqual(rerun.returncode, 0, rerun.stderr)
        self.assertIn("# Second", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertFalse(self.hook_paths()["claude"].exists())
        self.assertFalse((self.instance_root() / "hooks").exists())

    def test_remove_auto_update_refuses_a_changed_hook_without_mutation(self) -> None:
        _, origin = self.make_catalog("disable-edited", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        value = self.read_hook_config("codex")
        value["hooks"]["SessionStart"][0]["hooks"][0]["timeout"] = 5
        self.hook_paths()["codex"].write_text(json.dumps(value), encoding="utf-8")
        before = {name: path.read_bytes() for name, path in self.hook_paths().items()}

        disabled = self.run_installer("install", origin, "--remove-auto-update", auto_update=False)

        self.assertNotEqual(disabled.returncode, 0)
        self.assertIn("no longer owned", disabled.stderr)
        self.assertEqual({name: path.read_bytes() for name, path in self.hook_paths().items()}, before)
        self.assertTrue((self.instance_root() / "hooks" / "claude.owner").is_file())
        self.assertFalse((self.instance_root() / "update.lock").exists())

    def test_remove_auto_update_refuses_an_active_update_lock(self) -> None:
        _, origin = self.make_catalog("disable-locked", "# Initial")
        self.assertEqual(self.run_installer("install", origin).returncode, 0)
        before = self.hook_paths()["claude"].read_bytes()
        lock = self.instance_root() / "update.lock"
        lock.mkdir()
        (lock / "owner").write_text(f"{os.getpid()}\n2000000000\n", encoding="utf-8")

        disabled = self.run_installer("install", origin, "--remove-auto-update", auto_update=False)

        self.assertNotEqual(disabled.returncode, 0)
        self.assertIn("catalog update is in progress", disabled.stderr)
        self.assertEqual(self.hook_paths()["claude"].read_bytes(), before)
        self.assertTrue(lock.is_dir())

    def test_remove_auto_update_requires_an_installed_catalog(self) -> None:
        missing = self.base / "never cloned origin.git"
        result = self.run_installer("install", missing, "--remove-auto-update", auto_update=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("catalog instance is not installed", result.stderr)
        self.assertFalse(self.hook_paths()["claude"].exists())

    def test_auto_update_flags_reject_invalid_combinations(self) -> None:
        _, origin = self.make_catalog("flags", "# Initial")
        both = self.run_installer(
            "install", origin, "--setup-auto-update", "--remove-auto-update", auto_update=False
        )
        self.assertEqual(both.returncode, 2)
        on_remove = self.run_installer("remove", origin, "--setup-auto-update")
        self.assertEqual(on_remove.returncode, 2)
        with_prefix = self.run_installer(
            "install", origin, "--remove-auto-update", "--prefix", "acme", auto_update=False
        )
        self.assertEqual(with_prefix.returncode, 1)
        self.assertIn("omit --prefix", with_prefix.stderr)
        self.assertFalse((self.state / "catalogs").exists() and any((self.state / "catalogs").iterdir()))

    def test_final_remove_of_a_hookless_install_is_clean(self) -> None:
        _, origin = self.make_catalog("hookless-remove", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)

        removed = self.run_installer("remove", origin)

        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.agents / "common-skill").exists())
        self.assertEqual(list((self.state / "catalogs").iterdir()), [])
        self.assertFalse(self.hook_paths()["claude"].exists())

    def test_update_all_ignores_throttle_but_session_update_honors_it(self) -> None:
        work, origin = self.make_catalog("manual-now", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        instance = self.instance_root()
        self.env["TEAM_SKILLS_NOW"] = "2000000000"

        first = self.run_updater()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertRegex(first.stdout, r"Catalog shared-catalog-id: already current at [0-9a-f]{12}\.")
        self.assertEqual((instance / "last-success").read_text().strip(), "2000000000")

        self.advance_catalog(work, "# Initial", "# Second")
        self.env["TEAM_SKILLS_NOW"] = "2000000010"
        session = self.run_updater("update-instance", instance.name)
        self.assertEqual(session.returncode, 0, session.stderr)
        self.assertIn("# Initial", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual((instance / "last-success").read_text().strip(), "2000000000")

        manual = self.run_updater()
        self.assertEqual(manual.returncode, 0, manual.stderr)
        self.assertRegex(manual.stdout, r"updated [0-9a-f]{12} to [0-9a-f]{12}\.")
        self.assertIn("# Second", (self.agents / "common-skill" / "SKILL.md").read_text())
        self.assertEqual((instance / "last-success").read_text().strip(), "2000000010")

    def test_update_all_reports_a_failed_catalog(self) -> None:
        _, origin = self.make_catalog("manual-failure", "# Initial")
        self.assertEqual(self.run_installer("install", origin, auto_update=False).returncode, 0)
        self.git(
            "remote", "set-url", "origin", str(self.base / "missing origin"),
            cwd=self.instance_root() / "repo",
        )

        failed = self.run_updater()

        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("update failed; keeping the last known-good installation", failed.stderr)

    def test_update_all_explains_it_needs_a_script_file(self) -> None:
        result = subprocess.run(
            ["sh", "-s", "--", "update-all"],
            input=INSTALLER.read_text(encoding="utf-8"),
            text=True,
            capture_output=True,
            check=False,
            env=self.env,
            cwd=self.base,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("update-all must run from a script file", result.stderr)


if __name__ == "__main__":
    unittest.main()
