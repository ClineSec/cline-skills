"""The skills must work after the catalog's real installer delivers them."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from . import e2e_support as e2e
from .support import CATALOG, DISTILL_SKILL, FIXTURES, INIT_SKILL

E2E = FIXTURES / "e2e"
SKILLS = ("init-policy-relay", "policy-relay-distill")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)")


class PackagingTests(unittest.TestCase):
    def test_local_links_resolve_inside_each_skill(self) -> None:
        for skill in (INIT_SKILL, DISTILL_SKILL):
            for document in [skill / "SKILL.md", *sorted((skill / "references").glob("*.md"))]:
                for target in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
                    if "://" in target or target.startswith("#"):
                        continue
                    resolved = (document.parent / target.split("#", 1)[0]).resolve()
                    with self.subTest(document=document.name, target=target):
                        self.assertTrue(resolved.exists())
                        self.assertTrue(resolved.is_relative_to(skill.resolve()))

    def test_named_assets_exist(self) -> None:
        text = (DISTILL_SKILL / "SKILL.md").read_text(encoding="utf-8")
        for name in re.findall(r"`(assets/[^`]+)`", text):
            self.assertTrue((DISTILL_SKILL / name).is_file(), name)

    def test_only_portable_top_level_entries(self) -> None:
        allowed = {"SKILL.md", "scripts", "references", "assets"}
        for skill in (INIT_SKILL, DISTILL_SKILL):
            present = {p.name for p in skill.iterdir() if p.name != "__pycache__"}
            self.assertLessEqual(present, allowed, skill.name)

    def test_runtime_modules_ship_with_the_installer(self) -> None:
        sys_modules = {p.name for p in (INIT_SKILL / "scripts" / "policyrelay").glob("*.py")}
        self.assertLessEqual({"__init__.py", "lifecycle.py", "sync.py", "validator.py"}, sys_modules)

    def test_entry_scripts_are_executable(self) -> None:
        for path in (
            INIT_SKILL / "scripts" / "install_policy_relay.py",
            DISTILL_SKILL / "scripts" / "distill_policy.py",
        ):
            self.assertTrue(path.stat().st_mode & stat.S_IXUSR, path.name)


@unittest.skipUnless(shutil.which("git"), "Git is required")
class CatalogInstallTests(unittest.TestCase):
    """Install from a disposable origin, using disposable product locations."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        work = self.base / "catalog"
        shutil.copytree(
            CATALOG, work, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc")
        )
        e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(work)])
        e2e.git(work, "add", ".")
        e2e.git(work, "commit", "--quiet", "-m", "catalog")
        self.origin = self.base / "origin.git"
        e2e.run(["git", "clone", "--quiet", "--bare", str(work), str(self.origin)])
        self.lifecycle = work / "scripts" / "team-skills.sh"
        home = self.base / "home"
        home.mkdir()
        self.agents = self.base / "agents-skills"
        self.claude = self.base / "claude-skills"
        self.environment = {
            **os.environ,
            "HOME": str(home),
            "TEAM_SKILLS_STATE_ROOT": str(self.base / "state"),
            "TEAM_SKILLS_AGENTS_ROOT": str(self.agents),
            "TEAM_SKILLS_CLAUDE_ROOT": str(self.claude),
            "TEAM_SKILLS_CLAUDE_HOOKS_FILE": str(self.base / "claude-settings.json"),
            "TEAM_SKILLS_CODEX_HOOKS_FILE": str(self.base / "codex-hooks.json"),
            "TEAM_SKILLS_CURSOR_HOOKS_FILE": str(self.base / "cursor-hooks.json"),
        }
        self.environment.pop("PYTHONPATH", None)

    def _install_catalog(self, *arguments: str) -> None:
        result = subprocess.run(
            ["sh", str(self.lifecycle), "install", str(self.origin), *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def _prove_workflow(self, init_skill: Path, distill_skill: Path) -> None:
        self.assertEqual(init_skill.name.removesuffix("init-policy-relay"),
                         distill_skill.name.removesuffix("policy-relay-distill"))
        policy = self.base / "policy"
        e2e.distill(
            distill_skill,
            E2E / "authorized-documents.json",
            E2E / "source-mapping.json",
            policy,
            self.base / "plan",
            "2026-08-27",
        )
        consumer = self.base / "consumer"
        consumer.mkdir()
        e2e.run(["git", "init", "--quiet", "--initial-branch", "main", str(consumer)])
        e2e.install(init_skill, consumer, str(policy))
        self.assertRegex(e2e.session_start(consumer).stdout, r"routes=2\n$")

    def test_blank_prefix_exposes_both_skills_to_every_product(self) -> None:
        self._install_catalog()
        for root in (self.agents, self.claude):
            for skill in SKILLS:
                self.assertTrue((root / skill / "SKILL.md").is_file(), f"{root.name}/{skill}")
        self._prove_workflow(self.claude / SKILLS[0], self.agents / SKILLS[1])

    def test_prefixed_view_keeps_the_scripts_working(self) -> None:
        self._install_catalog("--prefix", "acme")
        init_view = self.claude / f"acme-{SKILLS[0]}"
        distill_view = self.claude / f"acme-{SKILLS[1]}"
        for view in (init_view, distill_view):
            first_lines = (view / "SKILL.md").read_text(encoding="utf-8").splitlines()[:3]
            self.assertIn(f"name: {view.name}", first_lines)
        self.assertTrue(os.access(init_view / "scripts" / "install_policy_relay.py", os.X_OK))
        self._prove_workflow(init_view, distill_view)


if __name__ == "__main__":
    unittest.main()
