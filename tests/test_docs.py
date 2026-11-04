"""Keep the documentation structure honest: every skill has a guide, and links resolve."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "docs" / "skills"
LINK = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^```.*?^```", re.M | re.S)
HEADING = re.compile(r"^#{1,6} +(.+?) *$", re.M)


def skill_names() -> list[str]:
    return sorted(path.name for path in (ROOT / "skills").iterdir() if path.is_dir())


def prose(path: Path) -> str:
    return FENCE.sub("", path.read_text(encoding="utf-8"))


def anchors(path: Path) -> set[str]:
    found = set()
    for heading in HEADING.findall(prose(path)):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        found.add(slug)
    return found


class DocumentationTests(unittest.TestCase):
    def test_every_skill_has_a_guide_listed_in_the_index_and_readme(self) -> None:
        index = (GUIDES / "README.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in skill_names():
            with self.subTest(skill=name):
                self.assertTrue((GUIDES / f"{name}.md").is_file(), "missing guide")
                self.assertIn(f"({name}.md)", index)
                self.assertIn(f"(docs/skills/{name}.md)", readme)

    def test_local_links_and_anchors_resolve(self) -> None:
        for document in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
            for target in LINK.findall(prose(document)):
                if "://" in target or target.startswith("mailto:"):
                    continue
                relative, _, anchor = target.partition("#")
                path = (document.parent / relative).resolve() if relative else document
                with self.subTest(document=document.relative_to(ROOT).as_posix(), target=target):
                    self.assertTrue(path.exists(), "broken link")
                    if anchor and path.suffix == ".md":
                        self.assertIn(anchor, anchors(path), "broken anchor")


if __name__ == "__main__":
    unittest.main()
