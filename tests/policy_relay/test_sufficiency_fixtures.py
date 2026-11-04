"""Keep the examples and fixtures that teach or test route sufficiency honest.

A script can't tell whether a route is sufficient, so ``live_e2e.py`` tests that with real agents.
These tests only keep its inputs, and the example agents learn from, from drifting.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from . import e2e_support as e2e
from .support import DISTILL_SKILL, FIXTURES

SUFFICIENCY = FIXTURES / "e2e" / "sufficiency"
ASSETS = DISTILL_SKILL / "assets"
DATE = "2026-08-27"
RUBRIC = "Critical is exploitable now with no authentication"


def distilled_guidance(documents: Path, mapping: Path, base: Path) -> str:
    policy = base / "policy"
    e2e.distill(DISTILL_SKILL, documents, mapping, policy, base / "plan", DATE)
    guidance = policy / "bundle" / "payload" / "guidance"
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(guidance.glob("*.md")))


class SufficiencyFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def test_skill_example_carries_the_rubric_it_applies(self) -> None:
        documents = ASSETS / "example-authorized-documents.json"
        self.assertIn(RUBRIC, documents.read_text(encoding="utf-8"))
        guidance = distilled_guidance(documents, ASSETS / "example-source-mapping.json", self.base)
        self.assertIn(RUBRIC, guidance)

    def test_skill_example_only_says_what_its_sources_say(self) -> None:
        documents = json.loads((ASSETS / "example-authorized-documents.json").read_text(encoding="utf-8"))
        content = {document["sourceId"]: document["content"].lower() for document in documents}
        mapping = json.loads((ASSETS / "example-source-mapping.json").read_text(encoding="utf-8"))
        for route in mapping["routes"]:
            for section in ("applicability", "normativeRequirements", "exceptionsAndEscalation"):
                for statement in route[section]:
                    for source_id in statement["sourceIds"]:
                        self.assertIn(statement["text"].lower(), content[source_id])

    def test_a_section_may_say_the_sources_state_nothing(self) -> None:
        mapping = json.loads((SUFFICIENCY / "mapping-omits-schedule.json").read_text(encoding="utf-8"))
        statement = "The sources state no exceptions or escalation path for this task."
        mapping["routes"][0]["exceptionsAndEscalation"][0]["text"] = statement
        path = self.base / "mapping.json"
        path.write_text(json.dumps(mapping), encoding="utf-8")
        self.assertIn(statement, distilled_guidance(SUFFICIENCY / "documents.json", path, self.base))

    def test_control_route_validates_without_the_list(self) -> None:
        guidance = distilled_guidance(
            SUFFICIENCY / "documents.json", SUFFICIENCY / "mapping-omits-schedule.json", self.base
        )
        for entry in e2e.SCHEDULE_ENTRIES:
            self.assertNotIn(entry, guidance)

    def test_the_policy_keeps_its_deliberately_undefined_term(self) -> None:
        content = (SUFFICIENCY / "documents.json").read_text(encoding="utf-8")
        self.assertIn("high-impact actions require approval", content)
        self.assertNotIn("A high-impact action", content)

    def test_only_the_full_documents_contain_the_list(self) -> None:
        full = (SUFFICIENCY / "documents.json").read_text(encoding="utf-8")
        missing = json.loads((SUFFICIENCY / "documents-missing-schedule.json").read_text(encoding="utf-8"))
        for entry in e2e.SCHEDULE_ENTRIES:
            self.assertIn(entry, full)
            self.assertNotIn(entry, json.dumps(missing))
        self.assertIn("Approved Provider Schedule", json.dumps(missing))


if __name__ == "__main__":
    unittest.main()
