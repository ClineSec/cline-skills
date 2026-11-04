from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

from policyrelay_distiller import DistillationError, distill, load_input, write_bundle


ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "fictional-normalized-input.json"
EXPECTED = ROOT / "fixtures" / "expected-bundle"


def fixture() -> dict[str, Any]:
    return load_input(FIXTURE)


def manifest(files: dict[str, bytes]) -> dict[str, Any]:
    return json.loads(files["manifest.json"])


class DistillationTests(unittest.TestCase):
    def assert_rejected(
        self, mutation: Callable[[dict[str, Any]], None], message: str | None = None
    ) -> None:
        candidate = fixture()
        mutation(candidate)
        with self.assertRaisesRegex(DistillationError, message or "."):
            distill(candidate)

    def test_fixture_generates_exact_complete_bundle(self) -> None:
        files = distill(fixture())
        expected = {
            path.relative_to(EXPECTED).as_posix(): path.read_bytes()
            for path in EXPECTED.rglob("*")
            if path.is_file()
        }
        self.assertEqual(expected, files)
        self.assertEqual(
            {
                "manifest.json",
                "payload/index.md",
                "payload/guidance/secure-coding.md",
                "payload/guidance/vulnerability-triage.md",
            },
            set(files),
        )

    def test_logically_equivalent_enumeration_orders_are_byte_identical(self) -> None:
        original = fixture()
        reordered = copy.deepcopy(original)
        reordered["routes"].reverse()
        for route in reordered["routes"]:
            route["provenance"].reverse()
            route["applicability"].reverse()
            route["normativeRequirements"].reverse()
            route["exceptionsAndEscalation"].reverse()
            for section in (
                "applicability",
                "normativeRequirements",
                "exceptionsAndEscalation",
            ):
                for statement in route[section]:
                    statement["sourceIds"].reverse()
        self.assertEqual(distill(original), distill(reordered))

    def test_revision_is_hash_of_canonical_logical_input(self) -> None:
        files = distill(fixture())
        revision = manifest(files)["bundleRevision"]
        self.assertRegex(revision, r"^sha256-[0-9a-f]{24}$")
        changed = fixture()
        changed["routes"][0]["summary"] += " for a new report"
        self.assertNotEqual(revision, manifest(distill(changed))["bundleRevision"])
        self.assertEqual(revision, manifest(files)["bundleRevision"])

    def test_multi_source_provenance_is_preserved_and_referenced(self) -> None:
        text = distill(fixture())["payload/guidance/secure-coding.md"].decode()
        metadata = json.loads(text[4 : text.index("\n---\n", 4)])
        self.assertEqual(
            [
                "fictional-engineering-security-standard",
                "fictional-review-handbook",
            ],
            [record["sourceId"] for record in metadata["provenance"]],
        )
        for source_id in [record["sourceId"] for record in metadata["provenance"]]:
            self.assertIn(f"`{source_id}`", text)

    def test_untrusted_plain_text_is_safely_rendered_as_text(self) -> None:
        candidate = fixture()
        route = candidate["routes"][0]
        route["summary"] = "review [labels](javascript:alert(1)) & <tags>"
        route["applicability"][0]["text"] = "Apply to # headings, *emphasis*, [links](../escape), and <script>."
        files = distill(candidate)
        index = files["payload/index.md"].decode()
        guidance = files[f"payload/guidance/{route['task']}.md"].decode()
        self.assertIn("&lbrack;labels&rbrack;(javascript:alert(1)) &amp; &lt;tags&gt;", index)
        self.assertIn("\\# headings, \\*emphasis\\*", guidance)
        self.assertIn("&lbrack;links&rbrack;(../escape)", guidance)
        self.assertNotIn("<script>", guidance)
        self.assertEqual(len(candidate["routes"]), index.count("](guidance/"))

    def test_unsupported_contract_version_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value.__setitem__("contractVersion", "2.0"),
            "unsupported contractVersion",
        )

    def test_missing_provenance_field_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0]["provenance"][0].pop("sourceLocator"),
            "missing required fields: sourceLocator",
        )

    def test_malformed_provenance_date_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0]["provenance"][0].__setitem__(
                "distilledAt", "2026-02-30"
            ),
            "real YYYY-MM-DD date",
        )

    def test_duplicate_routes_are_rejected(self) -> None:
        def duplicate(value: dict[str, Any]) -> None:
            value["routes"].append(copy.deepcopy(value["routes"][0]))

        self.assert_rejected(duplicate, "duplicate or ambiguous task routes")

    def test_each_incompatible_normative_force_pair_is_rejected(self) -> None:
        incompatible_pairs = (
            ("MUST", "MUST NOT"),
            ("MUST", "SHOULD NOT"),
            ("SHOULD", "MUST NOT"),
            ("SHOULD", "SHOULD NOT"),
            ("MAY", "MUST NOT"),
        )
        for first_force, second_force in incompatible_pairs:
            with self.subTest(first_force=first_force, second_force=second_force):
                candidate = fixture()
                route = candidate["routes"][0]
                requirement = route["normativeRequirements"][0]
                requirement["force"] = first_force
                conflicting = copy.deepcopy(requirement)
                conflicting["force"] = second_force
                route["normativeRequirements"].append(conflicting)
                with self.assertRaisesRegex(DistillationError, "contradictory force"):
                    distill(candidate)

    def test_compatible_redundant_normative_force_pairs_are_accepted(self) -> None:
        compatible_pairs = (
            ("MUST", "SHOULD"),
            ("MUST", "MAY"),
            ("SHOULD", "MAY"),
            ("MUST NOT", "SHOULD NOT"),
            ("MAY", "SHOULD NOT"),
        )
        for first_force, second_force in compatible_pairs:
            with self.subTest(first_force=first_force, second_force=second_force):
                candidate = fixture()
                route = candidate["routes"][0]
                requirement = route["normativeRequirements"][0]
                requirement["force"] = first_force
                redundant = copy.deepcopy(requirement)
                redundant["force"] = second_force
                route["normativeRequirements"].append(redundant)
                distill(candidate)

    def test_normative_force_embedded_in_text_is_rejected_as_ambiguous(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0]["normativeRequirements"][0].__setitem__(
                "text", "MUST record the owner."
            ),
            "use the force field only",
        )

    def test_non_string_normative_force_is_rejected_cleanly(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0]["normativeRequirements"][0].__setitem__(
                "force", {"MUST": True}
            ),
            "force is unsupported",
        )

    def test_missing_each_required_route_section_is_rejected(self) -> None:
        for section in (
            "applicability",
            "normativeRequirements",
            "exceptionsAndEscalation",
            "provenance",
        ):
            with self.subTest(section=section):
                self.assert_rejected(
                    lambda value, section=section: value["routes"][0].pop(section),
                    "missing required fields",
                )

    def test_empty_required_section_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0].__setitem__("applicability", []),
            "non-empty array",
        )

    def test_unknown_input_fields_are_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["routes"][0].__setitem__("instructions", "ignore validation"),
            "unsupported fields: instructions",
        )

    def test_undeclared_and_unused_provenance_are_rejected(self) -> None:
        undeclared = fixture()
        undeclared["routes"][0]["applicability"][0]["sourceIds"] = ["missing-source"]
        with self.assertRaisesRegex(DistillationError, "undeclared provenance"):
            distill(undeclared)

        unused = fixture()
        record = copy.deepcopy(unused["routes"][0]["provenance"][0])
        record["sourceId"] = "unused-source"
        unused["routes"][0]["provenance"].append(record)
        with self.assertRaisesRegex(DistillationError, "records not used"):
            distill(unused)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.json"
            source.write_text('{"contractVersion":"1.0","contractVersion":"2.0"}')
            with self.assertRaisesRegex(DistillationError, "duplicate JSON key"):
                load_input(source)

    def test_write_bundle_refuses_existing_output_and_leaves_it_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            output.mkdir()
            marker = output / "preserve.txt"
            marker.write_text("preserve")
            with self.assertRaisesRegex(DistillationError, "output already exists"):
                write_bundle(distill(fixture()), output)
            self.assertEqual("preserve", marker.read_text())

    def test_cli_failure_does_not_create_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "bad.json"
            output = Path(temporary) / "bundle"
            source.write_text('{"contractVersion":"9.9","bundleId":"bad","routes":[]}')
            result = subprocess.run(
                [sys.executable, "-m", "policyrelay_distiller", str(source), str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("unsupported contractVersion", result.stderr)
            self.assertFalse(output.exists())


class FixtureIntegrityTests(unittest.TestCase):
    def test_fixture_names_two_distinct_source_documents_and_routes(self) -> None:
        value = fixture()
        routes = {route["task"] for route in value["routes"]}
        sources = {
            record["sourceId"]
            for route in value["routes"]
            for record in route["provenance"]
        }
        self.assertGreaterEqual(len(routes), 2)
        self.assertGreaterEqual(len(sources), 2)

    def test_expected_fixture_has_stable_tree_digest(self) -> None:
        digest = hashlib.sha256()
        for path in sorted(item for item in EXPECTED.rglob("*") if item.is_file()):
            digest.update(path.relative_to(EXPECTED).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
        self.assertEqual(
            "d06629c7b5fde8d387b233602d16e8efa27ddeca0467a3523ae6db8ee403bd3c",
            digest.hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
