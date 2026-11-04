"""The installed runtime validator must agree with the authoritative contract validator.

Each skill must stay self-contained, so the runtime carries its own validator. This suite is the
drift check between that copy and ``policy-relay-distill/scripts/validate_bundle.py``.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import validate_bundle as authoritative_validator
from policyrelay.validator import validate_bundle

from .support import copy_bundle, mutate_manifest


class ContractParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = copy_bundle(Path(self.temporary.name) / "bundle")

    def assert_parity(self) -> None:
        ours = {issue.code for issue in validate_bundle(self.bundle)}
        accepted = {issue.code for issue in authoritative_validator.validate_bundle(self.bundle)}
        self.assertEqual(accepted, ours)

    def test_accepted_reference(self) -> None:
        self.assert_parity()

    def test_unsupported_version(self) -> None:
        mutate_manifest(self.bundle, lambda value: value.__setitem__("contractVersion", "2.0"))
        self.assert_parity()

    def test_escaping_link(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text() + "\n[x](../../outside.md)\n")
        self.assert_parity()

    def test_symlink(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.unlink()
        path.symlink_to(Path(self.temporary.name) / "outside")
        self.assert_parity()

    def test_malformed_json(self) -> None:
        (self.bundle / "manifest.json").write_text("{broken")
        self.assert_parity()

    def test_broken_link(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text() + "\n[x](missing.md)\n")
        self.assert_parity()

    def test_duplicate_route(self) -> None:
        def duplicate(value: dict) -> None:
            value["routes"][1] = dict(value["routes"][0])
        mutate_manifest(self.bundle, duplicate)
        self.assert_parity()

    def test_index_mismatch(self) -> None:
        path = self.bundle / "payload" / "index.md"
        path.write_text(path.read_text().replace("[secure-coding]", "[wrong-task]"))
        self.assert_parity()

    def test_missing_route_target(self) -> None:
        (self.bundle / "payload" / "guidance" / "secure-coding.md").unlink()
        self.assert_parity()

    def test_malformed_provenance(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text().replace('      "sourceLocator": "Section 4.2, Change Safety",\n', ""))
        self.assert_parity()
