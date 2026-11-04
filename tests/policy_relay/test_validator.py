from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from policyrelay.validator import validate_bundle

from .support import copy_bundle, mutate_manifest


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = copy_bundle(self.root / "bundle")

    def codes(self) -> set[str]:
        return {issue.code for issue in validate_bundle(self.bundle)}

    def test_reference_is_valid(self) -> None:
        self.assertEqual([], validate_bundle(self.bundle))

    def test_manifest_shape_version_routes_and_duplicates(self) -> None:
        mutate_manifest(self.bundle, lambda value: value.__setitem__("contractVersion", "2.0"))
        self.assertIn("unsupported-version", self.codes())
        (self.bundle / "manifest.json").write_text('{"contractVersion":"1.0","contractVersion":"2.0"}')
        self.assertIn("json", self.codes())

    def test_layout_utf8_and_symlinks(self) -> None:
        (self.bundle / "extra").write_text("unexpected")
        (self.bundle / "payload" / "guidance" / "secure-coding.md").write_bytes(b"\xff")
        link = self.bundle / "payload" / "guidance" / "link.md"
        link.symlink_to("secure-coding.md")
        codes = self.codes()
        self.assertTrue({"root-entry-unexpected", "utf8", "symlink-forbidden"} <= codes)

    def test_escaping_and_unsupported_links(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        path.write_text(path.read_text() + "\n[x](../../outside.md) [y](http://example.invalid)\n")
        codes = self.codes()
        self.assertIn("link-escape", codes)
        self.assertIn("link-scheme", codes)

    def test_progressive_index_correspondence_and_bounds(self) -> None:
        path = self.bundle / "payload" / "index.md"
        path.write_text("# Routes\n\n[wrong](guidance/secure-coding.md)\n" + ("x\n" * 26))
        codes = self.codes()
        self.assertTrue({"index-route-missing", "index-route-ambiguous", "index-size"} <= codes)

    def test_guidance_shape_and_provenance(self) -> None:
        path = self.bundle / "payload" / "guidance" / "secure-coding.md"
        value = path.read_text().replace('"sourceLocator": "Section 4.2, Change Safety",\n', "")
        value = value.replace("## Normative guidance", "## Wrong section")
        path.write_text(value)
        codes = self.codes()
        self.assertIn("provenance-malformed", codes)
        self.assertIn("guidance-sections", codes)

    def test_diagnostics_are_bounded_and_do_not_echo_content(self) -> None:
        secret = "SECRET-" + ("x" * 10_000)
        (self.bundle / "manifest.json").write_text("{" + json.dumps(secret) + ": 1,", encoding="utf-8")
        (self.bundle / "SECRET-filename").write_text("x", encoding="utf-8")
        issues = validate_bundle(self.bundle)
        rendered = "\n".join(f"{i.code}:{i.path}" for i in issues)
        self.assertNotIn("SECRET", rendered)
        self.assertLess(len(rendered), 10_000)


if __name__ == "__main__":
    unittest.main()
