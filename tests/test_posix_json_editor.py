from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EDITOR = ROOT / "scripts" / "team-skills-json.awk"


@unittest.skipIf(os.name == "nt", "the POSIX JSON editor is used by the POSIX installer")
class PosixJsonEditorTests(unittest.TestCase):
    def edit(
        self, source: str, operation: str, product: str = "", command: str = ""
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["TEAM_SKILLS_JSON_COMMAND"] = command
        # The lifecycle utility always fixes the byte-oriented parser locale so awk variants do
        # not reinterpret UTF-8 bytes while canonicalizing escaped object keys.
        environment["LC_ALL"] = "C"
        arguments = ["awk", f"-voperation={operation}"]
        if product:
            arguments.append(f"-vproduct={product}")
        arguments.extend(["-f", str(EDITOR)])
        return subprocess.run(
            arguments,
            input=source,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )

    def test_check_accepts_object_and_rejects_malformed_or_unsupported_root(self) -> None:
        self.assertEqual(self.edit('{"valid": [1, true, null]}', "check").returncode, 0)
        for source in ('{"broken":', "[]", '{"duplicate": 1, "duplicate": 2}'):
            with self.subTest(source=source):
                result = self.edit(source, "check")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_check_rejects_decoded_duplicate_and_case_colliding_keys(self) -> None:
        sources = (
            '{"key": 1, "\\u006bey": 2}',
            '{"é": 1, "\\u00e9": 2}',
            '{"😀": 1, "\\ud83d\\ude00": 2}',
            '{"key": 1, "KEY": 2}',
        )
        for source in sources:
            with self.subTest(source=source):
                result = self.edit(source, "check")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_check_bounds_size_depth_and_rejects_malformed_utf8(self) -> None:
        deep = '{"a":' * 65 + '1' + '}' * 65
        self.assertNotEqual(self.edit(deep, "check").returncode, 0)
        oversized = '{"value":"' + ('a' * 1048576) + '"}'
        self.assertNotEqual(self.edit(oversized, "check").returncode, 0)

        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        malformed_utf8 = subprocess.run(
            ["awk", "-voperation=check", "-f", str(EDITOR)],
            input=b'{"foreign":"\xed\xa0\x80"}\n',
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertNotEqual(malformed_utf8.returncode, 0)
        self.assertEqual(malformed_utf8.stdout, b"")

    def test_check_rejects_every_raw_json_control_byte(self) -> None:
        environment = os.environ.copy()
        for value in range(0x20):
            with self.subTest(value=value):
                source = b'{"foreign":"a' + bytes([value]) + b'b"}\n'
                result = subprocess.run(
                    ["awk", "-voperation=check", "-f", str(EDITOR)],
                    input=source,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

        permitted = subprocess.run(
            ["awk", "-voperation=check", "-f", str(EDITOR)],
            input=b'{"foreign":"a\x7fb"}\n',
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(permitted.returncode, 0, permitted.stderr)

    def test_claude_add_is_structural_preserving_and_idempotent(self) -> None:
        source = json.dumps(
            {
                "permissions": {"allow": ["Read"]},
                "hooks": {
                    "PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "foreign"}]}],
                    "SessionStart": [
                        {"matcher": "resume", "hooks": [{"command": "foreign-start"}]}
                    ],
                },
            },
            ensure_ascii=False,
        )
        command = "sh '/tmp/Team Skills 🧪/it'\\''s/update.sh' hook instance-$x"
        first = self.edit(source, "add", "claude", command)
        self.assertEqual(first.returncode, 0, first.stderr)
        value = json.loads(first.stdout)
        self.assertEqual(value["permissions"], {"allow": ["Read"]})
        self.assertEqual(value["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "foreign")
        self.assertEqual(value["hooks"]["SessionStart"][0]["matcher"], "resume")
        owned = value["hooks"]["SessionStart"][1]
        self.assertEqual(owned["matcher"], "startup|clear")
        self.assertEqual(
            owned["hooks"],
            [{"type": "command", "command": command, "async": True}],
        )

        second = self.edit(first.stdout, "add", "claude", command)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout), value)

    def test_codex_uses_startup_and_clear_async_group(self) -> None:
        unrelated = {
            "description": "Keep this Codex hook description",
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
        result = self.edit(json.dumps(unrelated), "add", "codex", "owned-codex-command")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["description"], unrelated["description"])
        self.assertEqual(value["hooks"]["Other"], unrelated["hooks"]["Other"])
        groups = value["hooks"]["SessionStart"]
        self.assertEqual(
            groups,
            [
                {
                    "matcher": "startup|clear",
                    "hooks": [
                        {"type": "command", "command": "owned-codex-command", "async": True}
                    ],
                }
            ],
        )

    def test_codex_rejects_unknown_root_fields_and_invalid_description_without_output(self) -> None:
        for source in ('{"foreign":true}', '{"description":7,"hooks":{}}'):
            with self.subTest(source=source):
                result = self.edit(source, "add", "codex", "owned")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

        # These are product-specific restrictions; other editors continue preserving
        # unrelated root fields.
        for product in ("claude", "cursor"):
            with self.subTest(product=product):
                result = self.edit('{"foreign":true}', "add", product, "owned")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(result.stdout)["foreign"])

    def test_cursor_adds_session_start_only_and_preserves_other_events(self) -> None:
        source = json.dumps(
            {
                "version": 1,
                "foreign": "keep",
                "hooks": {
                    "sessionStart": [{"command": "foreign-start"}],
                    "workspaceOpen": [{"command": "foreign-workspace"}],
                },
            }
        )
        result = self.edit(source, "add", "cursor", "owned-cursor-command")
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["foreign"], "keep")
        self.assertEqual(value["hooks"]["workspaceOpen"], [{"command": "foreign-workspace"}])
        self.assertEqual(
            value["hooks"]["sessionStart"],
            [{"command": "foreign-start"}, {"command": "owned-cursor-command"}],
        )

    def test_remove_deletes_only_exact_owned_entry(self) -> None:
        for product in ("claude", "codex", "cursor"):
            with self.subTest(product=product):
                source = '{"description":"keep"}' if product == "codex" else '{"foreign":true}'
                owned_command = f"owned-{product}"
                added = self.edit(source, "add", product, owned_command)
                self.assertEqual(added.returncode, 0, added.stderr)
                foreign_command = f"foreign-{product}"
                with_foreign = self.edit(added.stdout, "add", product, foreign_command)
                self.assertEqual(with_foreign.returncode, 0, with_foreign.stderr)

                removed = self.edit(with_foreign.stdout, "remove", product, owned_command)
                self.assertEqual(removed.returncode, 0, removed.stderr)
                value = json.loads(removed.stdout)
                if product == "codex":
                    self.assertEqual(value["description"], "keep")
                else:
                    self.assertTrue(value["foreign"])
                serialized = json.dumps(value)
                self.assertNotIn(owned_command, serialized)
                self.assertIn(foreign_command, serialized)

    def test_remove_refuses_changed_missing_or_ambiguous_entry(self) -> None:
        added = self.edit("{}", "add", "claude", "owned")
        self.assertEqual(added.returncode, 0, added.stderr)
        value = json.loads(added.stdout)
        value["hooks"]["SessionStart"][0]["hooks"][0]["async"] = False
        changed = self.edit(json.dumps(value), "remove", "claude", "owned")
        self.assertEqual(changed.returncode, 3)
        self.assertEqual(changed.stdout, "")

        missing = self.edit("{}", "remove", "cursor", "owned")
        self.assertEqual(missing.returncode, 3)

        duplicate_value = json.loads(added.stdout)
        duplicate_value["hooks"]["SessionStart"].append(
            duplicate_value["hooks"]["SessionStart"][0]
        )
        ambiguous = self.edit(json.dumps(duplicate_value), "remove", "claude", "owned")
        self.assertEqual(ambiguous.returncode, 3)

    def test_unsupported_existing_shapes_are_refused_without_output(self) -> None:
        fixtures = (
            ("claude", '{"hooks":[]}'),
            ("codex", '{"hooks":{"SessionStart":{}}}'),
            ("cursor", '{"version":2,"hooks":{}}'),
            ("cursor", '{"hooks":{"sessionStart":{}}}'),
        )
        for product, source in fixtures:
            with self.subTest(product=product, source=source):
                result = self.edit(source, "add", product, "owned")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
