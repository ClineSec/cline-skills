"""Private-upstream access: accepted locations and narrow credential forwarding.

These tests are offline. Git's own credential machinery is exercised through
``git credential fill``, which proves a forwarded helper is consulted without a server.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from policyrelay import InstallError, install
from policyrelay import lifecycle
from policyrelay.lifecycle import load_configuration

HELPER = "!f() { echo username=forwarded-user; echo password=forwarded-pass; }; f"
FILL_REQUEST = "protocol=https\nhost=policy.example.invalid\n\n"


class UpstreamLocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.consumer = Path(self.temporary.name) / "consumer"
        self.consumer.mkdir()

    def test_common_ssh_forms_install_and_reload(self) -> None:
        for location in (
            "git@github.com:example-org/policy.git",
            "deploy_key-1@git.example.invalid:team/policy",
            "ssh://git@github.com/example-org/policy.git",
        ):
            with self.subTest(location=location):
                install(self.consumer, location, "main")
                self.assertEqual(location, load_configuration(self.consumer).upstream)

    def test_unsafe_scp_like_locations_are_rejected(self) -> None:
        for location in (
            "git@host.example.invalid:-oProxyCommand=touch-pwned",
            "-oProxyCommand=x@host.example.invalid:path",
            "user:secret@host.example.invalid:path",
            "git@-host.example.invalid:path",
            "git@host.example.invalid:",
            "git@host.example.invalid:path with space",
            "git@host.example.invalid:path?query",
            "host.example.invalid:path",
            "ext::sh -c touch-pwned",
        ):
            with self.subTest(location=location):
                with self.assertRaisesRegex(InstallError, "upstream-invalid"):
                    install(self.consumer, location, "main")
                self.assertFalse((self.consumer / ".policyrelay").exists())


class CredentialForwardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir()
        (self.home / ".gitconfig").write_text(
            "[credential]\n"
            f'\thelper = "{HELPER}"\n'
            '[credential "https://policy.example.invalid"]\n'
            "\tusername = scoped-user\n"
            '[url "https://attacker.example.invalid/"]\n'
            "\tinsteadOf = https://policy.example.invalid/\n"
            "[core]\n"
            "\tsshCommand = touch-pwned\n"
            "\thooksPath = /tmp/pwned-hooks\n",
            encoding="utf-8",
        )
        patcher = mock.patch.dict(
            os.environ,
            {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / "xdg")},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _forwarded(environment: dict[str, str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for index in range(int(environment.get("GIT_CONFIG_COUNT", "0"))):
            key = environment[f"GIT_CONFIG_KEY_{index}"]
            result.setdefault(key, []).append(environment[f"GIT_CONFIG_VALUE_{index}"])
        return result

    def test_https_forwards_only_user_credential_settings(self) -> None:
        forwarded = self._forwarded(lifecycle._clone_environment("https://policy.example.invalid/p.git"))
        self.assertIn(HELPER, forwarded["credential.helper"])
        self.assertEqual(
            ["scoped-user"], forwarded["credential.https://policy.example.invalid.username"]
        )
        for key in forwarded:
            self.assertTrue(key.lower().startswith("credential."), key)

    def test_non_https_upstreams_receive_no_credential_settings(self) -> None:
        for location in (
            "/absolute/path/policy",
            "file:///absolute/path/policy",
            "ssh://git@github.com/example-org/policy.git",
            "git@github.com:example-org/policy.git",
        ):
            with self.subTest(location=location):
                self.assertNotIn("GIT_CONFIG_COUNT", lifecycle._clone_environment(location))

    def test_consumer_repository_config_is_never_a_credential_source(self) -> None:
        consumer = Path(self.temporary.name) / "consumer"
        subprocess.run(
            ["git", "init", "--quiet", "--initial-branch", "main", str(consumer)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(consumer), "config", "credential.helper", "!consumer-controlled"],
            check=True,
            capture_output=True,
        )
        previous = Path.cwd()
        os.chdir(consumer)
        try:
            forwarded = self._forwarded(
                lifecycle._clone_environment("https://policy.example.invalid/p.git")
            )
        finally:
            os.chdir(previous)
        self.assertNotIn("!consumer-controlled", forwarded["credential.helper"])

    def test_inherited_git_environment_is_not_a_credential_source(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "credential.helper",
                "GIT_CONFIG_VALUE_0": "!environment-controlled",
                "GIT_CONFIG_PARAMETERS": "'credential.helper=!parameter-controlled'",
            },
        ):
            environment = lifecycle._clone_environment("https://policy.example.invalid/p.git")
        forwarded = self._forwarded(environment)
        self.assertNotIn("!environment-controlled", forwarded["credential.helper"])
        self.assertNotIn("!parameter-controlled", forwarded["credential.helper"])
        self.assertNotIn("GIT_CONFIG_PARAMETERS", environment)

    def test_forwarded_helper_reaches_git_and_isolated_environment_does_not(self) -> None:
        forwarded = subprocess.run(
            ["git", "credential", "fill"],
            cwd=self.temporary.name,
            env=lifecycle._clone_environment("https://policy.example.invalid/p.git"),
            input=FILL_REQUEST,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(0, forwarded.returncode, forwarded.stderr)
        self.assertIn("password=forwarded-pass", forwarded.stdout)

        isolated = subprocess.run(
            ["git", "credential", "fill"],
            cwd=self.temporary.name,
            env=lifecycle._git_environment(),
            input=FILL_REQUEST,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(0, isolated.returncode)
        self.assertNotIn("forwarded-pass", isolated.stdout)

    def test_credential_settings_never_appear_on_the_clone_command_line(self) -> None:
        captured: list[list[str]] = []
        real_run = subprocess.run

        def record(command, **keywords):
            if "clone" in command:
                captured.append(list(command))
                return subprocess.CompletedProcess(command, 0, b"", b"")
            return real_run(command, **keywords)

        with mock.patch.object(lifecycle.subprocess, "run", side_effect=record):
            lifecycle._clone(
                "https://policy.example.invalid/p.git",
                "main",
                Path(self.temporary.name) / "checkout",
            )
        self.assertEqual(1, len(captured))
        self.assertNotIn(HELPER, " ".join(captured[0]))
        self.assertNotIn("credential", " ".join(captured[0]))

    def test_excess_settings_fail_closed_to_no_forwarding(self) -> None:
        lines = "".join(f'[credential "https://h{i}.example.invalid"]\n\tusername = u\n' for i in range(80))
        (self.home / ".gitconfig").write_text(lines, encoding="utf-8")
        self.assertEqual([], lifecycle._user_credential_settings())


if __name__ == "__main__":
    unittest.main()
