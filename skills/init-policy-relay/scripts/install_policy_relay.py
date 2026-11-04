#!/usr/bin/env python3
"""Run the PolicyRelay installer bundled with this skill."""

import os
import sys


def main() -> int:
    if sys.version_info < (3, 10):
        print("ERROR phase=prerequisite code=python-3.10-required", file=sys.stderr)
        return 1
    if os.name != "posix":
        print("ERROR phase=prerequisite code=macos-or-linux-required", file=sys.stderr)
        return 1
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    from policyrelay.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
