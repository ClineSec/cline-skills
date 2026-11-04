#!/usr/bin/env python3
"""Plan, validate, and apply a PolicyRelay bundle with the code bundled in this skill.

Commands:
  plan      Generate a candidate bundle and print a read-only preview.
  validate  Check a bundle directory against contract 1.0.
  apply     Create one local commit from a previewed plan.
"""

import os
import sys


def main() -> int:
    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10 or newer is required", file=sys.stderr)
        return 1
    if os.name != "posix":
        print("ERROR: macOS or Linux is required", file=sys.stderr)
        return 1
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    arguments = sys.argv[1:]
    if not arguments or arguments[0] in {"-h", "--help"}:
        print(__doc__)
        return 0 if arguments else 2
    if arguments[0] == "validate":
        import validate_bundle

        return validate_bundle.main(arguments[1:])
    from policyrelay_distiller.workflow import main as workflow_main

    return workflow_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
