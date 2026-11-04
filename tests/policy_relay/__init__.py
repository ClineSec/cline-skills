"""PolicyRelay skill tests: the runtime, Distiller, contract, and end-to-end workflow.

The catalog supports Python 3.9 and native Windows, but PolicyRelay needs Python 3.10 or newer on
macOS or Linux, so this package skips itself elsewhere. CI runs it in a dedicated job.
"""

import os
import sys
import unittest

if sys.version_info < (3, 10) or os.name == "nt":
    raise unittest.SkipTest("PolicyRelay requires Python 3.10+ on macOS or Linux")

from pathlib import Path

_CATALOG = Path(__file__).resolve().parents[2]
_SCRIPTS = [
    str(_CATALOG / "skills" / "init-policy-relay" / "scripts"),
    str(_CATALOG / "skills" / "policy-relay-distill" / "scripts"),
]
sys.dont_write_bytecode = True
sys.path[:0] = _SCRIPTS
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONPATH"] = os.pathsep.join(
    [*_SCRIPTS, *filter(None, [os.environ.get("PYTHONPATH")])]
)
