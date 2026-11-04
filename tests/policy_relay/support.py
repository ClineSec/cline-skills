from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
CATALOG = ROOT.parents[1]
INIT_SKILL = CATALOG / "skills" / "init-policy-relay"
DISTILL_SKILL = CATALOG / "skills" / "policy-relay-distill"
RUNTIME_SCRIPTS = INIT_SKILL / "scripts"
DISTILL_SCRIPTS = DISTILL_SKILL / "scripts"
FIXTURES = ROOT / "fixtures"
REFERENCE = FIXTURES / "reference-bundle"


def copy_bundle(destination: Path) -> Path:
    return Path(shutil.copytree(REFERENCE, destination))


def mutate_manifest(bundle: Path, mutation: Callable[[dict[str, Any]], None]) -> None:
    path = bundle / "manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    mutation(value)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def digest_tree(root: Path) -> str | None:
    if not root.exists():
        return None
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(relative)
        if path.is_symlink():
            digest.update(b"L" + str(path.readlink()).encode())
        elif path.is_dir():
            digest.update(b"D")
        else:
            digest.update(b"F" + path.read_bytes())
    return digest.hexdigest()
