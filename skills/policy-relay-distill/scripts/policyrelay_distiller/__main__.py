from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import DistillationError, distill, load_input, write_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic PolicyRelay contract 1.0 bundle."
    )
    parser.add_argument("source", type=Path, help="normalized local JSON input")
    parser.add_argument("output", type=Path, help="new bundle directory")
    args = parser.parse_args(argv)

    try:
        logical_input = load_input(args.source)
        files = distill(logical_input)
        write_bundle(files, args.output)
    except (DistillationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    manifest = json.loads(files["manifest.json"])
    print(
        "GENERATED "
        f"bundleId={manifest['bundleId']} "
        f"revision={manifest['bundleRevision']} "
        f"routes={len(manifest['routes'])} "
        f"output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
