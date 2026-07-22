#!/usr/bin/env python3
"""Command-line entry point for the deterministic golden evaluation suite.

Parses the manifest option, runs all evaluation cases, renders JSON results,
and maps aggregate success to a process exit status.
"""

from __future__ import annotations

import argparse
import json

from provenance_agent.golden import DEFAULT_MANIFEST, run_golden_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic golden suite.")
    parser.add_argument("manifest", nargs="?", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    result = run_golden_suite(args.manifest)
    print(json.dumps(result, indent=None if args.compact else 2, sort_keys=True))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
