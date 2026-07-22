"""Narrow process bridge to supported EDGP library capabilities.

Builds ALBS artifact inventories, normalizes advisory snapshots, and exposes a
JSON command interface that isolates optional EDGP runtime dependencies.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def build_albs_inventory(
    build_id: int,
    base_url: str,
    task_limit: int,
    artifact_limit: int,
) -> dict[str, Any]:
    from src.adapters.albs import AlbsBuildAdapter
    from src.albs_artifact_inventory import build_albs_artifact_inventory

    resolved = AlbsBuildAdapter().parse_build(
        build_id,
        base_url=base_url,
        task_limit=task_limit,
        artifact_limit=artifact_limit,
    )
    return build_albs_artifact_inventory(
        resolved.graph,
        root=resolved.root_identifier,
    )


def normalize_advisory(path: Path, ecosystem: str) -> dict[str, Any]:
    from src.public_advisory_feed import build_public_advisory_feed_report

    payload = json.loads(path.read_text(encoding="utf-8"))
    return build_public_advisory_feed_report(payload, ecosystem=ecosystem)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Narrow process bridge to installed EDGP library modules."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("albs-artifact-inventory")
    inventory.add_argument("--build-id", type=int, required=True)
    inventory.add_argument("--base-url", required=True)
    inventory.add_argument("--task-limit", type=int, default=5000)
    inventory.add_argument("--artifact-limit", type=int, default=5000)
    inventory.add_argument("--format", choices=["json"], default="json")

    advisory = subparsers.add_parser("public-advisory-feed")
    advisory.add_argument("--path", type=Path, required=True)
    advisory.add_argument("--ecosystem", required=True)
    advisory.add_argument("--format", choices=["report"], default="report")

    args = parser.parse_args()
    if args.command == "albs-artifact-inventory":
        result = build_albs_inventory(
            args.build_id,
            args.base_url,
            args.task_limit,
            args.artifact_limit,
        )
    else:
        result = normalize_advisory(args.path, args.ecosystem)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
