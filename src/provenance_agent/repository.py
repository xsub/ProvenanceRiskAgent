"""Saved-assessment repository boundary.

Loads JSON exports from disk and passes them through the same normalization
contract used by live investigations.
"""

from __future__ import annotations

import json
from pathlib import Path

from .normalization import normalize_export


def load_export(path: str | Path) -> dict:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Input file does not exist: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc

    return normalize_export(raw, source)
