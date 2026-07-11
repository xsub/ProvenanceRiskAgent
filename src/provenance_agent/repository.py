from __future__ import annotations

import json
from pathlib import Path
from .models import ProvenanceExport


def load_export(path: str | Path) -> ProvenanceExport:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Input file does not exist: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {source}: {exc}") from exc

    return ProvenanceExport.model_validate(raw)
