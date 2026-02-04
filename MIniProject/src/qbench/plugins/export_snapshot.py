from __future__ import annotations

import json
from pathlib import Path


def get_plugin_info() -> dict:
    return {
        "name": "export_snapshot",
        "description": "Exports a snapshot payload to JSON file.",
        "version": "1.0.0",
    }


def run(payload: dict) -> dict:
    path = Path(payload.get("path", "snapshot.json"))
    path.write_text(json.dumps(payload.get("data", {}), indent=2), encoding="utf-8")
    return {"saved_to": str(path)}
