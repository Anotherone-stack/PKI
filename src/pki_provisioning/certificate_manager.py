from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FileStore:
    def __init__(self, path: str | Path = "pki_store.json") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"devices": {}, "certificates": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"devices": {}, "certificates": {}}

    def save(self, state: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")
