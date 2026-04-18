from __future__ import annotations

import os
import sys
from pathlib import Path

_SUBPROJECTS = ("Access", "Devices", "Events", "Invites", "Personnel", "Vault")


def repository_root() -> Path:
    override = os.environ.get("VAULTOS_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[2]

def ensure_subproject_paths() -> None:
    root = repository_root()
    existing = {Path(entry).resolve() for entry in sys.path if entry}
    for name in _SUBPROJECTS:
        path = (root / name).resolve()
        if path not in existing:
            sys.path.append(str(path))
            existing.add(path)
