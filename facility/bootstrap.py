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

