from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters import (
    AccessController,
    AlertHandler,
    AlertManager,
    DevicePanel,
    EventBus,
    InviteManager,
    LogHandler,
    PersonnelRegistry,
    Vault,
    build_demo_controller,
    seed_demo_panel,
    seed_demo_vault,
)

class FacilityError(Exception):
    """Base integration-layer error."""


class FacilityStateError(FacilityError):
    """Raised when cross-system facility state blocks an operation."""

