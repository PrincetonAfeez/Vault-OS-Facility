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

from .operations import (
    FacilityAccessMixin,
    FacilityDevicesMixin,
    FacilityEventsMixin,
    FacilityInvitesMixin,
    FacilityPersonnelMixin,
    FacilityVaultMixin,
)


class Facility(
    FacilityPersonnelMixin,
    FacilityAccessMixin,
    FacilityVaultMixin,
    FacilityInvitesMixin,
    FacilityEventsMixin,
    FacilityDevicesMixin,
):
    def __init__(
        self,
        *,
        name: str,
        device_panel: DevicePanel,
        access: AccessController,
        personnel: PersonnelRegistry,
        vault: Vault,
        event_bus: EventBus,
        alert_manager: AlertManager,
        invite_manager: InviteManager,
        event_log: LogHandler,
        person_keycards: dict[str, str] | None = None,
        device_locations: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.device_panel = device_panel
        self.access = access
        self.personnel = personnel
        self.vault = vault
        self.event_bus = event_bus
        self.alert_manager = alert_manager
        self.invite_manager = invite_manager
        self.event_log = event_log
        self.person_keycards = dict(person_keycards or {})
        self.device_locations = dict(device_locations or {})
