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
    """Integration façade over Vault OS day-16+ subsystems (access, vault, personnel, …)."""

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

    @classmethod
    def create_demo(cls, name: str = "Vault OS Demo Facility") -> Facility:
        from .demo import configure_demo_facility

        event_bus, alert_manager, event_log = cls._build_event_stack()
        facility = cls(
            name=name,
            device_panel=seed_demo_panel(),
            access=build_demo_controller(),
            personnel=PersonnelRegistry(),
            vault=seed_demo_vault(),
            event_bus=event_bus,
            alert_manager=alert_manager,
            invite_manager=InviteManager(),
            event_log=event_log,
            device_locations={
                "CAM-01": "Main Entrance",
                "LOCK-01": "Vault Threshold",
                "ALARM-01": "North Wing",
                "THERM-01": "Server Room",
            },
        )

        for device in facility.device_panel.devices:
            device.power_on()

        configure_demo_facility(facility)
        return facility

    @staticmethod
    def _build_event_stack() -> tuple[EventBus, AlertManager, LogHandler]:
        alert_manager = AlertManager()
        event_bus = EventBus(dedup_threshold=10)
        event_log = LogHandler()
        event_bus.subscribe(event_log, name="facility-log")
        event_bus.subscribe(AlertHandler(alert_manager), name="facility-alerting")
        return event_bus, alert_manager, event_log

    def save(self, path: str | Path) -> Path:
        from .persistence import write_facility_json

        return write_facility_json(self, path)

    @classmethod
    def load(cls, path: str | Path) -> Facility:
        from .persistence import read_facility_json

        return read_facility_json(path, facility_cls=cls)

    def to_record(self) -> dict[str, Any]:
        from .persistence import facility_to_record

        return facility_to_record(self)

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> Facility:
        from .persistence import facility_from_record

        return facility_from_record(record, facility_cls=cls)
