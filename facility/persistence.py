from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from .adapters import (
    AccessController,
    AccessGate,
    AccessLog,
    AccessLogEntry,
    ActivityEntry,
    AlarmSystem,
    Alert,
    AlertHandler,
    AlertManager,
    AlertState,
    AuditAction,
    Camera,
    CardRegistry,
    Contractor,
    CustodyRecord,
    Device,
    Employee,
    Event,
    EventBus,
    Item,
    ItemCondition,
    ItemStatus,
    InviteManager,
    Keycard,
    Lock,
    LogHandler,
    PERSON_TYPES,
    Person,
    PersonnelRegistry,
    RecordingSession,
    SecurityAlert,
    SuspiciousActivityMonitor,
    Thermostat,
    Vault,
    VaultAccessLevel,
    format_event,
    money_string,
    parse_access_level,
    parse_schedule,
    schedule_record,
)
from .core import Facility, FacilityStateError

# Increment when the JSON snapshot shape changes incompatibly; loaders reject higher versions.
FACILITY_RECORD_VERSION = 1

def ensure_facility_record_version_supported(record: dict[str, Any]) -> None:
    raw = record.get("schema_version", 1)
    try:
        version = int(raw)
    except (TypeError, ValueError) as exc:
        raise FacilityStateError(f"Invalid facility record schema_version: {raw!r}.") from exc
    if version < 1:
        raise FacilityStateError(f"Invalid facility record schema_version: {version}.")
    if version > FACILITY_RECORD_VERSION:
        raise FacilityStateError(
            f"Facility state schema_version {version} is not supported by this build "
            f"(maximum {FACILITY_RECORD_VERSION}). Upgrade vaultos-facility or re-export state."
        )

def write_facility_json(facility: Facility, path: str | Path) -> Path:
    destination = Path(path)
    destination.write_text(json.dumps(facility_to_record(facility), indent=2) + "\n", encoding="utf-8")
    return destination

def read_facility_json(path: str | Path, *, facility_cls: type[Facility] | None = None) -> Facility:
    cls = facility_cls or Facility
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return facility_from_record(payload, facility_cls=cls)

def facility_to_record(facility: Facility) -> dict[str, Any]:
    return {
        "schema_version": FACILITY_RECORD_VERSION,
        "name": facility.name,
        "device_locations": dict(sorted(facility.device_locations.items())),
        "person_keycards": dict(sorted(facility._linked_cards().items())),
        "devices": device_panel_record(facility),
        "access": access_record(facility),
        "personnel": personnel_record(facility),
        "vault": vault_record(facility),
        "events": events_record(facility),
        "invites": facility.invite_manager.to_record(),
    }

def facility_from_record(record: dict[str, Any], *, facility_cls: type[Facility]) -> Facility:
    ensure_facility_record_version_supported(record)
    event_bus, alert_manager, event_log = events_stack_from_record(record["events"])
    return facility_cls(
        name=record["name"],
        device_panel=device_panel_from_record(record["devices"]),
        access=access_from_record(record["access"]),
        personnel=personnel_from_record(record["personnel"]),
        vault=vault_from_record(record["vault"]),
        event_bus=event_bus,
        alert_manager=alert_manager,
        invite_manager=InviteManager.from_record(record["invites"]),
        event_log=event_log,
        person_keycards=record.get("person_keycards", {}),
        device_locations=record.get("device_locations", {}),
    )

