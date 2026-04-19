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

def access_record(facility: Facility) -> dict[str, Any]:
    cards = []
    for card in facility.access.registry.all_cards():
        cards.append(
            {
                "card_id": card.card_id,
                "owner_name": card.owner_name,
                "access_level": card.access_level.name,
                "issue_date": card.issue_date.isoformat(),
                "expiry_date": card.expiry_date.isoformat(),
                "active": card.active,
                "revoked": card.revoked,
                "revocation_reason": card.revocation_reason,
                "revoked_at": card.revoked_at.isoformat() if card.revoked_at else None,
            }
        )
    gates = [
        {
            "name": gate.name,
            "location": gate.location,
            "required_access_level": gate.required_access_level.name,
            "time_window": schedule_record(gate.time_window),
        }
        for gate in facility.access.list_gates()
    ]
    return {
        "cards": cards,
        "gates": gates,
        "log_entries": [log_entry_record(entry) for entry in facility.access.log.entries()],
        "log_alerts": [security_alert_record(alert) for alert in facility.access.log.alerts()],
        "monitor": {
            "threshold": facility.access.monitor.threshold,
            "window_seconds": int(facility.access.monitor.window.total_seconds()),
            "flagged_cards": [
                security_alert_record(alert) for alert in facility.access.flagged_cards()
            ],
        },
    }

def access_from_record(record: dict[str, Any]) -> AccessController:
    card_numbers = [
        int(item["card_id"].split("-")[-1])
        for item in record["cards"]
        if item["card_id"].startswith("KC-")
    ]
    registry = CardRegistry(starting_number=(max(card_numbers) + 1) if card_numbers else 1)
    for item in record["cards"]:
        card = Keycard(
            card_id=item["card_id"],
            owner_name=item["owner_name"],
            access_level=parse_access_level(item["access_level"]),
            issue_date=date.fromisoformat(item["issue_date"]),
            expiry_date=date.fromisoformat(item["expiry_date"]),
        )
        if item["revoked"]:
            card.revoke(
                item["revocation_reason"] or "No reason recorded.",
                revoked_at=(
                    datetime.fromisoformat(item["revoked_at"])
                    if item["revoked_at"]
                    else datetime.now()
                ),
            )
        elif not item["active"]:
            card.deactivate()
        registry.ingest_restored_keycard(card)

    gates = [
        AccessGate(
            name=item["name"],
            location=item["location"],
            required_access_level=parse_access_level(item["required_access_level"]),
            time_window=parse_schedule(item["time_window"]),
        )
        for item in record["gates"]
    ]
    access_log = AccessLog()
    access_log.replace_stored_entries(
        [log_entry_from_record(item) for item in record["log_entries"]],
        [security_alert_from_record(item) for item in record["log_alerts"]],
    )
    monitor = SuspiciousActivityMonitor(
        threshold=record["monitor"]["threshold"],
        window=timedelta(seconds=record["monitor"]["window_seconds"]),
    )
    flagged = {
        alert.keycard_id: alert
        for alert in (security_alert_from_record(item) for item in record["monitor"]["flagged_cards"])
    }
    monitor.replace_flagged_cards_for_restore(flagged)
    return AccessController(registry=registry, gates=gates, access_log=access_log, monitor=monitor)

def personnel_record(facility: Facility) -> dict[str, Any]:
    return {"people": [person_record(person) for person in facility.personnel.iter_people_sorted_by_id()]}

def personnel_from_record(record: dict[str, Any]) -> PersonnelRegistry:
    registry = PersonnelRegistry()
    onsite_records: list[dict[str, Any]] = []
    for item in record["people"]:
        person = person_from_record(item)
        registry.register(person)
        if item["on_site"]:
            onsite_records.append(item)
    for item in onsite_records:
        assert item["checked_in_at"] is not None
        registry.restore_onsite_snapshot(
            item["unique_id"],
            checked_in_at=datetime.fromisoformat(item["checked_in_at"]),
            location=item["location"],
        )
    return registry

def device_panel_record(facility: Facility) -> dict[str, Any]:
    return {"devices": [device_record(device) for device in facility.device_panel.devices]}


def device_panel_from_record(record: dict[str, Any]) -> Any:
    from panel import DevicePanel

    panel = DevicePanel()
    for item in record["devices"]:
        panel.add_device(device_from_record(item))
    return panel

def vault_record(facility: Facility) -> dict[str, Any]:
    items = []
    for item in facility.vault.iter_items_sorted_by_id():
        items.append(
            {
                "item_id": item.item_id,
                "name": item.name,
                "category": item.category,
                "monetary_value": money_string(item.monetary_value),
                "status": item.status.value,
                "condition": item.condition.value,
                "current_holder": item.current_holder,
                "custody_chain": [custody_record(entry) for entry in item.custody_chain],
            }
        )
    return {"sequence": facility.vault.persisted_issue_sequence, "items": items}

def vault_record(facility: Facility) -> dict[str, Any]:
    items = []
    for item in facility.vault.iter_items_sorted_by_id():
        items.append(
            {
                "item_id": item.item_id,
                "name": item.name,
                "category": item.category,
                "monetary_value": money_string(item.monetary_value),
                "status": item.status.value,
                "condition": item.condition.value,
                "current_holder": item.current_holder,
                "custody_chain": [custody_record(entry) for entry in item.custody_chain],
            }
        )
    return {"sequence": facility.vault.persisted_issue_sequence, "items": items}

def vault_from_record(record: dict[str, Any]) -> Vault:
    vault = Vault()
    items: dict[str, Item] = {}
    for item_record in record["items"]:
        item = Item(
            item_id=item_record["item_id"],
            name=item_record["name"],
            category=item_record["category"],
            monetary_value=Decimal(item_record["monetary_value"]),
            status=ItemStatus.parse(item_record["status"]),
            condition=ItemCondition.parse(item_record["condition"]),
            current_holder=item_record["current_holder"],
        )
        item.apply_restored_custody_chain([custody_from_record(entry) for entry in item_record["custody_chain"]])
        items[item.item_id] = item
    vault.apply_restored_inventory(sequence=record["sequence"], items=items)
    return vault

def events_record(facility: Facility) -> dict[str, Any]:
    return {
        "max_history": facility.event_bus.max_history,
        "dedup_threshold": facility.event_bus.dedup_threshold,
        "dedup_window_seconds": int(facility.event_bus.dedup_window.total_seconds()),
        "history": [event_record(event) for event in facility.event_bus.history],
        "alerts": [alert_record(alert) for alert in facility.alert_manager.all_alerts()],
    }

def events_stack_from_record(record: dict[str, Any]) -> tuple[EventBus, AlertManager, LogHandler]:
    alert_manager = AlertManager()
    restored_alert_map = {alert.alert_id: alert for alert in (_alert_from_record(item) for item in record["alerts"])}
    alert_manager.replace_alerts_for_restore(restored_alert_map)

    event_bus = EventBus(
        max_history=record["max_history"],
        dedup_threshold=record["dedup_threshold"],
        dedup_window=timedelta(seconds=record["dedup_window_seconds"]),
    )
    event_log = LogHandler()
    event_bus.subscribe(event_log, name="facility-log")
    event_bus.subscribe(AlertHandler(alert_manager), name="facility-alerting")
    restored_events = [event_from_record(item) for item in record["history"]]
    event_bus.restore_history_snapshot(restored_events)
    event_log.replace_captured_events(list(restored_events), [format_event(event) for event in restored_events])
    return event_bus, alert_manager, event_log


def event_record(event: Event) -> dict[str, str]:
    return {
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity.name,
        "message": event.message,
        "timestamp": event.timestamp.isoformat(),
        "event_id": event.event_id,
    }

def event_from_record(record: dict[str, str]) -> Event:
    return Event(
        source=record["source"],
        event_type=record["event_type"],
        severity=record["severity"],
        message=record["message"],
        timestamp=datetime.fromisoformat(record["timestamp"]),
        event_id=record["event_id"],
    )

def alert_record(alert: Alert) -> dict[str, Any]:
    return {
        "event": event_record(alert.event),
        "state": alert.state.value,
        "acknowledged_by": alert.acknowledged_by,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolution_notes": alert.resolution_notes,
    }

def _alert_from_record(record: dict[str, Any]) -> Alert:
    alert = Alert(event=event_from_record(record["event"]))
    alert.state = AlertState(record["state"])
    alert.acknowledged_by = record["acknowledged_by"]
    alert.acknowledged_at = (
        datetime.fromisoformat(record["acknowledged_at"]) if record["acknowledged_at"] else None
    )
    alert.resolution_notes = record["resolution_notes"]
    return alert

def log_entry_record(entry: AccessLogEntry) -> dict[str, Any]:
    return {
        "timestamp": entry.timestamp.isoformat(),
        "keycard_id": entry.keycard_id,
        "gate_name": entry.gate_name,
        "granted": entry.granted,
        "reason": entry.reason,
    }

def log_entry_from_record(record: dict[str, Any]) -> AccessLogEntry:
    return AccessLogEntry(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        keycard_id=record["keycard_id"],
        gate_name=record["gate_name"],
        granted=record["granted"],
        reason=record["reason"],
    )

def security_alert_record(alert: SecurityAlert) -> dict[str, Any]:
    return {
        "timestamp": alert.timestamp.isoformat(),
        "keycard_id": alert.keycard_id,
        "denied_attempts": alert.denied_attempts,
        "window_minutes": alert.window_minutes,
        "message": alert.message,
    }

def security_alert_from_record(record: dict[str, Any]) -> SecurityAlert:
    return SecurityAlert(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        keycard_id=record["keycard_id"],
        denied_attempts=record["denied_attempts"],
        window_minutes=record["window_minutes"],
        message=record["message"],
    )

def person_record(person: Person) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "type": person.person_type,
        "unique_id": person.unique_id,
        "name": person.name,
        "contact_info": person.contact_info,
        "on_site": person.on_site,
        "checked_in_at": person.checked_in_at.isoformat() if person.checked_in_at else None,
        "location": person.location,
    }
    if isinstance(person, Employee):
        rec.update(
            {
                "department": person.department,
                "role_title": person.role_title,
                "hire_date": person.hire_date.isoformat(),
                "assigned_keycard_id": person.assigned_keycard_id,
            }
        )
    elif isinstance(person, Contractor):
        rec.update(
            {
                "company_name": person.company_name,
                "contract_start_date": person.contract_start_date.isoformat(),
                "contract_end_date": person.contract_end_date.isoformat(),
                "restricted_areas": list(person.restricted_areas),
            }
        )
    else:
        rec.update(
            {
                "host_employee_id": person.host_employee_id,
                "visit_purpose": person.visit_purpose,
                "expected_duration_minutes": person.expected_duration_minutes,
            }
        )
    return rec

def person_from_record(record: dict[str, Any]) -> Person:
    person_type = record["type"]
    if person_type == "Employee":
        return Employee(
            unique_id=record["unique_id"],
            name=record["name"],
            contact_info=record["contact_info"],
            department=record["department"],
            role_title=record["role_title"],
            hire_date=date.fromisoformat(record["hire_date"]),
            assigned_keycard_id=record["assigned_keycard_id"],
        )
    if person_type == "Contractor":
        return PERSON_TYPES["Contractor"](
            unique_id=record["unique_id"],
            name=record["name"],
            contact_info=record["contact_info"],
            company_name=record["company_name"],
            contract_start_date=date.fromisoformat(record["contract_start_date"]),
            contract_end_date=date.fromisoformat(record["contract_end_date"]),
            restricted_areas=list(record["restricted_areas"]),
        )
    return PERSON_TYPES["Visitor"](
        unique_id=record["unique_id"],
        name=record["name"],
        contact_info=record["contact_info"],
        host_employee_id=record["host_employee_id"],
        visit_purpose=record["visit_purpose"],
        expected_duration_minutes=record["expected_duration_minutes"],
    )

def device_record(device: Device) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "type": device.__class__.__name__,
        "device_id": device.device_id,
        "name": device.name,
        "powered_on": device.powered_on,
        "activity_log": [activity_record(item) for item in device.activity_log],
    }
    if isinstance(device, Camera):
        rec.update(
            {
                "recording": device.recording,
                "recording_started_at": (
                    device._recording_started_at.isoformat() if device._recording_started_at else None
                ),
                "night_mode": device.night_mode,
                "motion_detection": device.motion_detection,
                "recording_history": [recording_session_record(item) for item in device.recording_history],
            }
        )
    elif isinstance(device, Lock):
        rec.update(
            {
                "keycode": device._keycode,
                "locked": device.locked,
                "failed_attempts": device.failed_attempts,
                "lockout_threshold": device._lockout_threshold,
                "lockout_duration_seconds": device._lockout_duration_seconds,
                "auto_lock_seconds": device.auto_lock_seconds,
                "locked_out_until": (
                    device._locked_out_until.isoformat() if device._locked_out_until else None
                ),
                "last_unlocked_at": (
                    device._last_unlocked_at.isoformat() if device._last_unlocked_at else None
                ),
            }
        )
    elif isinstance(device, AlarmSystem):
        rec.update(
            {
                "reset_code": device._reset_code,
                "arm_mode": device.arm_mode,
                "triggered": device.triggered,
                "silent_alarm": device.silent_alarm,
            }
        )
    elif isinstance(device, Thermostat):
        rec.update(
            {
                "target_temperature": device.target_temperature,
                "current_temperature": device.current_temperature,
                "alert_threshold": device.alert_threshold,
                "mode": device.mode,
            }
        )
    return rec

def device_from_record(record: dict[str, Any]) -> Device:
    device_type = record["type"]
    if device_type == "Camera":
        device: Device = Camera(record["device_id"], record["name"])
        device._recording = record["recording"]
        device._recording_started_at = (
            datetime.fromisoformat(record["recording_started_at"])
            if record["recording_started_at"]
            else None
        )
        device._night_mode = record["night_mode"]
        device._motion_detection = record["motion_detection"]
        device._recording_history = [
            recording_session_from_record(item) for item in record["recording_history"]
        ]
    elif device_type == "Lock":
        device = Lock(
            record["device_id"],
            record["name"],
            keycode=record["keycode"],
            lockout_threshold=record["lockout_threshold"],
            lockout_duration_seconds=record["lockout_duration_seconds"],
            auto_lock_seconds=record["auto_lock_seconds"],
        )
        device._locked = record["locked"]
        device._failed_attempts = record["failed_attempts"]
        device._locked_out_until = (
            datetime.fromisoformat(record["locked_out_until"]) if record["locked_out_until"] else None
        )
        device._last_unlocked_at = (
            datetime.fromisoformat(record["last_unlocked_at"]) if record["last_unlocked_at"] else None
        )
    elif device_type == "AlarmSystem":
        device = AlarmSystem(
            record["device_id"],
            record["name"],
            reset_code=record["reset_code"],
        )
        device._arm_mode = record["arm_mode"]
        device._triggered = record["triggered"]
        device._silent_alarm = record["silent_alarm"]
    elif device_type == "Thermostat":
        device = Thermostat(
            record["device_id"],
            record["name"],
            target_temperature=record["target_temperature"],
            current_temperature=record["current_temperature"],
            alert_threshold=record["alert_threshold"],
        )
        device._mode = record["mode"]
    else:
        raise FacilityStateError(f"Unsupported device type {device_type!r}.")

    device._powered_on = record["powered_on"]
    device._activity_log = [activity_from_record(item) for item in record["activity_log"]]
    return device

def activity_record(entry: ActivityEntry) -> dict[str, str]:
    return {"timestamp": entry.timestamp.isoformat(), "message": entry.message}

def activity_from_record(record: dict[str, str]) -> ActivityEntry:
    return ActivityEntry(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        message=record["message"],
    )

def recording_session_record(session: RecordingSession) -> dict[str, str]:
    return {
        "started_at": session.started_at.isoformat(),
        "stopped_at": session.stopped_at.isoformat(),
    }


def recording_session_from_record(record: dict[str, str]) -> RecordingSession:
    return RecordingSession(
        started_at=datetime.fromisoformat(record["started_at"]),
        stopped_at=datetime.fromisoformat(record["stopped_at"]),
    )

def custody_record(entry: CustodyRecord) -> dict[str, str]:
    return {
        "timestamp": entry.timestamp.isoformat(),
        "item_id": entry.item_id,
        "action": entry.action.value,
        "actor_name": entry.actor_name,
        "actor_access_level": entry.actor_access_level.name,
        "notes": entry.notes,
    }
