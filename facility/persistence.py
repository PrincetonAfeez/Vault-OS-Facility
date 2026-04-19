""" Persistence layer for the facility subsystem. """

# Enable postponed evaluation of type annotations to allow for cleaner type hinting.
from __future__ import annotations

# Import standard library for JSON serialization, time handling, math, paths, and typing.
import json
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

# Import all domain models and helpers from the local adapters bridging subsystem.
from .adapters import (
    AccessController,          # Core logic for checking door and gate permissions.
    AccessGate,                # Representation of a physical entry point.
    AccessLog,                 # Storage for historical access attempt records.
    AccessLogEntry,            # A single record of a specific card swipe.
    ActivityEntry,             # A log entry for an individual hardware device action.
    AlarmSystem,               # Security hardware for facility-wide alerting.
    Alert,                     # High-priority system event requiring attention.
    AlertHandler,              # Logic interface for processing system alerts.
    AlertManager,              # Orchestrator for tracking active and resolved alerts.
    AlertState,                # Enum representing lifecycle of an alert (New, Ack, etc).
    AuditAction,               # Enum for vault operations like Deposit or Withdrawal.
    Camera,                    # Surveillance hardware capable of recording.
    CardRegistry,              # Database for issued keycards.
    Contractor,                # Personnel type for external service workers.
    CustodyRecord,             # Audit trail entry for a specific vault item.
    Device,                    # Base class for all physical hardware in the system.
    Employee,                  # Personnel type for internal staff.
    Event,                     # Generic system message structure.
    EventBus,                  # The central message hub for the entire facility.
    Item,                      # A physical object stored within the vault.
    ItemCondition,             # Enum for physical health of a vault item.
    ItemStatus,                # Enum for vault item availability (InVault, Out).
    InviteManager,             # Logic for managing visitor codes and usage.
    Keycard,                   # Digital credential assigned to a person.
    Lock,                      # Physical door hardware capable of locking/unlocking.
    LogHandler,                # Subscriber that captures event bus history.
    PERSON_TYPES,              # Dictionary mapping person type strings to classes.
    Person,                    # Base class for individuals in the registry.
    PersonnelRegistry,         # Central database of everyone in the facility.
    RecordingSession,          # Metadata for a specific camera video stream.
    SecurityAlert,             # Alert specific to the access control subsystem.
    SuspiciousActivityMonitor, # Logic to detect repeated failed access attempts.
    Thermostat,                # Environmental control hardware.
    Vault,                     # High-security storage controller.
    VaultAccessLevel,          # Permissions specific to the vault subsystem.
    format_event,              # Utility to turn events into human-readable text.
    money_string,              # Utility to format decimals into currency strings.
    parse_access_level,        # Helper to convert strings/ints to access enums.
    parse_schedule,            # Helper to build time windows from records.
    schedule_record,           # Helper to turn schedules into serializable dicts.
)
# Import core facility class and custom persistence error.
from .core import Facility, FacilityStateError

# Define the current version of the data format to ensure backward compatibility.
FACILITY_RECORD_VERSION = 1

# Validation logic to ensure a loaded JSON file is compatible with this version of the software.
def ensure_facility_record_version_supported(record: dict[str, Any]) -> None:
    # Default to version 1 if the field is missing from the dictionary.
    raw = record.get("schema_version", 1)
    try:
        version = int(raw)
    except (TypeError, ValueError) as exc:
        # Raise error if the version field is present but not a valid number.
        raise FacilityStateError(f"Invalid facility record schema_version: {raw!r}.") from exc
    # Logic to prevent loading data from negative or zero versions.
    if version < 1:
        raise FacilityStateError(f"Invalid facility record schema_version: {version}.")
    # Check if the file version is newer than what this code can currently handle.
    if version > FACILITY_RECORD_VERSION:
        raise FacilityStateError(
            f"Facility state schema_version {version} is not supported by this build "
            f"(maximum {FACILITY_RECORD_VERSION}). Upgrade vaultos-facility or re-export state."
        )

# Helper function to serialize the Facility object and save it to a physical file.
def write_facility_json(facility: Facility, path: str | Path) -> Path:
    # Ensure the path is a Path object.
    destination = Path(path)
    # Convert facility to a dictionary, then to a JSON string with indentation, and write to disk.
    destination.write_text(json.dumps(facility_to_record(facility), indent=2) + "\n", encoding="utf-8")
    return destination

# Helper function to read a file from disk and reconstruct the Facility object.
def read_facility_json(path: str | Path, *, facility_cls: type[Facility] | None = None) -> Facility:
    # Use the provided class or default to the standard Facility class.
    cls = facility_cls or Facility
    # Load the raw text file and parse it into a Python dictionary.
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    # Pass the dictionary to the reconstruction logic.
    return facility_from_record(payload, facility_cls=cls)

# Primary serialization logic: converts a live Facility object into a flat dictionary.
def facility_to_record(facility: Facility) -> dict[str, Any]:
    return {
        "schema_version": FACILITY_RECORD_VERSION, # Current format version.
        "name": facility.name,                     # Display name of the facility.
        "device_locations": dict(sorted(facility.device_locations.items())), # Map of device IDs to room names.
        "person_keycards": dict(sorted(facility._linked_cards().items())),   # Link between individuals and card IDs.
        "devices": device_panel_record(facility),  # Serialized state of all hardware.
        "access": access_record(facility),        # Serialized state of gates and keycards.
        "personnel": personnel_record(facility),  # Serialized state of all registered people.
        "vault": vault_record(facility),          # Serialized state of vault inventory and custody.
        "events": events_record(facility),        # Serialized history and alert states.
        "invites": facility.invite_manager.to_record(), # Serialized visitor invite codes.
    }

# Primary reconstruction logic: creates a live Facility object from a dictionary.
def facility_from_record(record: dict[str, Any], *, facility_cls: type[Facility]) -> Facility:
    # Validate the version before attempting to parse.
    ensure_facility_record_version_supported(record)
    # Reconstruct the message and alert infrastructure.
    event_bus, alert_manager, event_log = events_stack_from_record(record["events"])
    # Instantiate the new Facility with all reconstituted components.
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

# Logic to serialize the Access Control subsystem.
def access_record(facility: Facility) -> dict[str, Any]:
    cards = []
    # Loop through all issued cards and extract metadata and security status.
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
    # Loop through all facility gates and extract their physical location and security requirements.
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
        "log_entries": [log_entry_record(entry) for entry in facility.access.log.entries()], # Past swipes.
        "log_alerts": [security_alert_record(alert) for alert in facility.access.log.alerts()], # Security events.
        "monitor": {
            "threshold": facility.access.monitor.threshold, # Sensitivity settings.
            "window_seconds": int(facility.access.monitor.window.total_seconds()),
            "flagged_cards": [
                security_alert_record(alert) for alert in facility.access.flagged_cards()
            ],
        },
    }

# Logic to rebuild the Access Control subsystem from data.
def access_from_record(record: dict[str, Any]) -> AccessController:
    # Identify the highest card ID to ensure the card registry continues its auto-increment correctly.
    card_numbers = [
        int(item["card_id"].split("-")[-1])
        for item in record["cards"]
        if item["card_id"].startswith("KC-")
    ]
    registry = CardRegistry(starting_number=(max(card_numbers) + 1) if card_numbers else 1)
    # Rebuild each individual Keycard object.
    for item in record["cards"]:
        card = Keycard(
            card_id=item["card_id"],
            owner_name=item["owner_name"],
            access_level=parse_access_level(item["access_level"]),
            issue_date=date.fromisoformat(item["issue_date"]),
            expiry_date=date.fromisoformat(item["expiry_date"]),
        )
        # Apply revocation or deactivation states if necessary.
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
        # Insert the restored card into the registry without generating a new ID.
        registry.ingest_restored_keycard(card)

    # Reconstitute the facility's physical gates.
    gates = [
        AccessGate(
            name=item["name"],
            location=item["location"],
            required_access_level=parse_access_level(item["required_access_level"]),
            time_window=parse_schedule(item["time_window"]),
        )
        for item in record["gates"]
    ]
    # Reconstitute the historical logs and alerts.
    access_log = AccessLog()
    access_log.replace_stored_entries(
        [log_entry_from_record(item) for item in record["log_entries"]],
        [security_alert_from_record(item) for item in record["log_alerts"]],
    )
    # Reconstitute the monitoring logic (thresholds and flagged cards).
    monitor = SuspiciousActivityMonitor(
        threshold=record["monitor"]["threshold"],
        window=timedelta(seconds=record["monitor"]["window_seconds"]),
    )
    flagged = {
        alert.keycard_id: alert
        for alert in (security_alert_from_record(item) for item in record["monitor"]["flagged_cards"])
    }
    # Manually inject restored flagged cards into the monitor.
    monitor.replace_flagged_cards_for_restore(flagged)
    # Assemble and return the full controller.
    return AccessController(registry=registry, gates=gates, access_log=access_log, monitor=monitor)

# Serialize the personnel registry.
def personnel_record(facility: Facility) -> dict[str, Any]:
    # Convert all registered people into serializable records.
    return {"people": [person_record(person) for person in facility.personnel.iter_people_sorted_by_id()]}

# Restore the personnel registry.
def personnel_from_record(record: dict[str, Any]) -> PersonnelRegistry:
    registry = PersonnelRegistry()
    onsite_records: list[dict[str, Any]] = []
    # Loop through and register every person found in the record.
    for item in record["people"]:
        person = person_from_record(item)
        registry.register(person)
        # Keep track of people who were marked as currently on-site for a second pass.
        if item["on_site"]:
            onsite_records.append(item)
    # Manually restore the on-site status and location for relevant individuals.
    for item in onsite_records:
        assert item["checked_in_at"] is not None
        registry.restore_onsite_snapshot(
            item["unique_id"],
            checked_in_at=datetime.fromisoformat(item["checked_in_at"]),
            location=item["location"],
        )
    return registry

# Convert the hardware device panel into a serializable dictionary.
def device_panel_record(facility: Facility) -> dict[str, Any]:
    return {"devices": [device_record(device) for device in facility.device_panel.devices]}

# Reconstruct the hardware device panel from data.
def device_panel_from_record(record: dict[str, Any]) -> Any:
    # Deferred import to avoid circular dependency with the panel module.
    from panel import DevicePanel

    panel = DevicePanel()
    # Rebuild each device and add it back to the panel registry.
    for item in record["devices"]:
        panel.add_device(device_from_record(item))
    return panel

# Serialize the vault inventory and its audit history.
def vault_record(facility: Facility) -> dict[str, Any]:
    items = []
    # Iterate through every item currently or previously tracked by the vault.
    for item in facility.vault.iter_items_sorted_by_id():
        items.append(
            {
                "item_id": item.item_id,
                "name": item.name,
                "category": item.category,
                "monetary_value": money_string(item.monetary_value), # High precision to string.
                "status": item.status.value,
                "condition": item.condition.value,
                "current_holder": item.current_holder,
                # Serialize the chain of custody for this specific item.
                "custody_chain": [custody_record(entry) for entry in item.custody_chain],
            }
        )
    # Include the auto-increment sequence number to prevent ID collisions upon resume.
    return {"sequence": facility.vault.persisted_issue_sequence, "items": items}

# Restore the vault subsystem.
def vault_from_record(record: dict[str, Any]) -> Vault:
    vault = Vault()
    items: dict[str, Item] = {}
    # Reconstitute individual item objects.
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
        # Apply the full audit trail to the item.
        item.apply_restored_custody_chain([custody_from_record(entry) for entry in item_record["custody_chain"]])
        items[item.item_id] = item
    # Inject the entire inventory and ID sequence into the vault.
    vault.apply_restored_inventory(sequence=record["sequence"], items=items)
    return vault

# Serialize the central event bus and alert system state.
def events_record(facility: Facility) -> dict[str, Any]:
    return {
        "max_history": facility.event_bus.max_history,           # Limit for in-memory history.
        "dedup_threshold": facility.event_bus.dedup_threshold,   # Spam protection setting.
        "dedup_window_seconds": int(facility.event_bus.dedup_window.total_seconds()),
        "history": [event_record(event) for event in facility.event_bus.history], # All past events.
        "alerts": [alert_record(alert) for alert in facility.alert_manager.all_alerts()], # Active/Acked alerts.
    }

# Rebuild the complex messaging infrastructure and wire the components together.
def events_stack_from_record(record: dict[str, Any]) -> tuple[EventBus, AlertManager, LogHandler]:
    # 1. Setup the Alert Manager and restore all previous alert states.
    alert_manager = AlertManager()
    restored_alert_map = {alert.alert_id: alert for alert in (_alert_from_record(item) for item in record["alerts"])}
    alert_manager.replace_alerts_for_restore(restored_alert_map)

    # 2. Setup the Event Bus with previous settings.
    event_bus = EventBus(
        max_history=record["max_history"],
        dedup_threshold=record["dedup_threshold"],
        dedup_window=timedelta(seconds=record["dedup_window_seconds"]),
    )
    # 3. Create a Log Handler to capture future events.
    event_log = LogHandler()
    # 4. Subscribe handlers to the bus.
    event_bus.subscribe(event_log, name="facility-log")
    event_bus.subscribe(AlertHandler(alert_manager), name="facility-alerting")
    # 5. Restore the actual event history objects.
    restored_events = [event_from_record(item) for item in record["history"]]
    event_bus.restore_history_snapshot(restored_events)
    # 6. Ensure the log handler and the bus history are in sync.
    event_log.replace_captured_events(list(restored_events), [format_event(event) for event in restored_events])
    return event_bus, alert_manager, event_log

# Serialize an individual Event object.
def event_record(event: Event) -> dict[str, str]:
    return {
        "source": event.source,           # Which module sent this.
        "event_type": event.event_type,   # The specific action/occurrence.
        "severity": event.severity.name,  # INFO, WARNING, CRITICAL, etc.
        "message": event.message,         # Human-readable details.
        "timestamp": event.timestamp.isoformat(),
        "event_id": event.event_id,       # Unique message identifier.
    }

# Restore an individual Event object.
def event_from_record(record: dict[str, str]) -> Event:
    return Event(
        source=record["source"],
        event_type=record["event_type"],
        severity=record["severity"],
        message=record["message"],
        timestamp=datetime.fromisoformat(record["timestamp"]),
        event_id=record["event_id"],
    )

# Serialize a high-level Alert.
def alert_record(alert: Alert) -> dict[str, Any]:
    return {
        "event": event_record(alert.event), # The underlying event that triggered it.
        "state": alert.state.value,         # NEW, ACKNOWLEDGED, RESOLVED.
        "acknowledged_by": alert.acknowledged_by,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolution_notes": alert.resolution_notes,
    }

# Internal helper to restore an Alert object.
def _alert_from_record(record: dict[str, Any]) -> Alert:
    # Reconstruct from the serialized underlying event.
    alert = Alert(event=event_from_record(record["event"]))
    # Manually overwrite the fields that changed after the initial alert trigger.
    alert.state = AlertState(record["state"])
    alert.acknowledged_by = record["acknowledged_by"]
    alert.acknowledged_at = (
        datetime.fromisoformat(record["acknowledged_at"]) if record["acknowledged_at"] else None
    )
    alert.resolution_notes = record["resolution_notes"]
    return alert

# Serialize a simple access control log entry.
def log_entry_record(entry: AccessLogEntry) -> dict[str, Any]:
    return {
        "timestamp": entry.timestamp.isoformat(),
        "keycard_id": entry.keycard_id,
        "gate_name": entry.gate_name,
        "granted": entry.granted, # Boolean result of the attempt.
        "reason": entry.reason,   # Why it was granted or denied.
    }

# Restore an access control log entry.
def log_entry_from_record(record: dict[str, Any]) -> AccessLogEntry:
    return AccessLogEntry(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        keycard_id=record["keycard_id"],
        gate_name=record["gate_name"],
        granted=record["granted"],
        reason=record["reason"],
    )

# Serialize a SecurityAlert (used for monitor-flagged activity).
def security_alert_record(alert: SecurityAlert) -> dict[str, Any]:
    return {
        "timestamp": alert.timestamp.isoformat(),
        "keycard_id": alert.keycard_id,
        "denied_attempts": alert.denied_attempts, # Number of failures in window.
        "window_minutes": alert.window_minutes,
        "message": alert.message,
    }

# Restore a SecurityAlert object.
def security_alert_from_record(record: dict[str, Any]) -> SecurityAlert:
    return SecurityAlert(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        keycard_id=record["keycard_id"],
        denied_attempts=record["denied_attempts"],
        window_minutes=record["window_minutes"],
        message=record["message"],
    )

# Logic to serialize a person, branching based on their specific subclass.
def person_record(person: Person) -> dict[str, Any]:
    # Shared base fields for all individuals.
    rec: dict[str, Any] = {
        "type": person.person_type, # Employee, Contractor, or Visitor.
        "unique_id": person.unique_id,
        "name": person.name,
        "contact_info": person.contact_info,
        "on_site": person.on_site,
        "checked_in_at": person.checked_in_at.isoformat() if person.checked_in_at else None,
        "location": person.location,
    }
    # Add employee-specific fields.
    if isinstance(person, Employee):
        rec.update(
            {
                "department": person.department,
                "role_title": person.role_title,
                "hire_date": person.hire_date.isoformat(),
                "assigned_keycard_id": person.assigned_keycard_id,
            }
        )
    # Add contractor-specific fields.
    elif isinstance(person, Contractor):
        rec.update(
            {
                "company_name": person.company_name,
                "contract_start_date": person.contract_start_date.isoformat(),
                "contract_end_date": person.contract_end_date.isoformat(),
                "restricted_areas": list(person.restricted_areas),
            }
        )
    # Default to visitor fields.
    else:
        rec.update(
            {
                "host_employee_id": person.host_employee_id,
                "visit_purpose": person.visit_purpose,
                "expected_duration_minutes": person.expected_duration_minutes,
            }
        )
    return rec

# Logic to restore the correct Person subclass from data.
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
    # Fallback to Visitor.
    return PERSON_TYPES["Visitor"](
        unique_id=record["unique_id"],
        name=record["name"],
        contact_info=record["contact_info"],
        host_employee_id=record["host_employee_id"],
        visit_purpose=record["visit_purpose"],
        expected_duration_minutes=record["expected_duration_minutes"],
    )

# Serialize a hardware device, branching based on class properties.
def device_record(device: Device) -> dict[str, Any]:
    # Base fields common to all hardware devices.
    rec: dict[str, Any] = {
        "type": device.__class__.__name__,
        "device_id": device.device_id,
        "name": device.name,
        "powered_on": device.powered_on,
        "activity_log": [activity_record(item) for item in device.activity_log],
    }
    # Camera-specific serialization.
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
    # Lock-specific serialization.
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
    # Alarm system-specific serialization.
    elif isinstance(device, AlarmSystem):
        rec.update(
            {
                "reset_code": device._reset_code,
                "arm_mode": device.arm_mode,
                "triggered": device.triggered,
                "silent_alarm": device.silent_alarm,
            }
        )
    # Thermostat-specific serialization.
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

# Logic to restore the correct Device subclass and its internal private state.
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
        # Prevent loading if the device type is not recognized.
        raise FacilityStateError(f"Unsupported device type {device_type!r}.")

    # Restore common shared state across all devices.
    device._powered_on = record["powered_on"]
    device._activity_log = [activity_from_record(item) for item in record["activity_log"]]
    return device

# Utility to serialize a single activity log entry.
def activity_record(entry: ActivityEntry) -> dict[str, str]:
    return {"timestamp": entry.timestamp.isoformat(), "message": entry.message}

# Utility to restore a single activity log entry.
def activity_from_record(record: dict[str, str]) -> ActivityEntry:
    return ActivityEntry(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        message=record["message"],
    )

# Utility to serialize a camera recording window.
def recording_session_record(session: RecordingSession) -> dict[str, str]:
    return {
        "started_at": session.started_at.isoformat(),
        "stopped_at": session.stopped_at.isoformat(),
    }

# Utility to restore a camera recording window.
def recording_session_from_record(record: dict[str, str]) -> RecordingSession:
    return RecordingSession(
        started_at=datetime.fromisoformat(record["started_at"]),
        stopped_at=datetime.fromisoformat(record["stopped_at"]),
    )

# Utility to serialize a vault item custody event.
def custody_record(entry: CustodyRecord) -> dict[str, str]:
    return {
        "timestamp": entry.timestamp.isoformat(),
        "item_id": entry.item_id,
        "action": entry.action.value, # Enum value (checkout/checkin).
        "actor_name": entry.actor_name,
        "actor_access_level": entry.actor_access_level.name,
        "notes": entry.notes,
    }

# Utility to restore a vault item custody event.
def custody_from_record(record: dict[str, str]) -> CustodyRecord:
    return CustodyRecord(
        timestamp=datetime.fromisoformat(record["timestamp"]),
        item_id=record["item_id"],
        action=AuditAction.parse(record["action"]),
        actor_name=record["actor_name"],
        actor_access_level=VaultAccessLevel.parse(record["actor_access_level"]),
        notes=record["notes"],
    )