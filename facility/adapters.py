from __future__ import annotations

from datetime import UTC, date, datetime, time
from decimal import Decimal

from .bootstrap import ensure_subproject_paths

ensure_subproject_paths()

from access_control import ( 
    AccessController,
    AccessDecision,
    AccessGate,
    AccessLevel as AccessAccessLevel,
    AccessLog,
    AccessLogEntry,
    CardRegistry,
    GateSchedule,
    Keycard,
    SecurityAlert,
    SuspiciousActivityMonitor,
    build_demo_controller,
    naive_facility_moment,
)
from devices import (  # type: ignore[import-not-found]
    ActivityEntry,
    AlarmSystem,
    Camera,
    Device,
    DeviceAuthorizationError,
    DeviceLockoutError,
    DevicePoweredOffError,
    DeviceStateError,
    Lock,
    RecordingSession,
    Thermostat,
)
from events import (  # type: ignore[import-not-found]
    Alert,
    AlertHandler,
    AlertManager,
    AlertState,
    Event,
    EventBus,
    LogHandler,
    Severity,
    format_event,
)
from invites import (  # type: ignore[import-not-found]
    InviteCode,
    InviteManager,
    InviteNotFoundError,
    InviteState,
    InviteSummary,
    InviteValidationError,
    UsageLogEntry,
    ValidationResult,
)
from panel import DEMO_ALARM_RESET_CODE, DEMO_LOCK_KEYCODE, DevicePanel, seed_demo_panel  # type: ignore[import-not-found]
from personnel import (  # type: ignore[import-not-found]
    CheckInError,
    Contractor,
    Employee,
    Person,
    PersonnelRegistry,
    Visitor,
)
from vault import (  # type: ignore[import-not-found]
    AccessDeniedError,
    AccessLevel as VaultAccessLevel,
    AuditAction,
    CustodyRecord,
    ItemCondition,
    ItemSnapshot,
    ItemStateError,
    ItemStatus,
    ReconciliationReport,
    Vault,
    VaultSummary,
)
from vault.domain import Item, seed_demo_vault

ACCESS_TO_VAULT_LEVEL: dict[AccessAccessLevel, VaultAccessLevel] = {
    AccessAccessLevel.VISITOR: VaultAccessLevel.VISITOR,
    AccessAccessLevel.STAFF: VaultAccessLevel.STAFF,
    AccessAccessLevel.MANAGER: VaultAccessLevel.MANAGER,
    AccessAccessLevel.ADMIN: VaultAccessLevel.DIRECTOR,
}

PERSON_TYPES = {
    "Employee": Employee,
    "Visitor": Visitor,
    "Contractor": Contractor,
}

DEVICE_TYPES = {
    "Camera": Camera,
    "Lock": Lock,
    "AlarmSystem": AlarmSystem,
    "Thermostat": Thermostat,
}

def to_utc(moment: datetime | None = None) -> datetime:
    current = moment or datetime.now(UTC)
    if current.tzinfo is None:
        return current.astimezone(UTC)
    return current.astimezone(UTC)

def facility_date(moment: datetime | None = None) -> date:
    current = moment or datetime.now()
    return naive_facility_moment(current).date()

def parse_access_level(value: AccessAccessLevel | str | int) -> AccessAccessLevel:
    if isinstance(value, AccessAccessLevel):
        return value
    if isinstance(value, int):
        return AccessAccessLevel(value)
    return AccessAccessLevel.from_string(str(value))

def to_vault_access_level(level: AccessAccessLevel | str | int) -> VaultAccessLevel:
    return ACCESS_TO_VAULT_LEVEL[parse_access_level(level)]

def parse_schedule(record: dict[str, str] | None) -> GateSchedule | None:
    if record is None:
        return None
    return GateSchedule(
        start_time=time.fromisoformat(record["start_time"]),
        end_time=time.fromisoformat(record["end_time"]),
    )

def schedule_record(schedule: GateSchedule | None) -> dict[str, str] | None:
    if schedule is None:
        return None
    return {
        "start_time": schedule.start_time.isoformat(timespec="minutes"),
        "end_time": schedule.end_time.isoformat(timespec="minutes"),
    }

def money_string(value: Decimal) -> str:
    return f"{value:.2f}"
