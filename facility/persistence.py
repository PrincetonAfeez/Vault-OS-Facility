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

