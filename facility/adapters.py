"""facility.adapters - Imports and small helpers bridging subsystems"""

# Enable postponed evaluation of type annotations for forward references and cleaner typing.
from __future__ import annotations

# Import standard library time, date, and timezone utilities for handling facility scheduling.
from datetime import UTC, date, datetime, time
# Import Decimal for high-precision financial calculations, specifically for vault item values.
from decimal import Decimal

# Import the utility function responsible for configuring the system path to find sibling modules.
from .bootstrap import ensure_subproject_paths

# Execute the path configuration to allow subsequent imports from the separate Vault OS sub-projects.
ensure_subproject_paths()

# Import the core logic, domain models, and logging structures from the Access Control sub-project.
from access_control import ( 
    AccessController,               # Orchestrates entry requests and permissions.
    AccessDecision,                 # Represents the result (grant/deny) of an access attempt.
    AccessGate,                     # Represents a physical or logical entry point in the facility.
    AccessLevel as AccessAccessLevel, # Enum defining security clearances (aliased to avoid conflicts).
    AccessLog,                      # Collection of all entry/exit events.
    AccessLogEntry,                 # A single record of a specific person's access attempt.
    CardRegistry,                   # Database mapping unique IDs to specific keycards.
    GateSchedule,                   # Defines time windows when a gate is active or locked.
    Keycard,                        # The digital credential held by a person.
    SecurityAlert,                  # Represents a triggered security exception in the access layer.
    SuspiciousActivityMonitor,      # Logic to detect patterns like tailgating or repeated failures.
    build_demo_controller,          # Helper to instantiate a pre-populated access system.
    naive_facility_moment,          # Utility to convert standard time to the facility's local frame.
)
# Import hardware abstraction classes and error definitions from the Devices sub-project.
from devices import (  # type: ignore[import-not-found]
    ActivityEntry,                  # Log entry for a specific device interaction.
    AlarmSystem,                    # Device responsible for facility-wide security states.
    Camera,                         # Surveillance device capable of recording and snapshots.
    Device,                         # The base class for all hardware integrated into the facility.
    DeviceAuthorizationError,       # Raised when a user lacks permission to operate a device.
    DeviceLockoutError,             # Raised when a device is temporarily disabled due to security.
    DevicePoweredOffError,          # Raised when interacting with a device that has no power.
    DeviceStateError,               # Raised when a command is invalid for the current device state.
    Lock,                           # Abstraction for electronic door or container locks.
    RecordingSession,               # Metadata regarding a specific camera video stream.
    Thermostat,                     # Environmental control device for climate management.
)
# Import the messaging and notification infrastructure from the Events sub-project.
from events import (  # type: ignore[import-not-found]
    Alert,                          # High-priority notification requiring attention.
    AlertHandler,                   # Interface for logic that responds to specific alerts.
    AlertManager,                   # Orchestrator for routing and escalating system alerts.
    AlertState,                     # Enum representing if an alert is New, Acknowledged, or Resolved.
    Event,                          # The generic data structure for any system-wide occurrence.
    EventBus,                       # The central hub for publishing and subscribing to events.
    LogHandler,                     # Listener that writes events to a persistent storage medium.
    Severity,                       # Enum for event importance: INFO, WARNING, CRITICAL, etc.
    format_event,                   # Utility to turn event data into a human-readable string.
)
# Import guest management and temporary access logic from the Invites sub-project.
from invites import (  # type: ignore[import-not-found]
    InviteCode,                     # A unique token used by visitors for temporary entry.
    InviteManager,                  # Controller for generating and validating invite codes.
    InviteNotFoundError,            # Raised when an invalid or expired code is presented.
    InviteState,                    # Enum for the lifecycle of an invite (Active, Used, Revoked).
    InviteSummary,                  # A lightweight view of an invite's current status.
    InviteValidationError,          # Raised when a code is technically valid but fails constraints.
    UsageLogEntry,                  # A record of when and where an invite code was used.
    ValidationResult,               # Detailed object containing the outcome of an invite check.
)
# Import control panel abstractions and demo seeding constants.
from panel import DEMO_ALARM_RESET_CODE, DEMO_LOCK_KEYCODE, DevicePanel, seed_demo_panel  # type: ignore[import-not-found]
# Import personnel definitions and registry management from the Personnel sub-project.
from personnel import (  # type: ignore[import-not-found]
    CheckInError,                   # Raised when a person fails to log into the facility registry.
    Contractor,                     # Representation of external service personnel.
    Employee,                       # Representation of internal staff members.
    Person,                         # The base abstract class for any individual in the system.
    PersonnelRegistry,              # Central database of all known individuals and their roles.
    Visitor,                        # Representation of temporary guests.
)
# Import the high-security storage and inventory logic from the Vault sub-project.
from vault import (  # type: ignore[import-not-found]
    AccessDeniedError,               # Raised when vault clearance is insufficient for an action.
    AccessLevel as VaultAccessLevel, # Enum defining clearances specific to vault contents.
    AuditAction,                    # Enum for vault operations like Deposit, Withdraw, or Audit.
    CustodyRecord,                  # Tracking data for who currently possesses a specific item.
    ItemCondition,                  # Enum representing physical state (New, Damaged, etc.).
    ItemSnapshot,                   # A point-in-time record of an item's properties and value.
    ItemStateError,                 # Raised when an operation violates the item's current status.
    ItemStatus,                     # Enum for item availability (InVault, CheckedOut, Lost).
    ReconciliationReport,           # Summary of expected vs. actual vault inventory.
    Vault,                          # The primary controller for managing secure assets.
    VaultSummary,                   # A high-level overview of vault health and asset value.
)
# Import the domain-specific Item model and the function to populate a demo vault.
from vault.domain import Item, seed_demo_vault

# Map the generic Facility Access Levels to specific Vault Access Levels to bridge the two modules.
ACCESS_TO_VAULT_LEVEL: dict[AccessAccessLevel, VaultAccessLevel] = {
    AccessAccessLevel.VISITOR: VaultAccessLevel.VISITOR,
    AccessAccessLevel.STAFF: VaultAccessLevel.STAFF,
    AccessAccessLevel.MANAGER: VaultAccessLevel.MANAGER,
    AccessAccessLevel.ADMIN: VaultAccessLevel.DIRECTOR, # Admin maps to highest level: Director.
}

# Registry dictionary to allow dynamic lookup of personnel classes by their string names.
PERSON_TYPES = {
    "Employee": Employee,
    "Visitor": Visitor,
    "Contractor": Contractor,
}

# Registry dictionary to allow dynamic lookup of device classes by their string names.
DEVICE_TYPES = {
    "Camera": Camera,
    "Lock": Lock,
    "AlarmSystem": AlarmSystem,
    "Thermostat": Thermostat,
}

# Utility to ensure a datetime object is timezone-aware and set to Coordinated Universal Time.
def to_utc(moment: datetime | None = None) -> datetime:
    # Use provided moment or current system time in UTC if none provided.
    current = moment or datetime.now(UTC)
    # If the object is naive (no timezone), attach the UTC timezone.
    if current.tzinfo is None:
        return current.astimezone(UTC)
    # If it has a timezone, convert the existing time to the UTC equivalent.
    return current.astimezone(UTC)

# Utility to get the current facility-specific date, adjusted for local facility offsets.
def facility_date(moment: datetime | None = None) -> date:
    # Use provided moment or local system time.
    current = moment or datetime.now()
    # Convert to facility-time and extract only the date component.
    return naive_facility_moment(current).date()

# Helper to normalize various input types into a valid AccessLevel enumeration.
def parse_access_level(value: AccessAccessLevel | str | int) -> AccessAccessLevel:
    # If it is already an AccessLevel enum, return it as is.
    if isinstance(value, AccessAccessLevel):
        return value
    # If it is an integer, initialize the Enum using the integer value.
    if isinstance(value, int):
        return AccessAccessLevel(value)
    # If it is a string, use the custom from_string parser defined in the AccessLevel class.
    return AccessAccessLevel.from_string(str(value))

# Bridge function to convert a general facility access level into the specific vault level.
def to_vault_access_level(level: AccessAccessLevel | str | int) -> VaultAccessLevel:
    # Parse the input to an AccessLevel enum and look up the corresponding Vault level in the map.
    return ACCESS_TO_VAULT_LEVEL[parse_access_level(level)]

# Helper to reconstruct a GateSchedule object from a dictionary (typically from a JSON store).
def parse_schedule(record: dict[str, str] | None) -> GateSchedule | None:
    # Return None if no schedule record exists.
    if record is None:
        return None
    # Initialize a GateSchedule using ISO-formatted time strings for start and end points.
    return GateSchedule(
        start_time=time.fromisoformat(record["start_time"]),
        end_time=time.fromisoformat(record["end_time"]),
    )

# Helper to convert a GateSchedule object into a serializable dictionary format.
def schedule_record(schedule: GateSchedule | None) -> dict[str, str] | None:
    # Return None if the schedule object is null.
    if schedule is None:
        return None
    # Store times as ISO strings limited to minute precision for cleaner JSON.
    return {
        "start_time": schedule.start_time.isoformat(timespec="minutes"),
        "end_time": schedule.end_time.isoformat(timespec="minutes"),
    }

# Formatter to convert Decimal values into a standard currency string with two decimal places.
def money_string(value: Decimal) -> str:
    # Return the value formatted as a string with exactly two digits after the decimal point.
    return f"{value:.2f}"