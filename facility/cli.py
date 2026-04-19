"""facility.cli - Vault OS Facility CLI entry point"""

# Enable postponed evaluation of type annotations for cleaner forward references.
from __future__ import annotations

# Import standard library for CLI parsing, JSON handling, system interactions, and time math.
import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Import specific error classes from adapters to allow the CLI to catch and report domain errors gracefully.
from .adapters import (
    AccessDeniedError,         # Raised when vault or gate clearance fails.
    CheckInError,              # Raised when personnel check-in logic fails.
    DeviceAuthorizationError,  # Raised when hardware commands lack permission.
    DeviceLockoutError,        # Raised when a device is disabled due to security.
    InviteValidationError,     # Raised when an invite code is technically invalid.
    ItemStateError,            # Raised when a vault item is in an invalid state for an action.
)
# Import the main Facility controller and its base error class.
from .core import Facility, FacilityError


# Function to define the structure, commands, and arguments for the Facility Command Line Interface.
def build_parser() -> argparse.ArgumentParser:
    # Initialize the top-level parser with a program name and description.
    parser = argparse.ArgumentParser(prog="facility", description="Vault OS facility integration CLI.")
    # Add global optional flags for loading an existing state or saving the state after execution.
    parser.add_argument("--state", help="Path to an existing facility JSON state file.")
    parser.add_argument("--save", help="Write the resulting facility state to this path after the command.")
    # Create subparsers to handle different "domains" (facility, status, access, etc.).
    subparsers = parser.add_subparsers(dest="domain", required=True)

    # --- Domain: Facility (Meta operations like init/save/load) ---
    facility_parser = subparsers.add_parser("facility", help="Initialize or persist facility state.")
    facility_sub = facility_parser.add_subparsers(dest="facility_action", required=True)
    # Sub-command to create a fresh demo environment.
    facility_sub.add_parser("init", help="Create a seeded demo facility.")
    # Sub-command to load a specific JSON state file and display a summary.
    load_parser = facility_sub.add_parser("load", help="Load and summarize a saved facility state.")
    load_parser.add_argument("path")
    # Sub-command to manually trigger a save to a file.
    save_parser = facility_sub.add_parser("save", help="Save the current facility state.")
    save_parser.add_argument("path")

    # --- Domain: Status (Dashboard view) ---
    status_parser = subparsers.add_parser("status", help="Show a facility dashboard.")
    # Optional flag to control how many recent events are displayed.
    status_parser.add_argument("--recent", type=int, default=5)

    # --- Domain: Access (Gate and Keycard logic) ---
    access_parser = subparsers.add_parser("access", help="Access-control workflows.")
    access_sub = access_parser.add_subparsers(dest="access_action", required=True)
    # Sub-command to simulate swiping a card at a specific gate.
    gate_parser = access_sub.add_parser("gate-check", help="Run a gate access check.")
    gate_parser.add_argument("card_id")
    gate_parser.add_argument("gate_name")
    gate_parser.add_argument("--at", help="ISO timestamp for the check.")

    # --- Domain: Personnel (Employee and Visitor tracking) ---
    personnel_parser = subparsers.add_parser("personnel", help="Personnel workflows.")
    personnel_sub = personnel_parser.add_subparsers(dest="personnel_action", required=True)
    # Sub-command to log a person entering the facility.
    personnel_in = personnel_sub.add_parser("check-in", help="Check a person in.")
    personnel_in.add_argument("person_id")
    personnel_in.add_argument("--location")
    personnel_in.add_argument("--at", help="ISO timestamp for the check-in.")
    # Sub-command to log a person leaving the facility.
    personnel_out = personnel_sub.add_parser("check-out", help="Check a person out.")
    personnel_out.add_argument("person_id")

    # --- Domain: Vault (High-security asset management) ---
    vault_parser = subparsers.add_parser("vault", help="Vault workflows.")
    vault_sub = vault_parser.add_subparsers(dest="vault_action", required=True)
    # Sub-command to remove an item from the vault.
    vault_out = vault_sub.add_parser("checkout", help="Check out an item from the vault.")
    vault_out.add_argument("item_id")
    vault_out.add_argument("requester")
    vault_out.add_argument("--notes", default="")
    # Sub-command to return an item to the vault.
    vault_in = vault_sub.add_parser("checkin", help="Check an item back into the vault.")
    vault_in.add_argument("item_id")
    vault_in.add_argument("requester")
    vault_in.add_argument("--notes", default="")

    # --- Domain: Invites (Guest code management) ---
    invite_parser = subparsers.add_parser("invite", help="Invite workflows.")
    invite_sub = invite_parser.add_subparsers(dest="invite_action", required=True)
    # Sub-command to create a new temporary invite code.
    invite_gen = invite_sub.add_parser("generate", help="Generate an invite code.")
    invite_gen.add_argument("creator_ref")
    invite_gen.add_argument("required_access_level")
    invite_gen.add_argument("--uses", type=int, default=1)
    invite_gen.add_argument("--hours", type=float, default=8.0)
    # Sub-command to check if a code is still valid.
    invite_validate = invite_sub.add_parser("validate", help="Validate an invite code.")
    invite_validate.add_argument("code")
    # Sub-command to use/consume an invite code.
    invite_use = invite_sub.add_parser("use", help="Consume an invite code.")
    invite_use.add_argument("code")

    # --- Domain: Event (Log history) ---
    event_parser = subparsers.add_parser("event", help="Event workflows.")
    event_sub = event_parser.add_subparsers(dest="event_action", required=True)
    # Sub-command to list the raw event bus history.
    history_parser = event_sub.add_parser("history", help="Show recent event history.")
    history_parser.add_argument("--limit", type=int, default=10)

    # --- Domain: Alert (Security exceptions) ---
    alert_parser = subparsers.add_parser("alert", help="Alert workflows.")
    alert_sub = alert_parser.add_subparsers(dest="alert_action", required=True)
    # Sub-command to list all currently unacknowledged or active alerts.
    alert_sub.add_parser("list", help="List active alerts.")

    # --- Simulation: Scripted security breach scenario ---
    subparsers.add_parser("simulate-breach", help="Run the demo breach simulation.")
    return parser

# Main entry point for the CLI application.
def main(argv: list[str] | None = None) -> int:
    # Build the parser and parse the normalized command line arguments.
    parser = build_parser()
    args = parser.parse_args(_normalize_global_options(argv))

    # Define a tuple of known exceptions that should be printed cleanly rather than crashing with a traceback.
    _cli_errors = (
        FacilityError,
        CheckInError,
        KeyError,
        ValueError,
        InviteValidationError,
        ItemStateError,
        AccessDeniedError,
        DeviceAuthorizationError,
        DeviceLockoutError,
        json.JSONDecodeError,
        OSError,
    )
    try:
        # Load or initialize the Facility object based on provided flags.
        facility = _resolve_facility(args)
        # Execute the logic corresponding to the chosen command domain and action.
        exit_code = _dispatch(args, facility)
        # If the user specifically ran 'facility save', the save is already handled; return early.
        if args.domain == "facility" and args.facility_action == "save":
            return exit_code
        # If the --save flag was provided globally, persist the final state of the facility.
        if args.save:
            destination = facility.save(args.save)
            print(f"Saved facility state to {destination}")
        return exit_code
    # Catch business-logic errors and print them to stderr.
    except _cli_errors as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    # Catch any unhandled system-level errors to prevent a silent fail.
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

# Determines how to instantiate the Facility object (new demo, load file, or default demo).
def _resolve_facility(args: argparse.Namespace) -> Facility:
    # If specifically requested to init, return a fresh demo setup.
    if args.domain == "facility" and args.facility_action == "init":
        return Facility.create_demo()
    # If specifically requested to load, use the path provided in the load command.
    if args.domain == "facility" and args.facility_action == "load":
        return Facility.load(args.path)
    # If the global --state flag is present, load from that path.
    if args.state:
        return Facility.load(args.state)
    # Fallback: create a demo facility.
    return Facility.create_demo()

# Routes the parsed CLI arguments to the appropriate handler function based on the domain.
def _dispatch(args: argparse.Namespace, facility: Facility) -> int:
    # Handle top-level facility persistence commands.
    if args.domain == "facility":
        return _handle_facility(args, facility)
    # Handle the dashboard view.
    if args.domain == "status":
        _render_status(facility, recent=args.recent)
        return 0
    # Handle access control / gate check logic.
    if args.domain == "access":
        moment = _parse_datetime(args.at)
        decision = facility.gate_check(args.card_id, args.gate_name, timestamp=moment)
        outcome = "GRANTED" if decision.granted else "DENIED"
        print(f"{outcome}: {decision.keycard_id} at {decision.gate_name} -> {decision.reason}")
        if decision.warning:
            print(f"Warning: {decision.warning}")
        return 0
    # Route to personnel management (check-in/out).
    if args.domain == "personnel":
        return _handle_personnel(args, facility)
    # Route to vault management (item movement).
    if args.domain == "vault":
        return _handle_vault(args, facility)
    # Route to guest invite management.
    if args.domain == "invite":
        return _handle_invites(args, facility)
    # Print recent history from the Event Bus.
    if args.domain == "event":
        for line in facility.status_dashboard(recent_event_limit=args.limit)["recent_events"]:
            print(line)
        return 0
    # Print the list of active security alerts.
    if args.domain == "alert":
        alerts = facility.active_alerts()
        if not alerts:
            print("No active alerts.")
            return 0
        for alert in alerts:
            print(
                f"{alert.alert_id} | {alert.state.value} | {alert.severity.name} | "
                f"{alert.source} | {alert.event.event_type} | {alert.event.message}"
            )
        return 0
    # Run the pre-scripted breach simulation and output resulting events.
    if args.domain == "simulate-breach":
        events = facility.simulate_breach()
        print(f"Simulated breach with {len(events)} event(s).")
        for event in events:
            print(f"{event.event_type}: {event.message}")
        return 0
    # Raise error if domain is recognized by parser but not by dispatcher.
    raise ValueError(f"Unsupported command domain: {args.domain}")

# Logic for creating, loading, or saving the facility state via specific subcommands.
def _handle_facility(args: argparse.Namespace, facility: Facility) -> int:
    if args.facility_action == "init":
        print(f"Initialized {facility.name}")
        _render_status(facility, recent=3)
        return 0
    if args.facility_action == "load":
        print(f"Loaded {facility.name} from {args.path}")
        _render_status(facility, recent=3)
        return 0
    if args.facility_action == "save":
        destination = facility.save(args.path)
        print(f"Saved facility state to {destination}")
        return 0
    raise ValueError(f"Unsupported facility action: {args.facility_action}")

# Logic for managing personnel movements on/off site.
def _handle_personnel(args: argparse.Namespace, facility: Facility) -> int:
    # Perform a check-in and display the person's location.
    if args.personnel_action == "check-in":
        person = facility.personnel_check_in(
            args.person_id,
            location=args.location,
            checked_in_at=_parse_datetime(args.at),
        )
        print(f"{person.unique_id} checked in at {person.location or 'unspecified location'}.")
        return 0
    # Perform a check-out and report any warnings (like held vault items).
    result = facility.personnel_check_out(args.person_id)
    print(f"{args.person_id} checked out.")
    for warning in result["warnings"]:
        print(f"Warning: {warning}")
    for item in result["checked_out_items"]:
        print(f"Held item: {item.item_id} {item.name}")
    return 0

# Logic for interacting with the vault's inventory.
def _handle_vault(args: argparse.Namespace, facility: Facility) -> int:
    # Remove item from vault and assign custody.
    if args.vault_action == "checkout":
        item = facility.vault_checkout(args.item_id, args.requester, notes=args.notes)
        print(f"Checked out {item.item_id} to {item.current_holder}.")
        return 0
    # Return item to vault storage.
    item = facility.vault_check_in(args.item_id, args.requester, notes=args.notes)
    print(f"Checked in {item.item_id}.")
    return 0

# Logic for invite code creation and validation.
def _handle_invites(args: argparse.Namespace, facility: Facility) -> int:
    # Create a new code with specific expiry and usage limits.
    if args.invite_action == "generate":
        invite = facility.generate_invite(
            creator_ref=args.creator_ref,
            required_access_level=args.required_access_level,
            max_use_count=args.uses,
            expires_at=datetime.now() + timedelta(hours=args.hours),
        )
        print(
            f"Generated invite {invite.code_string} "
            f"(masked: {invite.masked_code}, uses: {invite.remaining_uses})."
        )
        return 0
    # Check if a code is valid without consuming it.
    if args.invite_action == "validate":
        result = facility.validate_invite(args.code)
        state = result.state.value if result.state else "UNKNOWN"
        print(
            f"{result.masked_code}: usable={result.usable} "
            f"state={state} reason={result.reason or 'ok'}"
        )
        return 0
    # Consume one use of an invite code.
    entry = facility.use_invite(args.code)
    print(entry.detail)
    return 0

# Formatter to print a comprehensive facility status report to the console.
def _render_status(facility: Facility, *, recent: int) -> None:
    # Get the raw status data from the facility object.
    dashboard = facility.status_dashboard(recent_event_limit=recent)
    print(f"Facility: {dashboard['facility']}")
    print("Devices:")
    # Iterate through devices and print their IDs, types, and custom states (temp, lock status, etc.).
    for item in dashboard["devices"]:
        extras = ", ".join(
            f"{key}={value}"
            for key, value in item.items()
            if key not in {"device_id", "name", "device_type"}
        )
        print(f"  {item['device_id']} {item['device_type']} {item['name']} [{extras}]")
    print("Personnel on site:")
    # Breakdown count of people currently in the facility by role.
    if dashboard["personnel_on_site"]:
        for role, count in dashboard["personnel_on_site"].items():
            print(f"  {role}: {count}")
    else:
        print("  none")
    # Display the number of unresolved alerts.
    print(f"Active alerts: {dashboard['active_alerts']}")
    # Display vault inventory stats and financial value.
    summary = dashboard["vault_summary"]
    print(f"Vault items: {summary.total_items}")
    print(f"Vault value in place: {summary.total_value_in_vault}")
    print(f"Vault value checked out: {summary.total_value_checked_out}")
    print("Recent events:")
    # Print the most recent audit/security log messages.
    if dashboard["recent_events"]:
        for line in dashboard["recent_events"]:
            print(f"  {line}")
    else:
        print("  none")

# Helper to convert string timestamps into datetime objects.
def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)

# Rearranges arguments to ensure global flags (--state, --save) are handled regardless of position.
def _normalize_global_options(argv: list[str] | None) -> list[str]:
    # Use provided argv or default to sys.argv.
    items = list(sys.argv[1:] if argv is None else argv)
    extracted: list[str] = []
    remaining: list[str] = []
    index = 0
    # Iterate through tokens and pull out the global flags and their associated values.
    while index < len(items):
        token = items[index]
        if token in {"--state", "--save"} and index + 1 < len(items):
            extracted.extend([token, items[index + 1]])
            index += 2
            continue
        remaining.append(token)
        index += 1
    # Return global flags first followed by the domain/action arguments for argparse compatibility.
    return extracted + remaining