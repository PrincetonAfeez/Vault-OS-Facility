from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .adapters import (
    AccessDeniedError,
    CheckInError,
    DeviceAuthorizationError,
    DeviceLockoutError,
    InviteValidationError,
    ItemStateError,
)
from .core import Facility, FacilityError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="facility", description="Vault OS facility integration CLI.")
    parser.add_argument("--state", help="Path to an existing facility JSON state file.")
    parser.add_argument("--save", help="Write the resulting facility state to this path after the command.")
    subparsers = parser.add_subparsers(dest="domain", required=True)

    facility_parser = subparsers.add_parser("facility", help="Initialize or persist facility state.")
    facility_sub = facility_parser.add_subparsers(dest="facility_action", required=True)
    facility_sub.add_parser("init", help="Create a seeded demo facility.")
    load_parser = facility_sub.add_parser("load", help="Load and summarize a saved facility state.")
    load_parser.add_argument("path")
    save_parser = facility_sub.add_parser("save", help="Save the current facility state.")
    save_parser.add_argument("path")

    status_parser = subparsers.add_parser("status", help="Show a facility dashboard.")
    status_parser.add_argument("--recent", type=int, default=5)

    access_parser = subparsers.add_parser("access", help="Access-control workflows.")
    access_sub = access_parser.add_subparsers(dest="access_action", required=True)
    gate_parser = access_sub.add_parser("gate-check", help="Run a gate access check.")
    gate_parser.add_argument("card_id")
    gate_parser.add_argument("gate_name")
    gate_parser.add_argument("--at", help="ISO timestamp for the check.")

    personnel_parser = subparsers.add_parser("personnel", help="Personnel workflows.")
    personnel_sub = personnel_parser.add_subparsers(dest="personnel_action", required=True)
    personnel_in = personnel_sub.add_parser("check-in", help="Check a person in.")
    personnel_in.add_argument("person_id")
    personnel_in.add_argument("--location")
    personnel_in.add_argument("--at", help="ISO timestamp for the check-in.")
    personnel_out = personnel_sub.add_parser("check-out", help="Check a person out.")
    personnel_out.add_argument("person_id")

    vault_parser = subparsers.add_parser("vault", help="Vault workflows.")
    vault_sub = vault_parser.add_subparsers(dest="vault_action", required=True)
    vault_out = vault_sub.add_parser("checkout", help="Check out an item from the vault.")
    vault_out.add_argument("item_id")
    vault_out.add_argument("requester")
    vault_out.add_argument("--notes", default="")
    vault_in = vault_sub.add_parser("checkin", help="Check an item back into the vault.")
    vault_in.add_argument("item_id")
    vault_in.add_argument("requester")
    vault_in.add_argument("--notes", default="")

    invite_parser = subparsers.add_parser("invite", help="Invite workflows.")
    invite_sub = invite_parser.add_subparsers(dest="invite_action", required=True)
    invite_gen = invite_sub.add_parser("generate", help="Generate an invite code.")
    invite_gen.add_argument("creator_ref")
    invite_gen.add_argument("required_access_level")
    invite_gen.add_argument("--uses", type=int, default=1)
    invite_gen.add_argument("--hours", type=float, default=8.0)
    invite_validate = invite_sub.add_parser("validate", help="Validate an invite code.")
    invite_validate.add_argument("code")
    invite_use = invite_sub.add_parser("use", help="Consume an invite code.")
    invite_use.add_argument("code")

    event_parser = subparsers.add_parser("event", help="Event workflows.")
    event_sub = event_parser.add_subparsers(dest="event_action", required=True)
    history_parser = event_sub.add_parser("history", help="Show recent event history.")
    history_parser.add_argument("--limit", type=int, default=10)

    alert_parser = subparsers.add_parser("alert", help="Alert workflows.")
    alert_sub = alert_parser.add_subparsers(dest="alert_action", required=True)
    alert_sub.add_parser("list", help="List active alerts.")

    subparsers.add_parser("simulate-breach", help="Run the demo breach simulation.")
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalize_global_options(argv))

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
        facility = _resolve_facility(args)
        exit_code = _dispatch(args, facility)
        if args.domain == "facility" and args.facility_action == "save":
            return exit_code
        if args.save:
            destination = facility.save(args.save)
            print(f"Saved facility state to {destination}")
        return exit_code
    except _cli_errors as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

def _resolve_facility(args: argparse.Namespace) -> Facility:
    if args.domain == "facility" and args.facility_action == "init":
        return Facility.create_demo()
    if args.domain == "facility" and args.facility_action == "load":
        return Facility.load(args.path)
    if args.state:
        return Facility.load(args.state)
    return Facility.create_demo()

