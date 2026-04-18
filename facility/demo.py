from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING

from .adapters import (
    AccessAccessLevel,
    DEMO_ALARM_RESET_CODE,
    DEMO_LOCK_KEYCODE,
    PERSON_TYPES,
    Contractor,
    Employee,
    Severity,
    to_utc,
)

if TYPE_CHECKING:
    from .core import Facility

def configure_demo_facility(facility: Facility) -> None:
    today = date.today()
    jordan = Employee(
        unique_id="EMP-001",
        name="Jordan Lee",
        contact_info="jordan.lee@vault.local",
        department="Operations",
        role_title="Operations Analyst",
        hire_date=today - timedelta(days=420),
        assigned_keycard_id="KC-0002",
    )
    sam = Employee(
        unique_id="EMP-002",
        name="Sam Rivera",
        contact_info="sam.rivera@vault.local",
        department="Collections",
        role_title="Collections Manager",
        hire_date=today - timedelta(days=900),
        assigned_keycard_id="KC-0003",
    )
    riley = Employee(
        unique_id="EMP-003",
        name="Riley Chen",
        contact_info="riley.chen@vault.local",
        department="Security",
        role_title="Security Director",
        hire_date=today - timedelta(days=1200),
        assigned_keycard_id="KC-0004",
    )
    avery = PERSON_TYPES["Visitor"](
        unique_id="VIS-001",
        name="Avery Stone",
        contact_info="avery.stone@example.com",
        host_employee_id="EMP-001",
        visit_purpose="Vendor demo",
        expected_duration_minutes=90,
    )
    taylor = Contractor(
        unique_id="CTR-001",
        name="Taylor Brooks",
        contact_info="taylor.brooks@contractor.example",
        company_name="Northline Security",
        contract_start_date=today - timedelta(days=30),
        contract_end_date=today + timedelta(days=30),
        restricted_areas=["Vault Antechamber", "Sublevel 2"],
    )

    for person in (jordan, sam, riley, avery, taylor):
        facility.register_person(person)

    contractor_card = facility.access.registry.issue_keycard(
        owner_name=taylor.name,
        access_level=AccessAccessLevel.STAFF,
        issue_date=today - timedelta(days=7),
        expiry_date=today + timedelta(days=30),
    )
    facility.link_person_keycard("VIS-001", "KC-0001")
    facility.link_person_keycard("CTR-001", contractor_card.card_id)

    facility.personnel_check_in("EMP-001", location="Main Entrance")
    facility.personnel_check_in("EMP-002", location="Sublevel 2")
    facility.personnel_check_in("EMP-003", location="North Tower")
    facility.personnel_check_in("VIS-001", location="Lobby")

    facility.generate_invite(
        creator_ref="EMP-003",
        required_access_level=AccessAccessLevel.STAFF,
        max_use_count=2,
        expires_at=to_utc(datetime.now() + timedelta(hours=12)),
    )
    facility.publish_event(
        source="Facility",
        event_type="FACILITY_INITIALIZED",
        severity=Severity.INFO,
        message=(
            f"Demo facility ready. Lock code {DEMO_LOCK_KEYCODE}; "
            f"alarm reset code {DEMO_ALARM_RESET_CODE}."
        ),
    )
