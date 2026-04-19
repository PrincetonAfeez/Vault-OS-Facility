""" Tests for the facility subsystem. """
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path

FACILITY_ROOT = Path(__file__).resolve().parents[1]
if str(FACILITY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACILITY_ROOT))

from facility import Facility
from facility.adapters import AccessAccessLevel, CheckInError, Contractor, ItemStatus


class FacilityIntegrationTests(unittest.TestCase):
    def test_demo_facility_connects_all_subsystems(self) -> None:
        facility = Facility.create_demo()

        dashboard = facility.status_dashboard()

        self.assertEqual(len(dashboard["devices"]), 4)
        self.assertEqual(dashboard["personnel_on_site"]["Employee"], 3)
        self.assertEqual(dashboard["personnel_on_site"]["Visitor"], 1)
        self.assertEqual(len(facility.invite_manager.list_codes()), 1)
        self.assertGreaterEqual(len(facility.event_history()), 5)

    def test_denied_gate_check_generates_event_alert(self) -> None:
        facility = Facility.create_demo()

        decision = facility.gate_check(
            "KC-0001",
            "Vault Antechamber",
            timestamp=datetime(2026, 4, 12, 10, 0, 0),
        )

        self.assertFalse(decision.granted)
        self.assertEqual(facility.active_alerts()[-1].event.event_type, "ACCESS_DENIED")

    def test_expired_contractor_check_in_revokes_linked_keycard(self) -> None:
        facility = Facility.create_demo()
        contractor = Contractor(
            unique_id="CTR-EXPIRED",
            name="Morgan Vale",
            contact_info="morgan.vale@example.com",
            company_name="TempSecure",
            contract_start_date=date.today() - timedelta(days=30),
            contract_end_date=date.today() - timedelta(days=1),
            restricted_areas=["Vault Antechamber"],
        )
        facility.register_person(contractor)
        card = facility.access.registry.issue_keycard(
            owner_name=contractor.name,
            access_level=AccessAccessLevel.STAFF,
            issue_date=date.today() - timedelta(days=5),
            expiry_date=date.today() + timedelta(days=10),
        )
        facility.link_person_keycard(contractor.unique_id, card.card_id)

        with self.assertRaises(CheckInError):
            facility.personnel_check_in(contractor.unique_id)

        self.assertTrue(facility.access.registry.require_card(card.card_id).revoked)

    def test_vault_checkout_and_state_round_trip(self) -> None:
        facility = Facility.create_demo()
        jewelry = next(
            item for item in facility.vault.search(status=ItemStatus.AVAILABLE) if item.item_id == "ITM-0002"
        )

        checked_out = facility.vault_checkout(jewelry.item_id, "EMP-002")

        self.assertEqual(checked_out.current_holder, "Sam Rivera")

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "facility.json"
            facility.save(path)
            restored = Facility.load(path)

        restored_checked_out = restored.vault.search(status=ItemStatus.CHECKED_OUT)
        self.assertEqual(len(restored_checked_out), 1)
        self.assertEqual(restored_checked_out[0].current_holder, "Sam Rivera")
        self.assertEqual(len(restored.event_history()), len(facility.event_history()))
        self.assertEqual(len(restored.invite_manager.list_codes()), len(facility.invite_manager.list_codes()))

    def test_load_invalid_json_raises_json_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{not valid json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                Facility.load(path)

    def test_cli_status_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "facility", "status", "--recent", "1"],
            cwd=str(FACILITY_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
