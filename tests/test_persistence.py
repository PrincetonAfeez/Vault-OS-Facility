""" Tests for the persistence layer. """

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FACILITY_ROOT = Path(__file__).resolve().parents[1]
if str(FACILITY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACILITY_ROOT))

from facility import Facility
from facility.core import FacilityStateError
from facility.persistence import (
    FACILITY_RECORD_VERSION,
    ensure_facility_record_version_supported,
    facility_from_record,
    facility_to_record,
)


class PersistenceSchemaTests(unittest.TestCase):
    def test_to_record_includes_schema_version(self) -> None:
        record = facility_to_record(Facility.create_demo())
        self.assertEqual(record["schema_version"], FACILITY_RECORD_VERSION)

    def test_ensure_accepts_legacy_missing_schema_version(self) -> None:
        ensure_facility_record_version_supported({"schema_version": 1})
        ensure_facility_record_version_supported({})

    def test_ensure_rejects_invalid_schema_type(self) -> None:
        with self.assertRaises(FacilityStateError):
            ensure_facility_record_version_supported({"schema_version": "x"})

    def test_ensure_rejects_future_schema(self) -> None:
        with self.assertRaises(FacilityStateError) as ctx:
            ensure_facility_record_version_supported({"schema_version": FACILITY_RECORD_VERSION + 1})
        self.assertIn("not supported", str(ctx.exception).lower())

    def test_from_record_rejects_unsupported_schema(self) -> None:
        base = facility_to_record(Facility.create_demo())
        base["schema_version"] = 99
        with self.assertRaises(FacilityStateError):
            facility_from_record(base, facility_cls=Facility)

    def test_round_trip_preserves_schema_version(self) -> None:
        facility = Facility.create_demo()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            facility.save(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], FACILITY_RECORD_VERSION)
            restored = Facility.load(path)
            self.assertEqual(restored.name, facility.name)

    def test_load_legacy_file_without_schema_version(self) -> None:
        facility = Facility.create_demo()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            record = facility_to_record(facility)
            del record["schema_version"]
            path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            restored = Facility.load(path)
            self.assertEqual(restored.name, facility.name)


if __name__ == "__main__":
    unittest.main()
