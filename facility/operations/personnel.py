from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from ..adapters import (
    AccessGate,
    CheckInError,
    Contractor,
    Employee,
    Keycard,
    Person,
    Severity,
    facility_date,
)
from ..core import FacilityStateError

if TYPE_CHECKING:
    from ..core import Facility


class FacilityPersonnelMixin:
    """Registration, roster, and keycard-to-person resolution."""

    def register_person(self: Facility, person: Person, *, card_id: str | None = None) -> Person:
        registered = self.personnel.register(person)
        if card_id:
            self.link_person_keycard(person.unique_id, card_id)
        elif isinstance(person, Employee):
            self.link_person_keycard(person.unique_id, person.assigned_keycard_id)
        return registered

    def link_person_keycard(self: Facility, person_id: str, card_id: str) -> None:
        self.person_keycards[person_id] = card_id.strip().upper()

    def personnel_check_in(
        self: Facility,
        person_id: str,
        *,
        location: str | None = None,
        checked_in_at: datetime | None = None,
    ) -> Person:
        moment = checked_in_at or datetime.now()
        person = self.require_person(person_id)

        if isinstance(person, Contractor) and not person.is_contract_active(facility_date(moment)):
            card_id = self.card_id_for_person(person.unique_id)
            if card_id:
                self.revoke_keycard(card_id, "Contract expired.")
            message = (
                f"Contractor {person.unique_id} cannot check in because the contract is inactive."
            )
            self.publish_event(
                source=person.unique_id,
                event_type="PERSONNEL_CHECK_IN_DENIED",
                severity=Severity.WARNING,
                timestamp=moment,
                message=message,
            )
            raise CheckInError(message)

        try:
            checked_in = self.personnel.check_in(
                person.unique_id,
                location=location,
                checked_in_at=moment,
            )
        except CheckInError as exc:
            self.publish_event(
                source=person.unique_id,
                event_type="PERSONNEL_CHECK_IN_DENIED",
                severity=Severity.WARNING,
                timestamp=moment,
                message=str(exc),
            )
            raise

        self.publish_event(
            source=checked_in.unique_id,
            event_type="PERSONNEL_CHECKED_IN",
            severity=Severity.INFO,
            timestamp=moment,
            message=f"{checked_in.name} checked in at {checked_in.location or 'unspecified location'}.",
        )
        return checked_in

    def personnel_check_out(self: Facility, person_id: str) -> dict[str, Any]:
        person = self.require_person(person_id)
        warnings = self.personnel.check_out(person.unique_id)
        held_items = self.items_checked_out_by_holder(person.name)
        self.publish_event(
            source=person.unique_id,
            event_type="PERSONNEL_CHECKED_OUT",
            severity=Severity.INFO,
            message=f"{person.name} checked out of the facility.",
        )
        for warning in warnings:
            self.publish_event(
                source=person.unique_id,
                event_type="HOST_DEPARTURE_WARNING",
                severity=Severity.WARNING,
                message=warning,
            )
        if held_items:
            item_ids = ", ".join(item.item_id for item in held_items)
            self.publish_event(
                source=person.unique_id,
                event_type="OUTSTANDING_VAULT_ITEMS",
                severity=Severity.WARNING,
                message=f"{person.name} left while still holding: {item_ids}.",
            )
        return {"warnings": warnings, "checked_out_items": held_items}

    def require_person(self: Facility, person_id: str) -> Person:
        person = self.personnel.lookup(person_id)
        if person is None:
            raise FacilityStateError(f"{person_id} is not registered in the facility.")
        return person

    def card_id_for_person(self: Facility, person_id: str) -> str | None:
        person = self.personnel.lookup(person_id)
        if isinstance(person, Employee):
            return person.assigned_keycard_id
        return self.person_keycards.get(person_id)

    def person_for_card(self: Facility, card_id: str) -> Person | None:
        normalized = card_id.strip().upper()
        for person_id, linked_card_id in self._linked_cards().items():
            if linked_card_id == normalized:
                return self.personnel.lookup(person_id)
        return None

    def resolve_actor(self: Facility, actor_ref: str) -> tuple[Person | None, Keycard]:
        person = self.personnel.lookup(actor_ref)
        if person is not None:
            card_id = self.card_id_for_person(person.unique_id)
            if card_id is None:
                raise FacilityStateError(f"{person.unique_id} does not have a linked keycard.")
            return person, self.access.registry.require_card(card_id)
        return self.person_for_card(actor_ref), self.access.registry.require_card(actor_ref)

    def _linked_cards(self: Facility) -> dict[str, str]:
        linked = dict(self.person_keycards)
        for person in self.personnel.iter_people_sorted_by_id():
            if isinstance(person, Employee):
                linked[person.unique_id] = person.assigned_keycard_id
        return linked

    def _contractor_area_blocked(self: Facility, person: Contractor, gate: AccessGate) -> bool:
        restricted = {area.strip().lower() for area in person.restricted_areas}
        return gate.name.lower() in restricted or gate.location.lower() in restricted
