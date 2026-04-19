from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from ..adapters import (
    AccessDecision,
    Contractor,
    Keycard,
    naive_facility_moment,
    Severity,
)
from ..core import FacilityStateError

if TYPE_CHECKING:
    from ..core import Facility


class FacilityAccessMixin:
    """Physical and logical access: gates, keycards."""

    def gate_check(
        self: Facility,
        card_id: str,
        gate_name: str,
        *,
        timestamp: datetime | None = None,
    ) -> AccessDecision:
        moment = naive_facility_moment(timestamp or datetime.now())
        normalized_card_id = card_id.strip().upper()
        gate = self.access.get_gate(gate_name)
        person = self.person_for_card(normalized_card_id)

        if gate is None:
            raise KeyError(f"Unknown gate '{gate_name}'.")

        if isinstance(person, Contractor) and self._contractor_area_blocked(person, gate):
            decision = AccessDecision(
                granted=False,
                reason=f"{person.unique_id} is restricted from {gate.name}.",
                keycard_id=normalized_card_id,
                gate_name=gate.name,
                timestamp=moment,
            )
            entry = self.access.log.record(decision)
            alert = self.access.monitor.observe(entry)
            if alert is not None:
                self.access.log.record_alert(alert)
                decision = decision.with_warning(alert.message)
        else:
            decision = self.access.attempt_access(normalized_card_id, gate.name, moment)

        self.publish_event(
            source=decision.gate_name,
            event_type="ACCESS_GRANTED" if decision.granted else "ACCESS_DENIED",
            severity=Severity.INFO if decision.granted else Severity.WARNING,
            timestamp=decision.timestamp,
            message=f"{decision.keycard_id}: {decision.reason}",
        )
        if decision.warning:
            self.publish_event(
                source=decision.gate_name,
                event_type="SUSPICIOUS_ACTIVITY",
                severity=Severity.CRITICAL,
                timestamp=decision.timestamp,
                message=f"{decision.keycard_id}: {decision.warning}",
            )
        return decision

    def revoke_keycard(self: Facility, card_id: str, reason: str, *, revoked_at: datetime | None = None) -> Keycard:
        card = self.access.registry.require_card(card_id)
        if not card.revoked:
            self.access.registry.revoke_card(card.card_id, reason, revoked_at=revoked_at)
            self.publish_event(
                source=card.card_id,
                event_type="KEYCARD_REVOKED",
                severity=Severity.WARNING,
                timestamp=revoked_at,
                message=f"{card.owner_name}: {reason}",
            )
        reviewed = self.review_invites_for_access_level(card.access_level)
        if reviewed:
            self.publish_event(
                source=card.card_id,
                event_type="INVITES_REVIEWED",
                severity=Severity.WARNING,
                message=(
                    f"{len(reviewed)} active invite(s) match revoked level {card.access_level.name}."
                ),
            )
        return card

    def _ensure_card_is_usable(self: Facility, card: Keycard, *, when: datetime | None = None) -> None:
        status = card.status(when or datetime.now())
        if status != "ACTIVE":
            raise FacilityStateError(f"Keycard {card.card_id} is not usable ({status}).")
