from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from ..adapters import (
    AccessDeniedError,
    ItemSnapshot,
    ItemStateError,
    ItemStatus,
    Severity,
    to_vault_access_level,
)
from ..core import FacilityStateError

if TYPE_CHECKING:
    from ..core import Facility


class FacilityVaultMixin:
    """Vault custody workflows."""

    def vault_checkout(
        self: Facility,
        item_id: str,
        requester: str,
        *,
        notes: str = "",
    ) -> ItemSnapshot:
        person, card = self.resolve_actor(requester)
        self._ensure_card_is_usable(card)
        if person is not None and not person.on_site:
            message = f"{person.unique_id} must be on-site before checking out vault items."
            self.publish_event(
                source=item_id,
                event_type="VAULT_CHECKOUT_DENIED",
                severity=Severity.WARNING,
                message=message,
            )
            raise FacilityStateError(message)

        try:
            snapshot = self.vault.check_out(
                item_id,
                actor_name=person.name if person else card.owner_name,
                actor_access_level=to_vault_access_level(card.access_level),
                notes=notes,
            )
        except (AccessDeniedError, ItemStateError) as exc:
            self.publish_event(
                source=item_id,
                event_type="VAULT_CHECKOUT_DENIED",
                severity=Severity.WARNING,
                message=str(exc),
            )
            raise

        severity = Severity.WARNING if snapshot.monetary_value >= Decimal("100000.00") else Severity.INFO
        self.publish_event(
            source=item_id,
            event_type="VAULT_ITEM_CHECKED_OUT",
            severity=severity,
            message=f"{snapshot.name} checked out by {snapshot.current_holder}.",
        )
        return snapshot

    def vault_check_in(
        self: Facility,
        item_id: str,
        requester: str,
        *,
        notes: str = "",
    ) -> ItemSnapshot:
        person, card = self.resolve_actor(requester)
        self._ensure_card_is_usable(card)
        try:
            snapshot = self.vault.check_in(
                item_id,
                actor_name=person.name if person else card.owner_name,
                actor_access_level=to_vault_access_level(card.access_level),
                notes=notes,
            )
        except (AccessDeniedError, ItemStateError) as exc:
            self.publish_event(
                source=item_id,
                event_type="VAULT_CHECKIN_DENIED",
                severity=Severity.WARNING,
                message=str(exc),
            )
            raise

        self.publish_event(
            source=item_id,
            event_type="VAULT_ITEM_CHECKED_IN",
            severity=Severity.INFO,
            message=f"{snapshot.name} checked in by {person.name if person else card.owner_name}.",
        )
        return snapshot

    def items_checked_out_by_holder(self: Facility, holder_name: str) -> list[ItemSnapshot]:
        return [
            item
            for item in self.vault.search(status=ItemStatus.CHECKED_OUT)
            if item.current_holder == holder_name
        ]
