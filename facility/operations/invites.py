from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from ..adapters import (
    AccessAccessLevel,
    InviteCode,
    InviteState,
    InviteSummary,
    InviteValidationError,
    parse_access_level,
    to_utc,
    ValidationResult,
    Severity,
)

if TYPE_CHECKING:
    from ..core import Facility


class FacilityInvitesMixin:
    """Visitor invite lifecycle."""

    def review_invites_for_access_level(
        self: Facility,
        access_level: AccessAccessLevel | str | int,
    ) -> list[InviteSummary]:
        target = int(parse_access_level(access_level))
        return [
            summary
            for summary in self.invite_manager.list_codes(filter_by_state=InviteState.ACTIVE)
            if summary.required_access_level == target
        ]

    def generate_invite(
        self: Facility,
        *,
        creator_ref: str,
        required_access_level: AccessAccessLevel | str | int,
        max_use_count: int,
        expires_at: datetime,
    ) -> InviteCode:
        _, card = self.resolve_actor(creator_ref)
        self._ensure_card_is_usable(card)
        invite = self.invite_manager.generate(
            creator_id=card.card_id,
            required_access_level=int(parse_access_level(required_access_level)),
            max_use_count=max_use_count,
            expires_at=to_utc(expires_at),
        )
        self.publish_event(
            source=card.card_id,
            event_type="INVITE_GENERATED",
            severity=Severity.INFO,
            message=f"Invite {invite.masked_code} created with {invite.remaining_uses} use(s).",
        )
        return invite

    def validate_invite(self: Facility, code_string: str, *, at: datetime | None = None) -> ValidationResult:
        result = self.invite_manager.validate(code_string, at=to_utc(at))
        severity = Severity.INFO if result.usable else Severity.WARNING
        self.publish_event(
            source="InviteManager",
            event_type="INVITE_VALIDATED",
            severity=severity,
            timestamp=at,
            message=(
                f"{result.masked_code}: usable"
                if result.usable
                else f"{result.masked_code}: {result.reason or 'unusable'}"
            ),
        )
        return result

    def use_invite(self: Facility, code_string: str, *, at: datetime | None = None) -> Any:
        try:
            entry = self.invite_manager.use(code_string, at=to_utc(at))
        except InviteValidationError as exc:
            self.publish_event(
                source="InviteManager",
                event_type="INVITE_USE_DENIED",
                severity=Severity.WARNING,
                timestamp=at,
                message=str(exc),
            )
            raise
        self.publish_event(
            source="InviteManager",
            event_type="INVITE_USED",
            severity=Severity.INFO,
            timestamp=at,
            message=entry.detail,
        )
        return entry
