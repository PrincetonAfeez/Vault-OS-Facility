from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ..adapters import (
    Alert,
    Event,
    ItemStatus,
    Severity,
    format_event,
    to_utc,
)

if TYPE_CHECKING:
    from ..core import Facility


class FacilityEventsMixin:
    """Cross-cutting event bus, alerts, and dashboard."""

    def publish_event(
        self: Facility,
        *,
        source: str,
        event_type: str,
        severity: Severity | str,
        message: str,
        timestamp: datetime | None = None,
    ) -> tuple[Event, ...]:
        event = Event(
            source=source,
            event_type=event_type,
            severity=severity,
            message=message,
            timestamp=to_utc(timestamp),
        )
        return self.event_bus.publish(event)

    def event_history(self: Facility, limit: int | None = None) -> tuple[Event, ...]:
        history = tuple(self.event_bus.history)
        if limit is None or limit >= len(history):
            return history
        return history[-limit:]

    def active_alerts(self: Facility) -> tuple[Alert, ...]:
        return self.alert_manager.active_alerts()

    def status_dashboard(self: Facility, recent_event_limit: int = 5) -> dict[str, Any]:
        on_site = self.personnel.who_is_on_site()
        personnel_counts = Counter(person.person_type for person in on_site)
        checked_out_items = self.vault.search(status=ItemStatus.CHECKED_OUT)
        return {
            "facility": self.name,
            "devices": self.device_panel.status_report(),
            "personnel_on_site": dict(personnel_counts),
            "active_alerts": len(self.active_alerts()),
            "vault_summary": self.vault.summary(),
            "checked_out_items": checked_out_items,
            "recent_events": [format_event(event) for event in self.event_history(limit=recent_event_limit)],
        }
