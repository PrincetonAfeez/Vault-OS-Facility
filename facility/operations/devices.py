from __future__ import annotations

from typing import TYPE_CHECKING

from ..adapters import (
    AlarmSystem,
    Camera,
    DeviceAuthorizationError,
    DeviceLockoutError,
    Event,
    Lock,
    Severity,
)

if TYPE_CHECKING:
    from ..core import Facility


class FacilityDevicesMixin:
    """Integrated device panel behaviors."""

    def simulate_breach(self: Facility) -> tuple[Event, ...]:
        before = len(self.event_bus.history)

        camera = self.device_panel.get_device("CAM-01")
        lock = self.device_panel.get_device("LOCK-01")
        alarm = self.device_panel.get_device("ALARM-01")

        if isinstance(camera, Camera):
            if not camera.powered_on:
                camera.power_on()
            if not camera.recording:
                camera.start_recording()
            self.publish_event(
                source=camera.device_id,
                event_type="MOTION_DETECTED",
                severity=Severity.WARNING,
                message=f"{camera.name} detected motion at {self.device_locations.get(camera.device_id, 'unknown area')}.",
            )

        if isinstance(lock, Lock):
            if not lock.powered_on:
                lock.power_on()
            for attempt in range(1, 4):
                try:
                    lock.unlock("0000")
                except DeviceAuthorizationError:
                    self.publish_event(
                        source=lock.device_id,
                        event_type="FORCED_ENTRY_ATTEMPT",
                        severity=Severity.WARNING,
                        message=f"Invalid unlock attempt {attempt} on {lock.name}.",
                    )
                except DeviceLockoutError as exc:
                    self.publish_event(
                        source=lock.device_id,
                        event_type="FORCED_ENTRY_ATTEMPT",
                        severity=Severity.CRITICAL,
                        message=str(exc),
                    )
                    break

        if isinstance(alarm, AlarmSystem):
            if not alarm.powered_on:
                alarm.power_on()
            if alarm.arm_mode is None:
                alarm.arm("away")
            if not alarm.triggered:
                alarm.trigger()
            self.publish_event(
                source=alarm.device_id,
                event_type="ALARM_TRIGGERED",
                severity=Severity.CRITICAL,
                message=f"{alarm.name} triggered during breach simulation.",
            )

        return tuple(self.event_bus.history)[before:]
