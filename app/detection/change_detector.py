"""Change Detector for OT Asset Discovery.

Compares incoming device data against stored inventory to generate alerts
for new devices, disappeared devices, firmware changes, and new protocol
observations. Persists alerts to the database before dispatching events.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.7
"""

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Callable, Awaitable, Optional

from app.models.domain import Alert, DeviceFingerprint


# Type alias for alert event callbacks
AlertCallback = Callable[[Alert], Awaitable[None]]


class ChangeDetector:
    """Detects changes in the OT device inventory and generates alerts.

    Compares incoming device fingerprints against known inventory state
    to detect:
    - New devices (Requirement 5.1)
    - Disappeared devices (Requirement 5.2)
    - Firmware version changes (Requirement 5.3)
    - New protocol observations (Requirement 5.4)

    Alerts are persisted with unique IDs before being dispatched to
    registered callbacks (Requirement 5.7).

    The class maintains in-memory state for tracking disappeared device
    alerts to prevent duplicate alerting. It uses an event-driven pattern
    where alert callbacks are registered for WebSocket broadcast and other
    consumers.
    """

    # Configurable timeout range for device disappearance (hours)
    MIN_DISAPPEARANCE_TIMEOUT_HOURS = 1.0
    MAX_DISAPPEARANCE_TIMEOUT_HOURS = 720.0
    DEFAULT_DISAPPEARANCE_TIMEOUT_HOURS = 24.0

    def __init__(
        self,
        disappearance_timeout_hours: float = DEFAULT_DISAPPEARANCE_TIMEOUT_HOURS,
    ):
        """Initialize the ChangeDetector.

        Args:
            disappearance_timeout_hours: Hours after which a device is
                considered disappeared. Must be between 1 and 720 (inclusive).
                Defaults to 24 hours.

        Raises:
            ValueError: If timeout is outside the valid range [1, 720].
        """
        if not (
            self.MIN_DISAPPEARANCE_TIMEOUT_HOURS
            <= disappearance_timeout_hours
            <= self.MAX_DISAPPEARANCE_TIMEOUT_HOURS
        ):
            raise ValueError(
                f"disappearance_timeout_hours must be between "
                f"{self.MIN_DISAPPEARANCE_TIMEOUT_HOURS} and "
                f"{self.MAX_DISAPPEARANCE_TIMEOUT_HOURS}, "
                f"got {disappearance_timeout_hours}"
            )

        self._disappearance_timeout_hours = disappearance_timeout_hours

        # Track devices that have been alerted as disappeared.
        # Maps device_id (UUID) -> True. Cleared when device is re-detected.
        self._disappeared_alerted: set[uuid.UUID] = set()

        # Registered alert callbacks for event dispatch
        self._alert_callbacks: list[AlertCallback] = []

        # Alert persistence callback (must be set before processing)
        self._persist_alert: Optional[Callable[[Alert], Awaitable[None]]] = None

    @property
    def disappearance_timeout_hours(self) -> float:
        """Get the configured disappearance timeout in hours."""
        return self._disappearance_timeout_hours

    @disappearance_timeout_hours.setter
    def disappearance_timeout_hours(self, value: float) -> None:
        """Set the disappearance timeout.

        Args:
            value: Timeout in hours, must be between 1 and 720.

        Raises:
            ValueError: If value is outside the valid range.
        """
        if not (
            self.MIN_DISAPPEARANCE_TIMEOUT_HOURS
            <= value
            <= self.MAX_DISAPPEARANCE_TIMEOUT_HOURS
        ):
            raise ValueError(
                f"disappearance_timeout_hours must be between "
                f"{self.MIN_DISAPPEARANCE_TIMEOUT_HOURS} and "
                f"{self.MAX_DISAPPEARANCE_TIMEOUT_HOURS}, "
                f"got {value}"
            )
        self._disappearance_timeout_hours = value

    def on_alert(self, callback: AlertCallback) -> None:
        """Register a callback to be invoked when an alert is generated.

        Callbacks are invoked after the alert is persisted to the database.
        Multiple callbacks can be registered (e.g., WebSocket broadcast,
        logging, metrics).

        Args:
            callback: Async function that receives an Alert object.
        """
        self._alert_callbacks.append(callback)

    def set_persist_handler(
        self, handler: Callable[[Alert], Awaitable[None]]
    ) -> None:
        """Set the alert persistence handler.

        This handler is called to persist the alert to the database
        BEFORE dispatching to registered callbacks (Requirement 5.7).

        Args:
            handler: Async function that persists an Alert to the database.
        """
        self._persist_alert = handler

    async def process_fingerprint(
        self,
        fingerprint: DeviceFingerprint,
        existing_device: Optional[dict] = None,
    ) -> list[Alert]:
        """Compare a fingerprint against inventory and generate alerts.

        Detects new devices, firmware changes, and new protocol observations.
        If existing_device is None, the device is treated as new.

        Args:
            fingerprint: The incoming DeviceFingerprint from parsing.
            existing_device: Dict with current device state from inventory,
                or None if this is a new device. Expected keys:
                - id: UUID of the device
                - mac_address: str
                - ip_address: str
                - firmware_version: Optional[str]
                - protocols: list[str]

        Returns:
            List of Alert objects generated from this fingerprint processing.
        """
        alerts: list[Alert] = []

        if existing_device is None:
            # New device detected (Requirement 5.1)
            alert = self._create_new_device_alert(fingerprint)
            alerts.append(alert)
        else:
            device_id = existing_device["id"]

            # Clear disappeared state on re-detection (Requirement 5.2)
            self._disappeared_alerted.discard(device_id)

            # Check firmware change (Requirement 5.3)
            firmware_alert = self._check_firmware_change(
                fingerprint, existing_device
            )
            if firmware_alert is not None:
                alerts.append(firmware_alert)

            # Check new protocol (Requirement 5.4)
            protocol_alert = self._check_new_protocol(
                fingerprint, existing_device
            )
            if protocol_alert is not None:
                alerts.append(protocol_alert)

        # Persist and dispatch all generated alerts
        for alert in alerts:
            await self._persist_and_dispatch(alert)

        return alerts

    async def check_disappeared_devices(
        self,
        devices: list[dict],
        current_time: Optional[datetime] = None,
    ) -> list[Alert]:
        """Check for devices that have not been seen within the timeout period.

        Generates a single MEDIUM alert per disappeared device. Does NOT
        generate duplicate alerts for the same device until it is re-detected
        and disappears again (Requirement 5.2).

        Args:
            devices: List of device dicts from inventory. Expected keys:
                - id: UUID of the device
                - mac_address: str
                - ip_address: str
                - last_seen: datetime (timezone-aware)
            current_time: Override for current time (useful for testing).
                Defaults to UTC now.

        Returns:
            List of Alert objects for newly disappeared devices.
        """
        if current_time is None:
            current_time = datetime.now(timezone.utc)

        timeout_seconds = self._disappearance_timeout_hours * 3600
        alerts: list[Alert] = []

        for device in devices:
            device_id = device["id"]
            last_seen = device["last_seen"]

            # Ensure last_seen is timezone-aware for comparison
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)

            elapsed = (current_time - last_seen).total_seconds()

            if elapsed > timeout_seconds:
                # Only alert if we haven't already alerted for this device
                if device_id not in self._disappeared_alerted:
                    alert = self._create_disappeared_alert(device)
                    self._disappeared_alerted.add(device_id)
                    alerts.append(alert)

        # Persist and dispatch all generated alerts
        for alert in alerts:
            await self._persist_and_dispatch(alert)

        return alerts

    def clear_disappeared_state(self, device_id: uuid.UUID) -> None:
        """Clear the disappeared alert state for a device.

        Called when a device is re-detected, allowing future disappearance
        alerts to be generated if it disappears again.

        Args:
            device_id: The UUID of the re-detected device.
        """
        self._disappeared_alerted.discard(device_id)

    def _create_new_device_alert(self, fingerprint: DeviceFingerprint) -> Alert:
        """Create a HIGH severity alert for a newly discovered device.

        Requirement 5.1: Contains IP, MAC, protocols, and discovery timestamp.

        Args:
            fingerprint: The DeviceFingerprint of the new device.

        Returns:
            Alert with type "new_device" and severity HIGH.
        """
        now = datetime.now(timezone.utc)
        protocols = []
        if fingerprint.protocol:
            protocols.append(fingerprint.protocol)

        return Alert(
            id=uuid.uuid4(),
            alert_type="new_device",
            severity="HIGH",
            device_id=None,  # Device may not have an ID yet
            details={
                "ip_address": fingerprint.ip_address or fingerprint.source_address,
                "mac_address": fingerprint.mac_address or "unknown",
                "protocols": protocols,
                "discovery_timestamp": now.isoformat(),
            },
            generated_at=now,
        )

    def _create_disappeared_alert(self, device: dict) -> Alert:
        """Create a MEDIUM severity alert for a disappeared device.

        Requirement 5.2: Single alert per disappearance, no duplicates.

        Args:
            device: Dict with device info (id, mac_address, ip_address, last_seen).

        Returns:
            Alert with type "device_disappeared" and severity MEDIUM.
        """
        now = datetime.now(timezone.utc)
        return Alert(
            id=uuid.uuid4(),
            alert_type="device_disappeared",
            severity="MEDIUM",
            device_id=device["id"],
            details={
                "ip_address": device.get("ip_address", "unknown"),
                "mac_address": device.get("mac_address", "unknown"),
                "last_seen": device["last_seen"].isoformat()
                if isinstance(device["last_seen"], datetime)
                else str(device["last_seen"]),
                "timeout_hours": self._disappearance_timeout_hours,
            },
            generated_at=now,
        )

    def _check_firmware_change(
        self,
        fingerprint: DeviceFingerprint,
        existing_device: dict,
    ) -> Optional[Alert]:
        """Check if firmware version has changed and generate alert.

        Requirement 5.3: HIGH alert with previous and new firmware versions.

        Args:
            fingerprint: The incoming DeviceFingerprint.
            existing_device: Dict with current device state.

        Returns:
            Alert if firmware changed, None otherwise.
        """
        new_firmware = fingerprint.firmware_version
        old_firmware = existing_device.get("firmware_version")

        # Only alert if both versions are known and they differ
        if (
            new_firmware is not None
            and old_firmware is not None
            and new_firmware != old_firmware
        ):
            now = datetime.now(timezone.utc)
            return Alert(
                id=uuid.uuid4(),
                alert_type="firmware_change",
                severity="HIGH",
                device_id=existing_device["id"],
                details={
                    "previous_version": old_firmware,
                    "new_version": new_firmware,
                    "device_ip": existing_device.get("ip_address", "unknown"),
                    "device_mac": existing_device.get("mac_address", "unknown"),
                },
                generated_at=now,
            )

        return None

    def _check_new_protocol(
        self,
        fingerprint: DeviceFingerprint,
        existing_device: dict,
    ) -> Optional[Alert]:
        """Check if a new protocol is observed and generate alert.

        Requirement 5.4: MEDIUM alert with device ID and protocol name.

        Args:
            fingerprint: The incoming DeviceFingerprint.
            existing_device: Dict with current device state.

        Returns:
            Alert if new protocol detected, None otherwise.
        """
        protocol = fingerprint.protocol
        existing_protocols = existing_device.get("protocols", [])

        if protocol and protocol not in existing_protocols:
            now = datetime.now(timezone.utc)
            return Alert(
                id=uuid.uuid4(),
                alert_type="new_protocol",
                severity="MEDIUM",
                device_id=existing_device["id"],
                details={
                    "device_id": str(existing_device["id"]),
                    "protocol": protocol,
                    "existing_protocols": existing_protocols,
                    "device_ip": existing_device.get("ip_address", "unknown"),
                },
                generated_at=now,
            )

        return None

    async def _persist_and_dispatch(self, alert: Alert) -> None:
        """Persist an alert to the database, then dispatch to callbacks.

        Requirement 5.7: Alerts are persisted BEFORE WebSocket dispatch.

        Args:
            alert: The Alert to persist and dispatch.
        """
        # Persist first (Requirement 5.7)
        if self._persist_alert is not None:
            await self._persist_alert(alert)

        # Then dispatch to all registered callbacks
        for callback in self._alert_callbacks:
            try:
                await callback(alert)
            except Exception:
                # Don't let a failing callback prevent other dispatches
                pass
