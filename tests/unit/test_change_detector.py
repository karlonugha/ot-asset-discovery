"""Unit tests for the ChangeDetector class.

Tests cover:
- New device detection generates HIGH alert (Requirement 5.1)
- Device disappearance generates single MEDIUM alert (Requirement 5.2)
- Firmware change detection generates HIGH alert (Requirement 5.3)
- New protocol detection generates MEDIUM alert (Requirement 5.4)
- Alert persistence before dispatch (Requirement 5.7)
- Configurable timeout validation
- No duplicate disappearance alerts
"""

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from app.detection.change_detector import ChangeDetector
from app.models.domain import DeviceFingerprint, Alert


# --- Fixtures ---


def make_fingerprint(
    protocol="modbus_tcp",
    source_address="192.168.1.10",
    destination_address="192.168.1.1",
    mac_address="00:11:22:33:44:55",
    ip_address="192.168.1.10",
    firmware_version=None,
    vendor=None,
    model=None,
) -> DeviceFingerprint:
    """Helper to create a DeviceFingerprint for testing."""
    return DeviceFingerprint(
        schema_version="1.0.0",
        protocol=protocol,
        source_address=source_address,
        destination_address=destination_address,
        mac_address=mac_address,
        ip_address=ip_address,
        firmware_version=firmware_version,
        vendor=vendor,
        model=model,
    )


def make_existing_device(
    device_id=None,
    mac_address="00:11:22:33:44:55",
    ip_address="192.168.1.10",
    firmware_version="1.0.0",
    protocols=None,
    last_seen=None,
) -> dict:
    """Helper to create an existing device dict for testing."""
    if device_id is None:
        device_id = uuid.uuid4()
    if protocols is None:
        protocols = ["modbus_tcp"]
    if last_seen is None:
        last_seen = datetime.now(timezone.utc)
    return {
        "id": device_id,
        "mac_address": mac_address,
        "ip_address": ip_address,
        "firmware_version": firmware_version,
        "protocols": protocols,
        "last_seen": last_seen,
    }


# --- Initialization Tests ---


class TestChangeDetectorInit:
    """Tests for ChangeDetector initialization and configuration."""

    def test_default_timeout(self):
        """Default disappearance timeout is 24 hours."""
        cd = ChangeDetector()
        assert cd.disappearance_timeout_hours == 24.0

    def test_custom_timeout(self):
        """Custom timeout within valid range is accepted."""
        cd = ChangeDetector(disappearance_timeout_hours=48.0)
        assert cd.disappearance_timeout_hours == 48.0

    def test_min_timeout(self):
        """Minimum timeout of 1 hour is accepted."""
        cd = ChangeDetector(disappearance_timeout_hours=1.0)
        assert cd.disappearance_timeout_hours == 1.0

    def test_max_timeout(self):
        """Maximum timeout of 720 hours is accepted."""
        cd = ChangeDetector(disappearance_timeout_hours=720.0)
        assert cd.disappearance_timeout_hours == 720.0

    def test_timeout_below_min_raises(self):
        """Timeout below 1 hour raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            ChangeDetector(disappearance_timeout_hours=0.5)

    def test_timeout_above_max_raises(self):
        """Timeout above 720 hours raises ValueError."""
        with pytest.raises(ValueError, match="must be between"):
            ChangeDetector(disappearance_timeout_hours=721.0)

    def test_timeout_setter_valid(self):
        """Setting timeout to valid value works."""
        cd = ChangeDetector()
        cd.disappearance_timeout_hours = 12.0
        assert cd.disappearance_timeout_hours == 12.0

    def test_timeout_setter_invalid(self):
        """Setting timeout to invalid value raises ValueError."""
        cd = ChangeDetector()
        with pytest.raises(ValueError, match="must be between"):
            cd.disappearance_timeout_hours = 0.0


# --- New Device Detection Tests (Requirement 5.1) ---


class TestNewDeviceDetection:
    """Tests for new device detection alert generation."""

    @pytest.mark.asyncio
    async def test_new_device_generates_high_alert(self):
        """New device generates a HIGH severity alert."""
        cd = ChangeDetector()
        fp = make_fingerprint()

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.alert_type == "new_device"
        assert alert.severity == "HIGH"

    @pytest.mark.asyncio
    async def test_new_device_alert_contains_ip(self):
        """New device alert contains the device IP address."""
        cd = ChangeDetector()
        fp = make_fingerprint(ip_address="10.0.0.5")

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert alerts[0].details["ip_address"] == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_new_device_alert_contains_mac(self):
        """New device alert contains the device MAC address."""
        cd = ChangeDetector()
        fp = make_fingerprint(mac_address="AA:BB:CC:DD:EE:FF")

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert alerts[0].details["mac_address"] == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.asyncio
    async def test_new_device_alert_contains_protocols(self):
        """New device alert contains the detected protocols."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="ethernetip")

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert "ethernetip" in alerts[0].details["protocols"]

    @pytest.mark.asyncio
    async def test_new_device_alert_contains_timestamp(self):
        """New device alert contains a discovery timestamp."""
        cd = ChangeDetector()
        fp = make_fingerprint()

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert "discovery_timestamp" in alerts[0].details

    @pytest.mark.asyncio
    async def test_new_device_alert_has_unique_id(self):
        """Each new device alert has a unique UUID."""
        cd = ChangeDetector()
        fp1 = make_fingerprint(ip_address="10.0.0.1")
        fp2 = make_fingerprint(ip_address="10.0.0.2")

        alerts1 = await cd.process_fingerprint(fp1, existing_device=None)
        alerts2 = await cd.process_fingerprint(fp2, existing_device=None)

        assert alerts1[0].id != alerts2[0].id

    @pytest.mark.asyncio
    async def test_new_device_uses_source_address_when_no_ip(self):
        """When ip_address is None, source_address is used."""
        cd = ChangeDetector()
        fp = make_fingerprint(ip_address=None, source_address="172.16.0.1")

        alerts = await cd.process_fingerprint(fp, existing_device=None)

        assert alerts[0].details["ip_address"] == "172.16.0.1"


# --- Device Disappearance Tests (Requirement 5.2) ---


class TestDeviceDisappearance:
    """Tests for device disappearance alert generation."""

    @pytest.mark.asyncio
    async def test_disappeared_device_generates_medium_alert(self):
        """Device past timeout generates MEDIUM alert."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        device = make_existing_device(last_seen=old_time)

        alerts = await cd.check_disappeared_devices([device])

        assert len(alerts) == 1
        assert alerts[0].alert_type == "device_disappeared"
        assert alerts[0].severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_device_within_timeout_no_alert(self):
        """Device within timeout does not generate alert."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        recent_time = datetime.now(timezone.utc) - timedelta(hours=12)
        device = make_existing_device(last_seen=recent_time)

        alerts = await cd.check_disappeared_devices([device])

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_no_duplicate_disappearance_alerts(self):
        """Same device does not get duplicate disappearance alerts."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        device = make_existing_device(last_seen=old_time)

        # First check - should alert
        alerts1 = await cd.check_disappeared_devices([device])
        assert len(alerts1) == 1

        # Second check - should NOT alert again
        alerts2 = await cd.check_disappeared_devices([device])
        assert len(alerts2) == 0

    @pytest.mark.asyncio
    async def test_re_detection_clears_disappeared_state(self):
        """Re-detecting a device clears its disappeared state."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        device_id = uuid.uuid4()
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        device = make_existing_device(device_id=device_id, last_seen=old_time)

        # First disappearance
        alerts1 = await cd.check_disappeared_devices([device])
        assert len(alerts1) == 1

        # Re-detection via process_fingerprint
        fp = make_fingerprint()
        existing = make_existing_device(device_id=device_id)
        await cd.process_fingerprint(fp, existing_device=existing)

        # Should alert again after re-detection + disappearance
        alerts2 = await cd.check_disappeared_devices([device])
        assert len(alerts2) == 1

    @pytest.mark.asyncio
    async def test_disappeared_alert_contains_device_id(self):
        """Disappeared alert references the correct device ID."""
        cd = ChangeDetector(disappearance_timeout_hours=1.0)
        device_id = uuid.uuid4()
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        device = make_existing_device(device_id=device_id, last_seen=old_time)

        alerts = await cd.check_disappeared_devices([device])

        assert alerts[0].device_id == device_id

    @pytest.mark.asyncio
    async def test_disappeared_alert_contains_last_seen(self):
        """Disappeared alert contains the last_seen timestamp."""
        cd = ChangeDetector(disappearance_timeout_hours=1.0)
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        device = make_existing_device(last_seen=old_time)

        alerts = await cd.check_disappeared_devices([device])

        assert "last_seen" in alerts[0].details

    @pytest.mark.asyncio
    async def test_multiple_devices_disappeared(self):
        """Multiple devices can disappear in one check."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        old_time = datetime.now(timezone.utc) - timedelta(hours=25)
        devices = [
            make_existing_device(device_id=uuid.uuid4(), last_seen=old_time),
            make_existing_device(device_id=uuid.uuid4(), last_seen=old_time),
        ]

        alerts = await cd.check_disappeared_devices(devices)

        assert len(alerts) == 2

    @pytest.mark.asyncio
    async def test_custom_current_time(self):
        """Custom current_time parameter is used for comparison."""
        cd = ChangeDetector(disappearance_timeout_hours=24.0)
        last_seen = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        device = make_existing_device(last_seen=last_seen)

        # 23 hours later - should NOT alert
        current_time = datetime(2024, 1, 2, 11, 0, 0, tzinfo=timezone.utc)
        alerts = await cd.check_disappeared_devices([device], current_time=current_time)
        assert len(alerts) == 0

        # 25 hours later - should alert
        current_time = datetime(2024, 1, 2, 13, 0, 0, tzinfo=timezone.utc)
        alerts = await cd.check_disappeared_devices([device], current_time=current_time)
        assert len(alerts) == 1


# --- Firmware Change Tests (Requirement 5.3) ---


class TestFirmwareChangeDetection:
    """Tests for firmware change alert generation."""

    @pytest.mark.asyncio
    async def test_firmware_change_generates_high_alert(self):
        """Firmware version change generates HIGH alert."""
        cd = ChangeDetector()
        fp = make_fingerprint(firmware_version="2.0.0")
        existing = make_existing_device(firmware_version="1.0.0")

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "firmware_change"
        assert alerts[0].severity == "HIGH"

    @pytest.mark.asyncio
    async def test_firmware_change_contains_versions(self):
        """Firmware change alert contains previous and new versions."""
        cd = ChangeDetector()
        fp = make_fingerprint(firmware_version="2.5.1")
        existing = make_existing_device(firmware_version="1.3.0")

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert alerts[0].details["previous_version"] == "1.3.0"
        assert alerts[0].details["new_version"] == "2.5.1"

    @pytest.mark.asyncio
    async def test_same_firmware_no_alert(self):
        """Same firmware version does not generate alert."""
        cd = ChangeDetector()
        fp = make_fingerprint(firmware_version="1.0.0")
        existing = make_existing_device(firmware_version="1.0.0")

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_null_new_firmware_no_alert(self):
        """Null new firmware does not generate alert."""
        cd = ChangeDetector()
        fp = make_fingerprint(firmware_version=None)
        existing = make_existing_device(firmware_version="1.0.0")

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_null_old_firmware_no_alert(self):
        """Null old firmware does not generate alert (first detection)."""
        cd = ChangeDetector()
        fp = make_fingerprint(firmware_version="1.0.0")
        existing = make_existing_device(firmware_version=None)

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_firmware_alert_references_device(self):
        """Firmware change alert references the correct device ID."""
        cd = ChangeDetector()
        device_id = uuid.uuid4()
        fp = make_fingerprint(firmware_version="2.0.0")
        existing = make_existing_device(device_id=device_id, firmware_version="1.0.0")

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert alerts[0].device_id == device_id


# --- New Protocol Detection Tests (Requirement 5.4) ---


class TestNewProtocolDetection:
    """Tests for new protocol observation alert generation."""

    @pytest.mark.asyncio
    async def test_new_protocol_generates_medium_alert(self):
        """New protocol generates MEDIUM alert."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="ethernetip")
        existing = make_existing_device(protocols=["modbus_tcp"])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "new_protocol"
        assert alerts[0].severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_new_protocol_contains_device_id(self):
        """New protocol alert contains the device identifier."""
        cd = ChangeDetector()
        device_id = uuid.uuid4()
        fp = make_fingerprint(protocol="s7comm")
        existing = make_existing_device(device_id=device_id, protocols=["modbus_tcp"])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert alerts[0].details["device_id"] == str(device_id)

    @pytest.mark.asyncio
    async def test_new_protocol_contains_protocol_name(self):
        """New protocol alert contains the protocol name."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="dnp3")
        existing = make_existing_device(protocols=["modbus_tcp"])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert alerts[0].details["protocol"] == "dnp3"

    @pytest.mark.asyncio
    async def test_existing_protocol_no_alert(self):
        """Already known protocol does not generate alert."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="modbus_tcp")
        existing = make_existing_device(protocols=["modbus_tcp"])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 0

    @pytest.mark.asyncio
    async def test_empty_protocols_list_triggers_alert(self):
        """Device with empty protocols list gets alert for any protocol."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="modbus_tcp")
        existing = make_existing_device(protocols=[])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "new_protocol"

    @pytest.mark.asyncio
    async def test_new_protocol_alert_references_device(self):
        """New protocol alert references the correct device ID."""
        cd = ChangeDetector()
        device_id = uuid.uuid4()
        fp = make_fingerprint(protocol="ethernetip")
        existing = make_existing_device(device_id=device_id, protocols=["modbus_tcp"])

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert alerts[0].device_id == device_id


# --- Alert Persistence Tests (Requirement 5.7) ---


class TestAlertPersistence:
    """Tests for alert persistence before WebSocket dispatch."""

    @pytest.mark.asyncio
    async def test_persist_called_before_callbacks(self):
        """Alert is persisted before callbacks are invoked."""
        cd = ChangeDetector()
        call_order = []

        async def persist_handler(alert: Alert):
            call_order.append("persist")

        async def callback(alert: Alert):
            call_order.append("callback")

        cd.set_persist_handler(persist_handler)
        cd.on_alert(callback)

        fp = make_fingerprint()
        await cd.process_fingerprint(fp, existing_device=None)

        assert call_order == ["persist", "callback"]

    @pytest.mark.asyncio
    async def test_alert_has_all_required_fields(self):
        """Persisted alert has unique ID, type, severity, device_id, details, timestamp."""
        cd = ChangeDetector()
        persisted_alerts = []

        async def persist_handler(alert: Alert):
            persisted_alerts.append(alert)

        cd.set_persist_handler(persist_handler)

        fp = make_fingerprint()
        await cd.process_fingerprint(fp, existing_device=None)

        alert = persisted_alerts[0]
        assert alert.id is not None
        assert alert.alert_type is not None
        assert alert.severity is not None
        assert alert.details is not None
        assert alert.generated_at is not None

    @pytest.mark.asyncio
    async def test_multiple_callbacks_all_invoked(self):
        """All registered callbacks are invoked for each alert."""
        cd = ChangeDetector()
        callback_calls = []

        async def callback1(alert: Alert):
            callback_calls.append("cb1")

        async def callback2(alert: Alert):
            callback_calls.append("cb2")

        cd.on_alert(callback1)
        cd.on_alert(callback2)

        fp = make_fingerprint()
        await cd.process_fingerprint(fp, existing_device=None)

        assert "cb1" in callback_calls
        assert "cb2" in callback_calls

    @pytest.mark.asyncio
    async def test_failing_callback_does_not_block_others(self):
        """A failing callback does not prevent other callbacks from running."""
        cd = ChangeDetector()
        callback_calls = []

        async def failing_callback(alert: Alert):
            raise RuntimeError("Callback failed")

        async def working_callback(alert: Alert):
            callback_calls.append("working")

        cd.on_alert(failing_callback)
        cd.on_alert(working_callback)

        fp = make_fingerprint()
        await cd.process_fingerprint(fp, existing_device=None)

        assert "working" in callback_calls

    @pytest.mark.asyncio
    async def test_no_persist_handler_still_dispatches(self):
        """Without a persist handler, callbacks still fire."""
        cd = ChangeDetector()
        callback_calls = []

        async def callback(alert: Alert):
            callback_calls.append(alert)

        cd.on_alert(callback)

        fp = make_fingerprint()
        await cd.process_fingerprint(fp, existing_device=None)

        assert len(callback_calls) == 1


# --- Combined Scenarios ---


class TestCombinedScenarios:
    """Tests for scenarios that trigger multiple alert types."""

    @pytest.mark.asyncio
    async def test_firmware_and_protocol_change_together(self):
        """Both firmware change and new protocol generate separate alerts."""
        cd = ChangeDetector()
        fp = make_fingerprint(protocol="ethernetip", firmware_version="2.0.0")
        existing = make_existing_device(
            firmware_version="1.0.0", protocols=["modbus_tcp"]
        )

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 2
        alert_types = {a.alert_type for a in alerts}
        assert "firmware_change" in alert_types
        assert "new_protocol" in alert_types

    @pytest.mark.asyncio
    async def test_re_detection_no_changes_no_alerts(self):
        """Re-detection with no changes generates no alerts."""
        cd = ChangeDetector()
        fp = make_fingerprint(
            protocol="modbus_tcp", firmware_version="1.0.0"
        )
        existing = make_existing_device(
            firmware_version="1.0.0", protocols=["modbus_tcp"]
        )

        alerts = await cd.process_fingerprint(fp, existing_device=existing)

        assert len(alerts) == 0
