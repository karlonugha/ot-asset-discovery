"""Unit tests for the export service.

Tests CSV, JSON, and PDF export functionality including:
- Correct CSV headers and data rows
- Valid JSON array output
- PDF report sections (vendor/protocol summary, inventory table, topology, risk histogram, alerts)
- Filter parameter support
- Empty result handling
- Record limit enforcement (50,000 max)
- Timeout enforcement (60 seconds)

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.export.service import (
    CSV_HEADERS,
    EXPORT_TIMEOUT_SECONDS,
    MAX_EXPORT_RECORDS,
    ExportRecordLimitExceeded,
    ExportService,
    ExportTimeoutError,
)


# --- Test Fixtures ---


def _make_device(
    ip="192.168.1.1",
    mac="00:11:22:33:44:55",
    vendor="Siemens",
    model="S7-1200",
    firmware_version="V4.5.0",
    device_type="PLC",
    protocols=None,
    risk_score=45,
    fingerprint=None,
):
    """Create a mock device object for testing."""
    device = MagicMock()
    device.id = uuid.uuid4()
    device.ip_address = ip
    device.mac_address = mac
    device.vendor = vendor
    device.model = model
    device.firmware_version = firmware_version
    device.device_type = device_type
    device.protocols = protocols or ["modbus_tcp"]
    device.risk_score = risk_score
    device.fingerprint = fingerprint
    device.first_seen = datetime(2024, 1, 1, tzinfo=timezone.utc)
    device.last_seen = datetime(2024, 6, 15, 10, 30, tzinfo=timezone.utc)
    device.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    device.updated_at = datetime(2024, 6, 15, 10, 30, tzinfo=timezone.utc)
    return device


def _make_fingerprint_dict(
    protocol="modbus_tcp",
    vendor="Siemens",
    model="S7-1200",
):
    """Create a DeviceFingerprint-compatible dict."""
    return {
        "schema_version": "1.0.0",
        "protocol": protocol,
        "source_address": "192.168.1.1",
        "destination_address": "192.168.1.100",
        "mac_address": "00:11:22:33:44:55",
        "ip_address": "192.168.1.1",
        "vendor": vendor,
        "model": model,
        "firmware_version": "V4.5.0",
        "device_type": "PLC",
        "serial_number": "SN12345",
        "protocol_data": {"unit_id": 1},
        "parsing_status": "complete",
        "binary_fields": {},
    }


# --- CSV Export Tests ---


class TestCSVExport:
    """Tests for CSV export functionality (Requirement 10.1)."""

    @pytest.mark.asyncio
    async def test_csv_export_headers_only_when_empty(self):
        """Empty results should return CSV with headers only (Requirement 10.5)."""
        session = AsyncMock()

        # Mock count query returning 0
        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        # Mock data query returning empty
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        csv_content = await service.export_csv()

        # Parse CSV
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        # Should have headers but no data rows
        assert reader.fieldnames == CSV_HEADERS
        assert len(rows) == 0

    @pytest.mark.asyncio
    async def test_csv_export_with_devices(self):
        """CSV export should have header row and one row per device (Requirement 10.1)."""
        session = AsyncMock()

        devices = [
            _make_device(ip="192.168.1.1", vendor="Siemens", fingerprint=_make_fingerprint_dict()),
            _make_device(ip="192.168.1.2", vendor="Allen-Bradley", fingerprint=_make_fingerprint_dict(vendor="Allen-Bradley")),
        ]

        # Mock count query
        count_result = MagicMock()
        count_result.scalar_one.return_value = 2

        # Mock data query
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        csv_content = await service.export_csv()

        # Parse CSV
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        assert reader.fieldnames == CSV_HEADERS
        assert len(rows) == 2
        assert rows[0]["vendor"] == "Siemens"
        assert rows[1]["vendor"] == "Allen-Bradley"

    @pytest.mark.asyncio
    async def test_csv_export_all_fingerprint_fields(self):
        """CSV should contain all DeviceFingerprint fields (Requirement 10.1)."""
        session = AsyncMock()

        fp = _make_fingerprint_dict()
        devices = [_make_device(fingerprint=fp)]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        csv_content = await service.export_csv()

        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["schema_version"] == "1.0.0"
        assert row["protocol"] == "modbus_tcp"
        assert row["source_address"] == "192.168.1.1"
        assert row["vendor"] == "Siemens"
        assert row["model"] == "S7-1200"
        assert row["firmware_version"] == "V4.5.0"
        assert row["device_type"] == "PLC"
        assert row["serial_number"] == "SN12345"
        assert row["parsing_status"] == "complete"

    @pytest.mark.asyncio
    async def test_csv_export_constructs_fingerprint_when_none(self):
        """When device has no stored fingerprint, CSV should construct one from attributes."""
        session = AsyncMock()

        devices = [_make_device(fingerprint=None)]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        csv_content = await service.export_csv()

        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["schema_version"] == "1.0.0"
        assert row["vendor"] == "Siemens"
        assert row["model"] == "S7-1200"


# --- JSON Export Tests ---


class TestJSONExport:
    """Tests for JSON export functionality (Requirement 10.2)."""

    @pytest.mark.asyncio
    async def test_json_export_empty_array_when_no_devices(self):
        """Empty results should return empty JSON array (Requirement 10.5)."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        json_content = await service.export_json()

        parsed = json.loads(json_content)
        assert isinstance(parsed, list)
        assert len(parsed) == 0

    @pytest.mark.asyncio
    async def test_json_export_valid_array(self):
        """JSON export should produce valid array of DeviceFingerprint objects (Requirement 10.2)."""
        session = AsyncMock()

        fp1 = _make_fingerprint_dict(vendor="Siemens")
        fp2 = _make_fingerprint_dict(vendor="Allen-Bradley")
        devices = [
            _make_device(ip="192.168.1.1", vendor="Siemens", fingerprint=fp1),
            _make_device(ip="192.168.1.2", vendor="Allen-Bradley", fingerprint=fp2),
        ]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 2

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        json_content = await service.export_json()

        parsed = json.loads(json_content)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

        # Verify each element has DeviceFingerprint fields
        for item in parsed:
            assert "schema_version" in item
            assert "protocol" in item
            assert "source_address" in item
            assert "destination_address" in item

    @pytest.mark.asyncio
    async def test_json_export_conforms_to_fingerprint_schema(self):
        """Each JSON element should conform to DeviceFingerprint schema (Requirement 10.2)."""
        session = AsyncMock()

        fp = _make_fingerprint_dict()
        devices = [_make_device(fingerprint=fp)]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        json_content = await service.export_json()

        parsed = json.loads(json_content)
        item = parsed[0]

        # Validate required DeviceFingerprint fields
        assert item["schema_version"] == "1.0.0"
        assert item["protocol"] in ["modbus_tcp", "ethernetip", "s7comm", "dnp3"]
        assert isinstance(item["source_address"], str)
        assert isinstance(item["destination_address"], str)
        assert isinstance(item.get("protocol_data", {}), dict)
        assert item["parsing_status"] in ["complete", "partial", "no_identity"]


# --- PDF Export Tests ---


class TestPDFExport:
    """Tests for PDF report functionality (Requirement 10.3)."""

    @pytest.mark.asyncio
    async def test_pdf_export_empty_report(self):
        """Empty results should state 'no devices matched' (Requirement 10.5)."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "No devices matched" in pdf_content or "no devices matched" in pdf_content.lower()

    @pytest.mark.asyncio
    async def test_pdf_export_contains_vendor_summary(self):
        """PDF report should contain device count summary by vendor (Requirement 10.3)."""
        session = AsyncMock()

        devices = [
            _make_device(ip="192.168.1.1", vendor="Siemens"),
            _make_device(ip="192.168.1.2", vendor="Siemens"),
            _make_device(ip="192.168.1.3", vendor="Allen-Bradley"),
        ]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 3

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        # Mock topology query (empty)
        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = []

        # Mock alert query (empty)
        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "DEVICE COUNT SUMMARY BY VENDOR" in pdf_content
        assert "Siemens" in pdf_content
        assert "Allen-Bradley" in pdf_content
        assert "Total Devices: 3" in pdf_content

    @pytest.mark.asyncio
    async def test_pdf_export_contains_protocol_summary(self):
        """PDF report should contain device count summary by protocol (Requirement 10.3)."""
        session = AsyncMock()

        devices = [
            _make_device(protocols=["modbus_tcp", "s7comm"]),
            _make_device(protocols=["modbus_tcp"]),
        ]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 2

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = []

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "DEVICE COUNT SUMMARY BY PROTOCOL" in pdf_content
        assert "modbus_tcp" in pdf_content

    @pytest.mark.asyncio
    async def test_pdf_export_contains_inventory_table(self):
        """PDF report should contain device inventory table (Requirement 10.3)."""
        session = AsyncMock()

        devices = [_make_device(ip="192.168.1.1", vendor="Siemens", model="S7-1200")]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = []

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "DEVICE INVENTORY TABLE" in pdf_content
        assert "192.168.1.1" in pdf_content

    @pytest.mark.asyncio
    async def test_pdf_export_contains_topology_description(self):
        """PDF report should contain topology description (Requirement 10.3)."""
        session = AsyncMock()

        devices = [_make_device(ip="192.168.1.1")]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        # Mock topology with edges
        edge = MagicMock()
        edge.source_device_id = devices[0].id
        edge.dest_device_id = uuid.uuid4()
        edge.protocol = "modbus_tcp"
        edge.packet_count = 150
        edge.last_seen = datetime(2024, 6, 15, tzinfo=timezone.utc)

        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = [edge]

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "NETWORK TOPOLOGY" in pdf_content
        assert "modbus_tcp" in pdf_content

    @pytest.mark.asyncio
    async def test_pdf_export_contains_risk_histogram(self):
        """PDF report should contain risk score histogram (Requirement 10.3)."""
        session = AsyncMock()

        devices = [
            _make_device(risk_score=10),
            _make_device(risk_score=45),
            _make_device(risk_score=85),
        ]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 3

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = []

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "RISK SCORE DISTRIBUTION" in pdf_content
        assert "0-20 (Low)" in pdf_content
        assert "81-100 (Critical)" in pdf_content

    @pytest.mark.asyncio
    async def test_pdf_export_contains_alert_summary(self):
        """PDF report should contain 30-day alert summary (Requirement 10.3)."""
        session = AsyncMock()

        devices = [_make_device()]

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        topo_result = MagicMock()
        topo_result.scalars.return_value.all.return_value = []

        # Mock alerts
        alert = MagicMock()
        alert.severity = "HIGH"
        alert.alert_type = "new_device"
        alert.generated_at = datetime.now(timezone.utc) - timedelta(days=5)

        alert_result = MagicMock()
        alert_result.scalars.return_value.all.return_value = [alert]

        session.execute = AsyncMock(
            side_effect=[count_result, data_result, topo_result, alert_result]
        )

        service = ExportService(session)
        pdf_content = await service.export_pdf()

        assert "30-DAY ALERT SUMMARY" in pdf_content
        assert "HIGH" in pdf_content
        assert "new_device" in pdf_content


# --- Record Limit Tests ---


class TestExportRecordLimit:
    """Tests for 50,000 record limit enforcement (Requirement 10.7)."""

    @pytest.mark.asyncio
    async def test_csv_rejects_over_50000_records(self):
        """CSV export should reject requests exceeding 50,000 records."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 50_001

        session.execute = AsyncMock(return_value=count_result)

        service = ExportService(session)

        with pytest.raises(ExportRecordLimitExceeded) as exc_info:
            await service.export_csv()

        assert exc_info.value.count == 50_001
        assert "50000" in str(exc_info.value) or "50,000" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_json_rejects_over_50000_records(self):
        """JSON export should reject requests exceeding 50,000 records."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 60_000

        session.execute = AsyncMock(return_value=count_result)

        service = ExportService(session)

        with pytest.raises(ExportRecordLimitExceeded) as exc_info:
            await service.export_json()

        assert exc_info.value.count == 60_000

    @pytest.mark.asyncio
    async def test_pdf_rejects_over_50000_records(self):
        """PDF export should reject requests exceeding 50,000 records."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 100_000

        session.execute = AsyncMock(return_value=count_result)

        service = ExportService(session)

        with pytest.raises(ExportRecordLimitExceeded) as exc_info:
            await service.export_pdf()

        assert exc_info.value.count == 100_000

    @pytest.mark.asyncio
    async def test_exactly_50000_records_allowed(self):
        """Exactly 50,000 records should be allowed (boundary test)."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 50_000

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        # Should not raise
        result = await service.export_json()
        parsed = json.loads(result)
        assert isinstance(parsed, list)


# --- Timeout Tests ---


class TestExportTimeout:
    """Tests for 60-second timeout enforcement (Requirement 10.6)."""

    @pytest.mark.asyncio
    async def test_csv_timeout_raises_error(self):
        """CSV export should raise ExportTimeoutError if exceeding 60 seconds."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 100

        # Simulate slow fetch by patching datetime
        devices = [_make_device() for _ in range(100)]
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)

        # Patch datetime to simulate timeout
        with patch("app.export.service.datetime") as mock_dt:
            mock_dt.now.side_effect = [
                # First call: start_time
                datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                # Second call: after fetch - already past timeout
                datetime(2024, 1, 1, 0, 1, 1, tzinfo=timezone.utc),
            ]
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            with pytest.raises(ExportTimeoutError):
                await service.export_csv()

    @pytest.mark.asyncio
    async def test_json_timeout_raises_error(self):
        """JSON export should raise ExportTimeoutError if exceeding 60 seconds."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 100

        devices = [_make_device() for _ in range(100)]
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)

        with patch("app.export.service.datetime") as mock_dt:
            mock_dt.now.side_effect = [
                datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
                datetime(2024, 1, 1, 0, 1, 1, tzinfo=timezone.utc),
            ]
            mock_dt.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            with pytest.raises(ExportTimeoutError):
                await service.export_json()


# --- Filter Tests ---


class TestExportFiltering:
    """Tests for filter parameter support (Requirement 10.4)."""

    @pytest.mark.asyncio
    async def test_csv_export_passes_filters_to_query(self):
        """Export should support same filter parameters as REST endpoints (Requirement 10.4)."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 1

        devices = [_make_device(vendor="Siemens")]
        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = devices

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        csv_content = await service.export_csv(
            vendor="Siemens",
            model="S7",
            protocol="modbus_tcp",
            risk_score_min=20,
            risk_score_max=80,
        )

        # Verify the query was executed (filters applied)
        assert session.execute.call_count == 2  # count + data query

        # Verify CSV has data
        reader = csv.DictReader(io.StringIO(csv_content))
        rows = list(reader)
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_json_export_with_filters(self):
        """JSON export should support filtering (Requirement 10.4)."""
        session = AsyncMock()

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0

        data_result = MagicMock()
        data_result.scalars.return_value.all.return_value = []

        session.execute = AsyncMock(side_effect=[count_result, data_result])

        service = ExportService(session)
        json_content = await service.export_json(
            vendor="NonExistent",
            risk_score_min=90,
        )

        parsed = json.loads(json_content)
        assert parsed == []


# --- ExportRecordLimitExceeded Tests ---


class TestExportRecordLimitExceededException:
    """Tests for the ExportRecordLimitExceeded exception."""

    def test_exception_message_contains_count(self):
        """Exception message should include the record count."""
        exc = ExportRecordLimitExceeded(75_000)
        assert "75000" in str(exc)
        assert exc.count == 75_000

    def test_exception_suggests_filters(self):
        """Exception message should suggest additional filter criteria."""
        exc = ExportRecordLimitExceeded(55_000)
        assert "filter" in str(exc).lower()


# --- ExportTimeoutError Tests ---


class TestExportTimeoutException:
    """Tests for the ExportTimeoutError exception."""

    def test_timeout_error_message(self):
        """Timeout error should mention the 60-second limit."""
        exc = ExportTimeoutError()
        assert "60" in str(exc)
