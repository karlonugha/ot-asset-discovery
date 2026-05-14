"""Unit tests for the ActiveProber class.

Tests cover:
- Protocol-specific probe request building
- Timeout and retry behavior
- Concurrency limiting via semaphore
- Error handling and scan history recording
- Fingerprint result passing to Device_Inventory callback

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.8, 3.9
"""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.capture.prober import ActiveProber
from app.models.domain import DeviceFingerprint, ProbeResult, ProbeTarget


class TestActiveProberInit:
    """Tests for ActiveProber initialization."""

    def test_default_constants(self):
        """Verify default configuration constants."""
        prober = ActiveProber()
        assert prober.MAX_CONCURRENT == 10
        assert prober.TIMEOUT_SECONDS == 5.0
        assert prober.MAX_RETRIES == 1

    def test_semaphore_initialized(self):
        """Verify semaphore is initialized with MAX_CONCURRENT value."""
        prober = ActiveProber()
        # Semaphore should allow MAX_CONCURRENT acquisitions
        assert prober._semaphore._value == 10

    def test_callbacks_stored(self):
        """Verify callbacks are stored correctly."""
        on_result = AsyncMock()
        on_history = AsyncMock()
        prober = ActiveProber(on_result=on_result, on_scan_history=on_history)
        assert prober._on_result is on_result
        assert prober._on_scan_history is on_history


class TestProbeRequestBuilding:
    """Tests for protocol-specific probe request construction."""

    def setup_method(self):
        self.prober = ActiveProber()

    def test_modbus_device_id_request(self):
        """Verify Modbus Read Device Identification request structure."""
        request = self.prober._build_modbus_device_id_request()

        # MBAP Header: Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1)
        assert len(request) >= 7 + 4  # MBAP + PDU

        # Parse MBAP header
        transaction_id, protocol_id, length, unit_id = struct.unpack_from(
            ">HHHB", request, 0
        )
        assert protocol_id == 0x0000  # Modbus protocol
        assert unit_id == 0x01

        # Parse PDU
        function_code = request[7]
        mei_type = request[8]
        assert function_code == 0x2B  # MEI
        assert mei_type == 0x0E  # Read Device Identification

    def test_ethernetip_list_identity_request(self):
        """Verify EtherNet/IP List Identity request structure."""
        request = self.prober._build_ethernetip_list_identity_request()

        # Encapsulation header is 24 bytes
        assert len(request) == 24

        # Parse command (little-endian)
        command = struct.unpack_from("<H", request, 0)[0]
        assert command == 0x0063  # List Identity

        # Data length should be 0
        data_length = struct.unpack_from("<H", request, 2)[0]
        assert data_length == 0

    def test_s7comm_szl_request(self):
        """Verify S7comm SZL Read request structure."""
        request = self.prober._build_s7comm_szl_request()

        # Should start with TPKT header (version 0x03)
        assert request[0] == 0x03
        assert request[1] == 0x00  # Reserved

        # TPKT length should match actual packet length
        tpkt_length = struct.unpack_from(">H", request, 2)[0]
        assert tpkt_length == len(request)

        # After TPKT (4 bytes), COTP Data PDU type should be 0xF0
        cotp_pdu_type = request[5]
        assert cotp_pdu_type == 0xF0

    def test_dnp3_device_attributes_request(self):
        """Verify DNP3 Device Attributes request structure."""
        request = self.prober._build_dnp3_device_attributes_request()

        # Should start with DNP3 start bytes
        assert request[0:2] == b"\x05\x64"

    def test_unsupported_protocol_raises(self):
        """Verify unsupported protocol raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported protocol"):
            self.prober._build_probe_request("unknown_protocol")


class TestProbeDevice:
    """Tests for probe_device() method."""

    def setup_method(self):
        self.prober = ActiveProber()
        self.target = ProbeTarget(
            ip_address="192.168.1.100",
            protocol="modbus_tcp",
            port=502,
        )

    @pytest.mark.asyncio
    async def test_timeout_after_retries(self):
        """Verify probe returns timeout after exhausting retries (10s max)."""
        # Mock _send_probe to always time out
        async def slow_probe(target):
            await asyncio.sleep(10)  # Will be cancelled by timeout

        with patch.object(self.prober, "_send_probe", side_effect=slow_probe):
            result = await self.prober.probe_device(self.target)

        assert result.status == "timeout"
        assert result.error_code == "timeout"
        assert result.target == self.target
        # Should take approximately 10s (2 × 5s timeout)
        assert result.elapsed_ms >= 9000  # Allow some tolerance

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self):
        """Verify successful probe returns fingerprint."""
        from app.models.domain import ParseResult

        mock_fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            vendor="TestVendor",
            model="TestModel",
            firmware_version="1.0.0",
        )
        mock_result = ParseResult(
            fingerprint=mock_fingerprint,
            parsing_status="complete",
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
        )

        async def mock_send_probe(target):
            return mock_result

        with patch.object(self.prober, "_send_probe", side_effect=mock_send_probe):
            result = await self.prober.probe_device(self.target)

        assert result.status == "success"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "TestVendor"

    @pytest.mark.asyncio
    async def test_error_recorded_in_history(self):
        """Verify error results are recorded in scan history."""
        from app.models.domain import ParseResult

        on_history = AsyncMock()
        prober = ActiveProber(on_scan_history=on_history)

        mock_result = ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="",
            error="Connection refused",
        )

        async def mock_send_probe(target):
            return mock_result

        with patch.object(prober, "_send_probe", side_effect=mock_send_probe):
            result = await prober.probe_device(self.target)

        assert result.status == "error"
        assert on_history.called
        history_entry = on_history.call_args[0][0]
        assert history_entry["ip_address"] == "192.168.1.100"
        assert history_entry["status"] == "error"

    @pytest.mark.asyncio
    async def test_timeout_recorded_in_history(self):
        """Verify timeout results are recorded in scan history."""
        on_history = AsyncMock()
        prober = ActiveProber(on_scan_history=on_history)

        async def slow_probe(target):
            await asyncio.sleep(10)

        with patch.object(prober, "_send_probe", side_effect=slow_probe):
            result = await prober.probe_device(self.target)

        assert result.status == "timeout"
        assert on_history.called
        history_entry = on_history.call_args[0][0]
        assert history_entry["status"] == "timeout"

    @pytest.mark.asyncio
    async def test_fingerprint_passed_to_inventory_callback(self):
        """Verify valid fingerprints are passed to the on_result callback."""
        from app.models.domain import ParseResult

        on_result = AsyncMock()
        prober = ActiveProber(on_result=on_result)

        mock_fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            vendor="TestVendor",
        )
        mock_result = ParseResult(
            fingerprint=mock_fingerprint,
            parsing_status="complete",
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
        )

        async def mock_send_probe(target):
            return mock_result

        with patch.object(prober, "_send_probe", side_effect=mock_send_probe):
            await prober.probe_device(self.target)

        on_result.assert_called_once_with(mock_fingerprint)

    @pytest.mark.asyncio
    async def test_retry_on_first_timeout_then_success(self):
        """Verify probe retries on timeout and succeeds on second attempt."""
        from app.models.domain import ParseResult

        mock_fingerprint = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            vendor="TestVendor",
        )
        mock_result = ParseResult(
            fingerprint=mock_fingerprint,
            parsing_status="complete",
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
        )

        call_count = 0

        async def mock_send_probe(target):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                await asyncio.sleep(10)  # First attempt times out
            return mock_result

        with patch.object(prober := ActiveProber(), "_send_probe", side_effect=mock_send_probe):
            result = await prober.probe_device(self.target)

        assert result.status == "success"
        assert result.fingerprint is not None
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Verify connection errors are handled gracefully."""
        from app.models.domain import ParseResult

        mock_result = ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address="192.168.1.100",
            destination_address="",
            error="Connection failed: [Errno 111] Connection refused",
        )

        async def mock_send_probe(target):
            return mock_result

        on_history = AsyncMock()
        prober = ActiveProber(on_scan_history=on_history)

        with patch.object(prober, "_send_probe", side_effect=mock_send_probe):
            result = await prober.probe_device(self.target)

        assert result.status == "error"
        assert "Connection" in result.error_code


class TestProbeBatch:
    """Tests for probe_batch() method."""

    def setup_method(self):
        self.prober = ActiveProber()

    @pytest.mark.asyncio
    async def test_empty_batch(self):
        """Verify empty batch returns empty list."""
        results = await self.prober.probe_batch([])
        assert results == []

    @pytest.mark.asyncio
    async def test_batch_returns_results_for_all_targets(self):
        """Verify batch returns one result per target."""
        from app.models.domain import ParseResult

        targets = [
            ProbeTarget(ip_address=f"192.168.1.{i}", protocol="modbus_tcp", port=502)
            for i in range(5)
        ]

        mock_result = ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address="",
            destination_address="",
        )

        async def mock_send_probe(target):
            return mock_result

        with patch.object(self.prober, "_send_probe", side_effect=mock_send_probe):
            results = await self.prober.probe_batch(targets)

        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_concurrency_limited_to_10(self):
        """Verify no more than 10 probes execute concurrently.

        Requirements: 3.9
        """
        from app.models.domain import ParseResult

        max_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        targets = [
            ProbeTarget(ip_address=f"192.168.1.{i}", protocol="modbus_tcp", port=502)
            for i in range(25)
        ]

        mock_result = ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address="",
            destination_address="",
        )

        async def mock_send_probe(target):
            nonlocal max_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > max_concurrent:
                    max_concurrent = current_concurrent
            await asyncio.sleep(0.05)  # Simulate network delay
            async with lock:
                current_concurrent -= 1
            return mock_result

        with patch.object(self.prober, "_send_probe", side_effect=mock_send_probe):
            results = await self.prober.probe_batch(targets)

        assert len(results) == 25
        assert max_concurrent <= 10

    @pytest.mark.asyncio
    async def test_batch_continues_on_individual_errors(self):
        """Verify batch continues processing when individual probes fail.

        Requirements: 3.6
        """
        from app.models.domain import ParseResult

        targets = [
            ProbeTarget(ip_address=f"192.168.1.{i}", protocol="modbus_tcp", port=502)
            for i in range(5)
        ]

        call_count = 0

        async def mock_send_probe(target):
            nonlocal call_count
            call_count += 1
            if target.ip_address == "192.168.1.2":
                raise ConnectionRefusedError("Connection refused")
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="modbus_tcp",
                source_address=target.ip_address,
                destination_address="",
            )

        on_history = AsyncMock()
        prober = ActiveProber(on_scan_history=on_history)

        with patch.object(prober, "_send_probe", side_effect=mock_send_probe):
            results = await prober.probe_batch(targets)

        # All targets should have results
        assert len(results) == 5
        # The failed one should have error status
        error_results = [r for r in results if r.status == "error"]
        assert len(error_results) >= 1

    @pytest.mark.asyncio
    async def test_batch_handles_exceptions_gracefully(self):
        """Verify batch handles unexpected exceptions without crashing."""
        targets = [
            ProbeTarget(ip_address="192.168.1.1", protocol="modbus_tcp", port=502),
        ]

        async def mock_send_probe(target):
            raise RuntimeError("Unexpected error")

        on_history = AsyncMock()
        prober = ActiveProber(on_scan_history=on_history)

        with patch.object(prober, "_send_probe", side_effect=mock_send_probe):
            results = await prober.probe_batch(targets)

        assert len(results) == 1
        assert results[0].status == "error"


class TestDnp3CrcComputation:
    """Tests for DNP3 CRC computation."""

    def test_crc_returns_two_bytes(self):
        """Verify CRC computation returns 2 bytes."""
        prober = ActiveProber()
        crc = prober._compute_dnp3_crc(b"\x05\x64\x05\xc0\x01\x00\x03\x00")
        assert len(crc) == 2

    def test_crc_deterministic(self):
        """Verify CRC is deterministic for same input."""
        prober = ActiveProber()
        data = b"\x05\x64\x05\xc0\x01\x00\x03\x00"
        crc1 = prober._compute_dnp3_crc(data)
        crc2 = prober._compute_dnp3_crc(data)
        assert crc1 == crc2

    def test_crc_different_for_different_input(self):
        """Verify CRC differs for different inputs."""
        prober = ActiveProber()
        crc1 = prober._compute_dnp3_crc(b"\x00\x00\x00\x00")
        crc2 = prober._compute_dnp3_crc(b"\xFF\xFF\xFF\xFF")
        assert crc1 != crc2
