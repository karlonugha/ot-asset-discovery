"""Unit tests for the S7comm protocol parser.

Tests cover:
- Parsing valid SZL responses with device identity (Requirement 2.3)
- Handling non-identity S7comm packets (Requirement 2.5)
- Handling partial/incomplete identity data (Requirement 2.6)
- Handling malformed packets gracefully
"""

import struct

import pytest

from app.parsers.s7comm import (
    MIN_S7COMM_HEADER_LENGTH,
    S7COMM_MSG_TYPE_USERDATA,
    S7COMM_PROTOCOL_ID,
    SZL_ID_COMPONENT_IDENTIFICATION,
    SZL_ID_MODULE_IDENTIFICATION,
    TPKT_VERSION,
    parse_s7comm,
)


def _build_tpkt_header(payload_length: int) -> bytes:
    """Build a TPKT header for the given payload length."""
    total_length = 4 + payload_length  # TPKT header is 4 bytes
    return struct.pack(">BBH", TPKT_VERSION, 0x00, total_length)


def _build_cotp_data_header() -> bytes:
    """Build a minimal COTP Data Transfer PDU header."""
    # Length=2, PDU type=0xF0 (Data), TPDU number=0x80 (EOT)
    return struct.pack("BBB", 0x02, 0xF0, 0x80)


def _build_s7comm_header(
    msg_type: int = S7COMM_MSG_TYPE_USERDATA,
    pdu_ref: int = 0x0001,
    param_length: int = 0,
    data_length: int = 0,
) -> bytes:
    """Build an S7comm header (10 bytes).

    Format: protocol_id(1) + msg_type(1) + reserved(2) + pdu_ref(2) + param_length(2) + data_length(2)
    """
    return struct.pack(
        ">BBHHHH",
        S7COMM_PROTOCOL_ID,  # Protocol ID (1 byte)
        msg_type,  # Message type (1 byte)
        0x0000,  # Reserved (2 bytes)
        pdu_ref,  # PDU reference (2 bytes)
        param_length,  # Parameter length (2 bytes)
        data_length,  # Data length (2 bytes)
    )


def _build_szl_userdata_params() -> bytes:
    """Build S7comm userdata parameters for an SZL read response.

    Parameter structure (12 bytes):
      Bytes 0-2: Parameter head
      Byte 3: Parameter length (remaining)
      Byte 4: Method (0x12)
      Byte 5: Type/Function (0x84 = response + CPU functions)
      Byte 6: Subfunction (0x01 = Read SZL)
      Byte 7: Sequence number
      Bytes 8-11: Additional parameter data
    """
    return struct.pack(
        ">BBBBBBBBBBBB",
        0x00, 0x01, 0x12,  # Parameter head (3 bytes)
        0x08,  # Parameter length (remaining = 8 bytes)
        0x12,  # Method
        0x84,  # Type (0x8=response) + Function group (0x4=CPU functions)
        0x01,  # Subfunction (Read SZL)
        0x00,  # Sequence number
        0x00, 0x00, 0x00, 0x00,  # Additional data
    )


def _build_szl_data_header(
    szl_id: int,
    szl_index: int = 0x0000,
    record_length: int = 28,
    record_count: int = 1,
    data_length: int = 0,
) -> bytes:
    """Build SZL data section header.

    Data section:
      Byte 0: Return code (0xFF = success)
      Byte 1: Transport size (0x09 = octet string)
      Bytes 2-3: Data length
      Bytes 4-5: SZL ID
      Bytes 6-7: SZL Index
      Bytes 8-9: Record length (length of one record)
      Bytes 10-11: Record count
    """
    if data_length == 0:
        data_length = 8 + record_length * record_count  # SZL header (8) + records
    return struct.pack(
        ">BBHHHHHH",
        0xFF,  # Return code (success)
        0x09,  # Transport size (octet string)
        data_length,  # Data length
        szl_id,  # SZL ID
        szl_index,  # SZL Index
        record_length,  # Record length
        record_count,  # Record count
        0x0000,  # Padding (not always present, but helps alignment)
    )[:-2]  # Remove the extra padding - we only need 12 bytes


def _build_szl_0011_record(
    index: int, name: str, extra: str = ""
) -> bytes:
    """Build an SZL 0x0011 (Module Identification) record (28 bytes).

    Bytes 0-1: Index
    Bytes 2-21: Name (20 bytes, null-padded)
    Bytes 22-27: Extra/serial (6 bytes, null-padded)
    """
    name_bytes = name.encode("ascii")[:20].ljust(20, b"\x00")
    extra_bytes = extra.encode("ascii")[:6].ljust(6, b"\x00")
    return struct.pack(">H", index) + name_bytes + extra_bytes


def _build_szl_001c_record(
    index: int, name: str, extra: str = ""
) -> bytes:
    """Build an SZL 0x001C (Component Identification) record (34 bytes).

    Bytes 0-1: Index
    Bytes 2-25: Component name (24 bytes, null-padded)
    Bytes 26-33: Additional info (8 bytes, null-padded)
    """
    name_bytes = name.encode("ascii")[:24].ljust(24, b"\x00")
    extra_bytes = extra.encode("ascii")[:8].ljust(8, b"\x00")
    return struct.pack(">H", index) + name_bytes + extra_bytes



def _build_complete_szl_packet(
    szl_id: int,
    records: bytes,
    record_length: int = 28,
    record_count: int = 1,
    source_ip: str = "",
    dest_ip: str = "",
) -> bytes:
    """Build a complete S7comm packet with SZL response data.

    This builds the full packet from TPKT through SZL records,
    without IP/TCP headers (those are handled by _extract_addresses).
    """
    # Build SZL data section
    data_length = 8 + len(records)  # SZL header fields (8 bytes) + records
    szl_data = struct.pack(
        ">BBHHHHH",
        0xFF,  # Return code (success)
        0x09,  # Transport size
        data_length,  # Data length
        szl_id,  # SZL ID
        0x0000,  # SZL Index
        record_length,  # Record length
        record_count,  # Record count
    ) + records

    # Build userdata parameters
    params = _build_szl_userdata_params()
    param_length = len(params)
    data_section_length = len(szl_data)

    # Build S7comm header
    s7_header = _build_s7comm_header(
        msg_type=S7COMM_MSG_TYPE_USERDATA,
        pdu_ref=0x0100,
        param_length=param_length,
        data_length=data_section_length,
    )

    # Combine S7comm header + params + data
    s7_payload = s7_header + params + szl_data

    # Build COTP header
    cotp = _build_cotp_data_header()

    # Build TPKT
    tpkt_payload = cotp + s7_payload
    tpkt = _build_tpkt_header(len(tpkt_payload))

    return tpkt + tpkt_payload


class TestS7commParserValidSZL0011:
    """Tests for valid SZL 0x0011 (Module Identification) responses (Requirement 2.3)."""

    def test_complete_module_identification(self):
        """Parse a complete SZL 0x0011 response with all identity fields."""
        records = (
            _build_szl_0011_record(1, "6ES7 315-2AG10-0AB0", "SN1234")  # Module order number + serial
            + _build_szl_0011_record(2, "CPU 315-2 DP")  # Hardware
            + _build_szl_0011_record(3, "V3.3.12")  # Firmware
        )
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=3,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "complete"
        assert result.protocol == "s7comm"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"
        assert result.fingerprint.model == "6ES7 315-2AG10-0AB0"
        assert result.fingerprint.firmware_version == "V3.3.12"
        assert result.fingerprint.serial_number == "SN1234"
        assert result.fingerprint.device_type == "PLC"
        assert result.fingerprint.protocol == "s7comm"
        assert result.fingerprint.protocol_data["module_name"] == "CPU 315-2 DP"
        assert result.fingerprint.protocol_data["szl_id"] == "0x11"

    def test_module_identification_with_firmware_in_extra(self):
        """Parse SZL 0x0011 where firmware version is in the extra field of index 3."""
        records = (
            _build_szl_0011_record(1, "6ES7 412-2EK06-0AB0", "ABC123")
            + _build_szl_0011_record(2, "CPU 412-2 PN/DP")
            + _build_szl_0011_record(3, "", "V6.0.3")  # Firmware in extra field
        )
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=3,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.model == "6ES7 412-2EK06-0AB0"
        assert result.fingerprint.firmware_version == "V6.0.3"
        assert result.fingerprint.serial_number == "ABC123"
        assert result.fingerprint.protocol_data["module_name"] == "CPU 412-2 PN/DP"


class TestS7commParserValidSZL001C:
    """Tests for valid SZL 0x001C (Component Identification) responses (Requirement 2.3)."""

    def test_complete_component_identification(self):
        """Parse a complete SZL 0x001C response with all identity fields."""
        records = (
            _build_szl_001c_record(1, "S7-300 CPU")  # PLC name
            + _build_szl_001c_record(2, "CPU 315-2 DP", "V3.3.12")  # Module name + firmware
            + _build_szl_001c_record(5, "SN-987654")  # Serial number
        )
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_COMPONENT_IDENTIFICATION,
            records=records,
            record_length=34,
            record_count=3,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "complete"
        assert result.protocol == "s7comm"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"
        assert result.fingerprint.model == "S7-300 CPU"
        assert result.fingerprint.firmware_version == "V3.3.12"
        assert result.fingerprint.serial_number == "SN-987654"
        assert result.fingerprint.device_type == "PLC"
        assert result.fingerprint.protocol_data["module_name"] == "CPU 315-2 DP"

    def test_component_identification_with_module_type_fallback(self):
        """Parse SZL 0x001C where PLC type comes from index 7 (module type) when index 1 is absent."""
        records = (
            _build_szl_001c_record(2, "ET 200SP")  # Module name
            + _build_szl_001c_record(5, "SER-12345")  # Serial
            + _build_szl_001c_record(7, "CPU 1515SP PC")  # Module type (fallback for PLC type)
        )
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_COMPONENT_IDENTIFICATION,
            records=records,
            record_length=34,
            record_count=3,
        )

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.model == "CPU 1515SP PC"  # From index 7 fallback
        assert result.fingerprint.serial_number == "SER-12345"
        assert result.fingerprint.protocol_data["module_name"] == "ET 200SP"

    def test_component_identification_serial_from_index_9(self):
        """Parse SZL 0x001C where serial number comes from index 9 (alternative location)."""
        records = (
            _build_szl_001c_record(1, "S7-1200 PLC")  # PLC name
            + _build_szl_001c_record(2, "CPU 1214C", "V4.5.0")  # Module + firmware
            + _build_szl_001c_record(9, "ALT-SN-999")  # Alternative serial
        )
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_COMPONENT_IDENTIFICATION,
            records=records,
            record_length=34,
            record_count=3,
        )

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.model == "S7-1200 PLC"
        assert result.fingerprint.serial_number == "ALT-SN-999"
        assert result.fingerprint.firmware_version == "V4.5.0"


class TestS7commParserNonIdentity:
    """Tests for non-identity S7comm packets (Requirement 2.5)."""

    def test_non_userdata_message_type(self):
        """S7comm packet with Job message type (0x01) returns no_identity."""
        # Build a minimal S7comm Job request (not userdata)
        s7_header = _build_s7comm_header(msg_type=0x01, param_length=2, data_length=0)
        s7_payload = s7_header + b"\x00\x00"  # Minimal params

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "s7comm"

    def test_userdata_non_szl_subfunction(self):
        """S7comm userdata with non-SZL subfunction returns no_identity."""
        # Build userdata params with subfunction != 0x01 (e.g., 0x02 = Write SZL)
        params = struct.pack(
            ">BBBBBBBBBBBB",
            0x00, 0x01, 0x12,  # Parameter head
            0x08,  # Parameter length
            0x12,  # Method
            0x84,  # Response + CPU functions
            0x02,  # Subfunction = Write SZL (not Read)
            0x00,  # Sequence number
            0x00, 0x00, 0x00, 0x00,
        )
        param_length = len(params)

        s7_header = _build_s7comm_header(
            msg_type=S7COMM_MSG_TYPE_USERDATA,
            param_length=param_length,
            data_length=0,
        )
        s7_payload = s7_header + params

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_userdata_non_cpu_function_group(self):
        """S7comm userdata with non-CPU function group returns no_identity."""
        # Function group 0x02 (Security) instead of 0x04 (CPU)
        params = struct.pack(
            ">BBBBBBBBBBBB",
            0x00, 0x01, 0x12,
            0x08,
            0x12,
            0x82,  # Response (0x8) + Security function group (0x2)
            0x01,
            0x00,
            0x00, 0x00, 0x00, 0x00,
        )
        param_length = len(params)

        s7_header = _build_s7comm_header(
            msg_type=S7COMM_MSG_TYPE_USERDATA,
            param_length=param_length,
            data_length=0,
        )
        s7_payload = s7_header + params

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_szl_response_with_non_identity_szl_id(self):
        """SZL response with non-identity SZL ID (e.g., 0x0111) returns no_identity."""
        # Build a valid SZL response but with a non-identity SZL ID
        szl_data = struct.pack(
            ">BBHHHHH",
            0xFF,  # Return code (success)
            0x09,  # Transport size
            16,  # Data length
            0x0111,  # SZL ID (not 0x0011 or 0x001C)
            0x0000,  # SZL Index
            8,  # Record length
            1,  # Record count
        ) + b"\x00" * 8  # Dummy record

        params = _build_szl_userdata_params()
        param_length = len(params)
        data_length = len(szl_data)

        s7_header = _build_s7comm_header(
            msg_type=S7COMM_MSG_TYPE_USERDATA,
            param_length=param_length,
            data_length=data_length,
        )
        s7_payload = s7_header + params + szl_data

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_cotp_connect_request_pdu(self):
        """COTP Connect Request PDU (non-data) returns no_identity."""
        # COTP Connect Request: length=6, PDU type=0xE0
        cotp = struct.pack("BB", 0x06, 0xE0) + b"\x00" * 5
        tpkt_payload = cotp
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestS7commParserPartialData:
    """Tests for partial/incomplete identity data (Requirement 2.6)."""

    def test_module_name_only(self):
        """SZL 0x0011 with only hardware name (index 2) produces partial status."""
        records = _build_szl_0011_record(2, "CPU 317-2 PN/DP")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.protocol_data["module_name"] == "CPU 317-2 PN/DP"
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version is None
        assert result.fingerprint.serial_number is None

    def test_plc_type_and_serial_only(self):
        """SZL 0x0011 with module order number and serial but no firmware produces partial."""
        records = _build_szl_0011_record(1, "6ES7 416-3ES06-0AB0", "SN9999")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.model == "6ES7 416-3ES06-0AB0"
        assert result.fingerprint.serial_number == "SN9999"
        assert result.fingerprint.firmware_version is None

    def test_component_plc_name_only(self):
        """SZL 0x001C with only PLC name (index 1) produces partial status."""
        records = _build_szl_001c_record(1, "MyPLC-Station")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_COMPONENT_IDENTIFICATION,
            records=records,
            record_length=34,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.model == "MyPLC-Station"
        assert result.fingerprint.firmware_version is None
        assert result.fingerprint.serial_number is None

    def test_szl_0011_empty_records(self):
        """SZL 0x0011 with records containing only null bytes returns no_identity."""
        # Build a record with all null content
        records = struct.pack(">H", 1) + b"\x00" * 20 + b"\x00" * 6
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestS7commParserMalformedPackets:
    """Tests for malformed packet handling."""

    def test_packet_too_short(self):
        """Packet shorter than TPKT header returns no_identity with error."""
        raw = b"\x03\x00"  # Only 2 bytes

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "s7comm"

    def test_invalid_tpkt_version(self):
        """Packet with invalid TPKT version returns no_identity."""
        # TPKT with version 0x04 instead of 0x03
        raw = struct.pack(">BBH", 0x04, 0x00, 10) + b"\x00" * 6

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_invalid_s7comm_protocol_id(self):
        """Packet with invalid S7comm protocol ID returns no_identity."""
        cotp = _build_cotp_data_header()
        # S7comm header with wrong protocol ID (0x33 instead of 0x32)
        s7_header = struct.pack(">BBHHHHH", 0x33, 0x07, 0, 1, 12, 0, 0)
        tpkt_payload = cotp + s7_header
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_empty_bytes(self):
        """Empty byte input returns no_identity."""
        result = parse_s7comm(b"")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "s7comm"

    def test_szl_response_with_error_return_code(self):
        """SZL response with non-success return code returns no_identity."""
        # Build SZL data with return code 0x0A (error) instead of 0xFF (success)
        szl_data = struct.pack(
            ">BBHHHHH",
            0x0A,  # Return code (error)
            0x09,
            16,
            SZL_ID_MODULE_IDENTIFICATION,
            0x0000,
            28,
            1,
        ) + b"\x00" * 28

        params = _build_szl_userdata_params()
        param_length = len(params)
        data_length = len(szl_data)

        s7_header = _build_s7comm_header(
            msg_type=S7COMM_MSG_TYPE_USERDATA,
            param_length=param_length,
            data_length=data_length,
        )
        s7_payload = s7_header + params + szl_data

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_truncated_szl_data(self):
        """SZL response with truncated data section returns no_identity."""
        # Build params but truncate the data section
        params = _build_szl_userdata_params()
        param_length = len(params)
        # Only 4 bytes of data (less than the 12 required for SZL header)
        szl_data = b"\xFF\x09\x00\x10"

        s7_header = _build_s7comm_header(
            msg_type=S7COMM_MSG_TYPE_USERDATA,
            param_length=param_length,
            data_length=len(szl_data),
        )
        s7_payload = s7_header + params + szl_data

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestS7commParserIPExtraction:
    """Tests for IP address extraction from packet headers."""

    def test_with_ipv4_header(self):
        """Parse S7comm packet with IPv4 + TCP headers extracts addresses."""
        # Build a minimal IPv4 header (20 bytes)
        # Version=4, IHL=5 (20 bytes), total length, etc.
        src_ip = (192, 168, 1, 100)
        dst_ip = (192, 168, 1, 1)

        ip_header = struct.pack(
            ">BBHHHBBH4s4s",
            0x45,  # Version 4, IHL 5
            0x00,  # DSCP/ECN
            0,  # Total length (will be filled)
            0x1234,  # Identification
            0x0000,  # Flags/Fragment offset
            64,  # TTL
            6,  # Protocol (TCP)
            0,  # Checksum
            bytes(src_ip),
            bytes(dst_ip),
        )

        # Build a minimal TCP header (20 bytes)
        tcp_header = struct.pack(
            ">HHIIBBHHH",
            102,  # Source port
            102,  # Destination port (S7comm)
            0,  # Sequence number
            0,  # Ack number
            0x50,  # Data offset (5 * 4 = 20 bytes), no flags high nibble
            0x10,  # Flags (ACK)
            65535,  # Window size
            0,  # Checksum
            0,  # Urgent pointer
        )

        # Build the S7comm payload (TPKT + COTP + S7)
        records = (
            _build_szl_0011_record(1, "6ES7 315-2AG10-0AB0", "SN1234")
            + _build_szl_0011_record(2, "CPU 315-2 DP")
            + _build_szl_0011_record(3, "V3.3.12")
        )
        s7_packet = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=3,
        )

        # Combine: IP + TCP + S7comm
        raw = ip_header + tcp_header + s7_packet

        result = parse_s7comm(raw)

        assert result.source_address == "192.168.1.100"
        assert result.destination_address == "192.168.1.1"
        assert result.fingerprint is not None
        assert result.fingerprint.source_address == "192.168.1.100"
        assert result.fingerprint.destination_address == "192.168.1.1"

    def test_without_ip_header(self):
        """Parse S7comm packet without IP header uses empty addresses."""
        records = _build_szl_0011_record(1, "6ES7 315-2AG10-0AB0", "SN1234")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        # Without IP header, addresses should be empty strings
        assert result.source_address == ""
        assert result.destination_address == ""


class TestS7commParserEdgeCases:
    """Edge case tests."""

    def test_device_type_is_plc(self):
        """S7comm devices are typed as PLC."""
        records = _build_szl_0011_record(1, "6ES7 315-2AG10-0AB0", "SN1234")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.device_type == "PLC"

    def test_vendor_is_siemens(self):
        """S7comm devices are always attributed to Siemens."""
        records = _build_szl_001c_record(1, "TestPLC")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_COMPONENT_IDENTIFICATION,
            records=records,
            record_length=34,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"

    def test_pdu_reference_in_protocol_data(self):
        """PDU reference is included in protocol_data."""
        records = _build_szl_0011_record(1, "TestModule", "SN0001")
        raw = _build_complete_szl_packet(
            szl_id=SZL_ID_MODULE_IDENTIFICATION,
            records=records,
            record_length=28,
            record_count=1,
        )

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert "pdu_reference" in result.fingerprint.protocol_data
        assert result.fingerprint.protocol_data["pdu_reference"] == 0x0100

    def test_ack_data_message_type_also_parsed(self):
        """S7comm Ack-Data message type (0x03) is also parsed for SZL data."""
        # Build with msg_type=0x03 (Ack-Data) instead of 0x07 (Userdata)
        records = _build_szl_0011_record(1, "6ES7 416-3ES06-0AB0", "SN5678")
        szl_data = struct.pack(
            ">BBHHHHH",
            0xFF, 0x09, 8 + len(records),
            SZL_ID_MODULE_IDENTIFICATION, 0x0000, 28, 1,
        ) + records

        params = _build_szl_userdata_params()
        param_length = len(params)
        data_length = len(szl_data)

        # Use Ack-Data message type (0x03)
        s7_header = _build_s7comm_header(
            msg_type=0x03,  # Ack-Data
            pdu_ref=0x0200,
            param_length=param_length,
            data_length=data_length,
        )
        s7_payload = s7_header + params + szl_data

        cotp = _build_cotp_data_header()
        tpkt_payload = cotp + s7_payload
        tpkt = _build_tpkt_header(len(tpkt_payload))
        raw = tpkt + tpkt_payload

        result = parse_s7comm(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.model == "6ES7 416-3ES06-0AB0"
        assert result.fingerprint.serial_number == "SN5678"
