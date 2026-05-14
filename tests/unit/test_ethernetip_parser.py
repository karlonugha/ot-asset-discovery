"""Unit tests for the EtherNet/IP protocol parser.

Tests cover:
- Complete CIP Identity parsing (Requirement 2.2)
- Non-identity packet handling (Requirement 2.5)
- Partial/incomplete identity data (Requirement 2.6)
- Malformed packet handling (Requirement 1.4)
"""

import struct

import pytest

from app.parsers.ethernetip import (
    ENCAP_CMD_LIST_IDENTITY,
    ENCAP_CMD_REGISTER_SESSION,
    ENCAP_CMD_SEND_RR_DATA,
    ENCAP_HEADER_SIZE,
    CIP_ITEM_ID_LIST_IDENTITY,
    parse_ethernetip,
)


def _build_encap_header(
    command: int = ENCAP_CMD_LIST_IDENTITY,
    length: int = 0,
    session_handle: int = 0,
    status: int = 0,
    sender_context: bytes = b"\x00" * 8,
    options: int = 0,
) -> bytes:
    """Build an EtherNet/IP encapsulation header."""
    header = struct.pack("<HHI I", command, length, session_handle, status)
    header += sender_context
    header += struct.pack("<I", options)
    return header


def _build_socket_address(
    ip: str = "192.168.1.100", port: int = 44818
) -> bytes:
    """Build a 16-byte socket address structure."""
    ip_parts = [int(p) for p in ip.split(".")]
    addr = struct.pack(">H", 2)  # sin_family = AF_INET
    addr += struct.pack(">H", port)  # sin_port
    addr += bytes(ip_parts)  # sin_addr
    addr += b"\x00" * 8  # sin_zero
    return addr


def _build_cip_identity_item(
    vendor_id: int = 1,
    device_type: int = 0x0E,
    product_code: int = 100,
    revision_major: int = 3,
    revision_minor: int = 5,
    serial_number: int = 0xDEADBEEF,
    product_name: str = "Test PLC",
    ip: str = "192.168.1.100",
    state: int = 0,
) -> bytes:
    """Build a complete CIP Identity item data (without item type/length header)."""
    data = struct.pack("<H", 1)  # Encapsulation Protocol Version
    data += _build_socket_address(ip)
    data += struct.pack("<H", vendor_id)
    data += struct.pack("<H", device_type)
    data += struct.pack("<H", product_code)
    data += struct.pack("BB", revision_major, revision_minor)
    data += struct.pack("<H", 0)  # Status
    data += struct.pack("<I", serial_number)
    name_bytes = product_name.encode("ascii")
    data += struct.pack("B", len(name_bytes))
    data += name_bytes
    data += struct.pack("B", state)
    return data


def _build_list_identity_response(
    vendor_id: int = 1,
    device_type: int = 0x0E,
    product_code: int = 100,
    revision_major: int = 3,
    revision_minor: int = 5,
    serial_number: int = 0xDEADBEEF,
    product_name: str = "Test PLC",
    ip: str = "192.168.1.100",
) -> bytes:
    """Build a complete List Identity response packet."""
    # Build CIP Identity item data
    identity_data = _build_cip_identity_item(
        vendor_id=vendor_id,
        device_type=device_type,
        product_code=product_code,
        revision_major=revision_major,
        revision_minor=revision_minor,
        serial_number=serial_number,
        product_name=product_name,
        ip=ip,
    )

    # Build item header: type + length
    item_header = struct.pack("<HH", CIP_ITEM_ID_LIST_IDENTITY, len(identity_data))

    # Build response data: item count + items
    response_data = struct.pack("<H", 1)  # Item count = 1
    response_data += item_header + identity_data

    # Build encapsulation header
    header = _build_encap_header(
        command=ENCAP_CMD_LIST_IDENTITY,
        length=len(response_data),
    )

    return header + response_data


class TestParseEthernetIPComplete:
    """Tests for complete CIP Identity parsing (Requirement 2.2)."""

    def test_parse_complete_identity(self):
        """Parse a complete List Identity response with all fields."""
        packet = _build_list_identity_response(
            vendor_id=1,
            device_type=0x0E,  # PLC
            product_code=100,
            revision_major=3,
            revision_minor=5,
            serial_number=0xDEADBEEF,
            product_name="1756-L71 ControlLogix",
            ip="192.168.1.100",
        )

        result = parse_ethernetip(packet)

        assert result.parsing_status == "complete"
        assert result.protocol == "ethernetip"
        assert result.error is None
        assert result.fingerprint is not None

        fp = result.fingerprint
        assert fp.protocol == "ethernetip"
        assert fp.vendor == "VendorID:1"
        assert fp.model == "1756-L71 ControlLogix"
        assert fp.firmware_version == "3.5"
        assert fp.serial_number == "DEADBEEF"
        assert fp.device_type == "PLC"
        assert fp.ip_address == "192.168.1.100"
        assert fp.source_address == "192.168.1.100"
        assert fp.parsing_status == "complete"
        assert fp.schema_version == "1.0.0"

    def test_parse_identity_with_hmi_device_type(self):
        """Parse identity with HMI device type code."""
        packet = _build_list_identity_response(
            vendor_id=42,
            device_type=0x12,  # HMI
            product_code=200,
            revision_major=2,
            revision_minor=1,
            serial_number=0x12345678,
            product_name="PanelView Plus",
            ip="10.0.0.50",
        )

        result = parse_ethernetip(packet)

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.device_type == "HMI"
        assert result.fingerprint.vendor == "VendorID:42"
        assert result.fingerprint.model == "PanelView Plus"
        assert result.fingerprint.firmware_version == "2.1"
        assert result.fingerprint.serial_number == "12345678"

    def test_parse_identity_with_rtu_device_type(self):
        """Parse identity with RTU/Adapter device type code."""
        packet = _build_list_identity_response(
            vendor_id=5,
            device_type=0x21,  # Adapter/RTU
            product_code=50,
            revision_major=1,
            revision_minor=0,
            serial_number=0xAABBCCDD,
            product_name="Remote I/O Adapter",
            ip="172.16.0.10",
        )

        result = parse_ethernetip(packet)

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.device_type == "RTU"

    def test_parse_identity_unknown_device_type(self):
        """Parse identity with unknown device type code returns None for device_type."""
        packet = _build_list_identity_response(
            vendor_id=99,
            device_type=0xFF,  # Unknown
            product_code=1,
            revision_major=1,
            revision_minor=1,
            serial_number=0x11111111,
            product_name="Unknown Device",
        )

        result = parse_ethernetip(packet)

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.device_type is None

    def test_protocol_data_contains_raw_values(self):
        """Verify protocol_data contains raw numeric values."""
        packet = _build_list_identity_response(
            vendor_id=1,
            device_type=0x0E,
            product_code=100,
            revision_major=3,
            revision_minor=5,
            serial_number=0xDEADBEEF,
            product_name="Test",
        )

        result = parse_ethernetip(packet)

        assert result.fingerprint is not None
        pd = result.fingerprint.protocol_data
        assert pd["vendor_id"] == 1
        assert pd["device_type_code"] == 0x0E
        assert pd["product_code"] == 100
        assert pd["revision_major"] == 3
        assert pd["revision_minor"] == 5
        assert pd["serial_number_raw"] == 0xDEADBEEF

    def test_parse_empty_product_name(self):
        """Parse identity with empty product name."""
        packet = _build_list_identity_response(
            vendor_id=1,
            device_type=0x0E,
            product_code=100,
            revision_major=1,
            revision_minor=0,
            serial_number=0x00000001,
            product_name="",
        )

        result = parse_ethernetip(packet)

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        # Empty product name means model is None
        assert result.fingerprint.model is None


class TestParseEthernetIPNoIdentity:
    """Tests for non-identity packet handling (Requirement 2.5)."""

    def test_register_session_command(self):
        """Register Session command has no identity data."""
        header = _build_encap_header(
            command=ENCAP_CMD_REGISTER_SESSION,
            length=4,
        )
        data = struct.pack("<HH", 1, 0)  # Protocol version, options
        packet = header + data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "ethernetip"
        assert result.error is None

    def test_send_rr_data_command(self):
        """SendRRData command has no identity data."""
        header = _build_encap_header(
            command=ENCAP_CMD_SEND_RR_DATA,
            length=0,
        )

        result = parse_ethernetip(header)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "ethernetip"
        assert result.error is None

    def test_list_identity_with_zero_items(self):
        """List Identity response with zero items."""
        response_data = struct.pack("<H", 0)  # Item count = 0
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is None

    def test_list_identity_with_non_identity_item_type(self):
        """List Identity response with non-CIP-Identity item type."""
        # Build an item with a different type (e.g., 0x0001)
        item_data = b"\x00" * 10
        item_header = struct.pack("<HH", 0x0001, len(item_data))
        response_data = struct.pack("<H", 1) + item_header + item_data
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestParseEthernetIPPartial:
    """Tests for partial/incomplete identity data (Requirement 2.6)."""

    def test_truncated_after_vendor_id(self):
        """Identity item truncated after vendor ID - partial result."""
        # Build partial identity data: protocol version + socket addr + vendor ID only
        identity_data = struct.pack("<H", 1)  # Protocol version
        identity_data += _build_socket_address("192.168.1.50")
        identity_data += struct.pack("<H", 7)  # Vendor ID
        # Truncated here - no device type, product code, etc.

        item_header = struct.pack("<HH", CIP_ITEM_ID_LIST_IDENTITY, len(identity_data))
        response_data = struct.pack("<H", 1) + item_header + identity_data
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "VendorID:7"
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version is None
        assert result.fingerprint.serial_number is None
        assert result.fingerprint.parsing_status == "partial"

    def test_truncated_after_revision(self):
        """Identity item truncated after revision - partial result with firmware."""
        identity_data = struct.pack("<H", 1)  # Protocol version
        identity_data += _build_socket_address("10.0.0.1")
        identity_data += struct.pack("<H", 1)  # Vendor ID
        identity_data += struct.pack("<H", 0x0E)  # Device Type (PLC)
        identity_data += struct.pack("<H", 55)  # Product Code
        identity_data += struct.pack("BB", 4, 2)  # Revision 4.2
        # Truncated here - no status, serial, name

        item_header = struct.pack("<HH", CIP_ITEM_ID_LIST_IDENTITY, len(identity_data))
        response_data = struct.pack("<H", 1) + item_header + identity_data
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "VendorID:1"
        assert result.fingerprint.firmware_version == "4.2"
        assert result.fingerprint.device_type == "PLC"
        assert result.fingerprint.serial_number is None
        assert result.fingerprint.model is None

    def test_truncated_product_name(self):
        """Identity item with truncated product name - partial result."""
        identity_data = struct.pack("<H", 1)  # Protocol version
        identity_data += _build_socket_address("192.168.1.10")
        identity_data += struct.pack("<H", 1)  # Vendor ID
        identity_data += struct.pack("<H", 0x0E)  # Device Type
        identity_data += struct.pack("<H", 100)  # Product Code
        identity_data += struct.pack("BB", 2, 0)  # Revision
        identity_data += struct.pack("<H", 0)  # Status
        identity_data += struct.pack("<I", 0xCAFEBABE)  # Serial
        identity_data += struct.pack("B", 20)  # Name length = 20
        identity_data += b"Truncated"  # Only 9 bytes of 20

        item_header = struct.pack("<HH", CIP_ITEM_ID_LIST_IDENTITY, len(identity_data))
        response_data = struct.pack("<H", 1) + item_header + identity_data
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.serial_number == "CAFEBABE"
        assert result.fingerprint.firmware_version == "2.0"


class TestParseEthernetIPMalformed:
    """Tests for malformed packet handling (Requirement 1.4)."""

    def test_empty_bytes(self):
        """Empty byte sequence."""
        result = parse_ethernetip(b"")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None
        assert "too short" in result.error.lower()

    def test_too_short_for_header(self):
        """Packet shorter than encapsulation header."""
        result = parse_ethernetip(b"\x63\x00\x04\x00")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None

    def test_declared_length_exceeds_packet(self):
        """Encapsulation header declares more data than available."""
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=1000,  # Claims 1000 bytes of data
        )
        # But only provide the header with no data
        result = parse_ethernetip(header)

        assert result.parsing_status == "no_identity"
        assert result.error is not None

    def test_list_identity_too_short_for_item_count(self):
        """List Identity response data too short for item count."""
        response_data = b"\x01"  # Only 1 byte, need 2 for item count
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        assert result.parsing_status == "no_identity"
        assert result.error is not None

    def test_identity_item_too_short_for_socket_address(self):
        """CIP Identity item too short to contain socket address."""
        # Only protocol version (2 bytes), no socket address
        identity_data = struct.pack("<H", 1)

        item_header = struct.pack("<HH", CIP_ITEM_ID_LIST_IDENTITY, len(identity_data))
        response_data = struct.pack("<H", 1) + item_header + identity_data
        header = _build_encap_header(
            command=ENCAP_CMD_LIST_IDENTITY,
            length=len(response_data),
        )
        packet = header + response_data

        result = parse_ethernetip(packet)

        # Should return no_identity since no fields could be extracted
        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_source_and_dest_addresses_populated(self):
        """Verify source and destination addresses are always populated for valid packets."""
        header = _build_encap_header(
            command=ENCAP_CMD_SEND_RR_DATA,
            length=0,
            session_handle=12345,
        )

        result = parse_ethernetip(header)

        assert result.source_address != ""
        assert result.destination_address != ""
        assert "12345" in result.destination_address
