"""Unit tests for the Modbus TCP protocol parser.

Tests cover:
- Parsing valid Read Device Identification responses (Requirement 2.1)
- Handling non-identity Modbus packets (Requirement 2.5)
- Handling partial/incomplete identity data (Requirement 2.6)
- Handling malformed packets gracefully
"""

import struct

import pytest

from app.parsers.modbus import (
    MBAP_HEADER_SIZE,
    MODBUS_FUNCTION_CODE_MEI,
    MODBUS_MEI_TYPE_DEVICE_ID,
    MODBUS_PROTOCOL_ID,
    OBJECT_ID_MAJOR_MINOR_REVISION,
    OBJECT_ID_MODEL_NAME,
    OBJECT_ID_PRODUCT_CODE,
    OBJECT_ID_VENDOR_NAME,
    parse_modbus,
)


def _build_mbap_header(
    transaction_id: int = 0x0001,
    protocol_id: int = MODBUS_PROTOCOL_ID,
    length: int = 0,
    unit_id: int = 1,
) -> bytes:
    """Build a Modbus TCP MBAP header."""
    return struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)


def _build_device_id_response(
    unit_id: int = 1,
    device_id_code: int = 0x01,
    conformity_level: int = 0x01,
    more_follows: int = 0x00,
    next_object_id: int = 0x00,
    objects: dict[int, str] | None = None,
) -> bytes:
    """Build a complete Modbus TCP Read Device Identification response packet.

    Args:
        unit_id: Modbus Unit ID.
        device_id_code: Device ID code (read access level).
        conformity_level: Conformity level.
        more_follows: Whether more objects follow.
        next_object_id: Next object ID if more follows.
        objects: Dictionary of object ID -> string value.

    Returns:
        Complete Modbus TCP frame bytes.
    """
    if objects is None:
        objects = {}

    # Build object list
    object_bytes = b""
    for obj_id, obj_value in objects.items():
        encoded_value = obj_value.encode("utf-8")
        object_bytes += struct.pack("BB", obj_id, len(encoded_value)) + encoded_value

    # Build PDU: function code + MEI type + response header + objects
    pdu = struct.pack(
        "BBBBBBB",
        MODBUS_FUNCTION_CODE_MEI,  # Function code
        MODBUS_MEI_TYPE_DEVICE_ID,  # MEI type
        device_id_code,
        conformity_level,
        more_follows,
        next_object_id,
        len(objects),  # Number of objects
    ) + object_bytes

    # MBAP header: length includes unit_id + PDU
    length = 1 + len(pdu)
    mbap = _build_mbap_header(
        transaction_id=0x0001,
        protocol_id=MODBUS_PROTOCOL_ID,
        length=length,
        unit_id=unit_id,
    )

    return mbap + pdu


class TestModbusParserValidResponses:
    """Tests for valid Read Device Identification responses (Requirement 2.1)."""

    def test_complete_device_identification(self):
        """Parse a complete response with vendor, model, and firmware."""
        objects = {
            OBJECT_ID_VENDOR_NAME: "Schneider Electric",
            OBJECT_ID_PRODUCT_CODE: "TM221CE16R",
            OBJECT_ID_MAJOR_MINOR_REVISION: "V1.3.2",
            OBJECT_ID_MODEL_NAME: "Modicon M221",
        }
        raw = _build_device_id_response(unit_id=5, objects=objects)

        result = parse_modbus(raw, source_address="192.168.1.10", destination_address="192.168.1.1")

        assert result.parsing_status == "complete"
        assert result.protocol == "modbus_tcp"
        assert result.source_address == "192.168.1.10"
        assert result.destination_address == "192.168.1.1"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Schneider Electric"
        assert result.fingerprint.model == "Modicon M221"  # ModelName preferred over ProductCode
        assert result.fingerprint.firmware_version == "V1.3.2"
        assert result.fingerprint.protocol == "modbus_tcp"
        assert result.fingerprint.protocol_data["unit_id"] == 5
        assert result.fingerprint.protocol_data["function_code"] == MODBUS_FUNCTION_CODE_MEI
        assert result.fingerprint.protocol_data["VendorName"] == "Schneider Electric"
        assert result.fingerprint.protocol_data["ProductCode"] == "TM221CE16R"

    def test_all_seven_objects(self):
        """Parse response with all 7 standard device identification objects."""
        objects = {
            0x00: "ABB",
            0x01: "AC500-eCo",
            0x02: "2.8.0",
            0x03: "https://www.abb.com",
            0x04: "AC500 PLC",
            0x05: "PM554-TP",
            0x06: "WaterTreatment",
        }
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.5", destination_address="10.0.0.1")

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "ABB"
        assert result.fingerprint.model == "PM554-TP"  # ModelName (0x05) preferred
        assert result.fingerprint.firmware_version == "2.8.0"
        assert result.fingerprint.protocol_data["VendorUrl"] == "https://www.abb.com"
        assert result.fingerprint.protocol_data["ProductName"] == "AC500 PLC"
        assert result.fingerprint.protocol_data["UserApplicationName"] == "WaterTreatment"

    def test_vendor_and_product_code_only(self):
        """Parse response with vendor and product code but no model name - uses ProductCode as model."""
        objects = {
            OBJECT_ID_VENDOR_NAME: "Siemens",
            OBJECT_ID_PRODUCT_CODE: "S7-1200",
            OBJECT_ID_MAJOR_MINOR_REVISION: "4.5.1",
        }
        raw = _build_device_id_response(unit_id=2, objects=objects)

        result = parse_modbus(raw, source_address="192.168.0.100", destination_address="192.168.0.1")

        assert result.parsing_status == "complete"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"
        assert result.fingerprint.model == "S7-1200"  # Falls back to ProductCode
        assert result.fingerprint.firmware_version == "4.5.1"

    def test_unit_id_extraction(self):
        """Verify Unit ID is correctly extracted from MBAP header."""
        objects = {OBJECT_ID_VENDOR_NAME: "TestVendor"}
        raw = _build_device_id_response(unit_id=247, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.fingerprint is not None
        assert result.fingerprint.protocol_data["unit_id"] == 247


class TestModbusParserNonIdentity:
    """Tests for non-identity Modbus packets (Requirement 2.5)."""

    def test_non_mei_function_code(self):
        """Modbus packet with non-MEI function code returns no_identity."""
        # Build a Read Holding Registers response (function code 0x03)
        pdu = struct.pack("BBH", 0x03, 0x02, 0x1234)  # FC=3, byte count=2, data
        length = 1 + len(pdu)
        mbap = _build_mbap_header(length=length, unit_id=1)
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="192.168.1.10", destination_address="192.168.1.1")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "modbus_tcp"
        assert result.source_address == "192.168.1.10"
        assert result.destination_address == "192.168.1.1"
        assert result.error is None

    def test_mei_non_device_id_type(self):
        """MEI packet with non-device-identification MEI type returns no_identity."""
        # MEI type 0x0D (CANopen General Reference)
        pdu = struct.pack("BB", MODBUS_FUNCTION_CODE_MEI, 0x0D) + b"\x00" * 5
        length = 1 + len(pdu)
        mbap = _build_mbap_header(length=length, unit_id=1)
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is None

    def test_write_single_register(self):
        """Write Single Register (FC 0x06) returns no_identity."""
        pdu = struct.pack(">BHH", 0x06, 0x0001, 0x0003)  # FC=6, register, value
        length = 1 + len(pdu)
        mbap = _build_mbap_header(length=length, unit_id=1)
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestModbusParserPartialData:
    """Tests for partial/incomplete identity data (Requirement 2.6)."""

    def test_vendor_only(self):
        """Response with only vendor name produces partial status."""
        objects = {OBJECT_ID_VENDOR_NAME: "Rockwell Automation"}
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Rockwell Automation"
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version is None

    def test_firmware_only(self):
        """Response with only firmware version produces partial status."""
        objects = {OBJECT_ID_MAJOR_MINOR_REVISION: "3.2.1"}
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor is None
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version == "3.2.1"

    def test_vendor_and_firmware_no_model(self):
        """Response with vendor and firmware but no model produces partial status."""
        objects = {
            OBJECT_ID_VENDOR_NAME: "Honeywell",
            OBJECT_ID_MAJOR_MINOR_REVISION: "R430.1",
        }
        raw = _build_device_id_response(unit_id=3, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Honeywell"
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version == "R430.1"

    def test_empty_objects_in_response(self):
        """Response with zero objects returns no_identity."""
        raw = _build_device_id_response(unit_id=1, objects={})

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestModbusParserMalformedPackets:
    """Tests for malformed packet handling."""

    def test_packet_too_short(self):
        """Packet shorter than MBAP header returns error."""
        raw = b"\x00\x01\x00\x00"  # Only 4 bytes

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None
        assert "too short" in result.error.lower()

    def test_invalid_protocol_id(self):
        """Packet with non-Modbus protocol ID returns error."""
        mbap = _build_mbap_header(protocol_id=0x1234, length=3, unit_id=1)
        pdu = struct.pack("BB", 0x2B, 0x0E)
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None
        assert "protocol ID" in result.error

    def test_truncated_device_id_response(self):
        """Device ID response truncated before objects returns no_identity."""
        # Build MBAP + function code + MEI type but truncate response header
        mbap = _build_mbap_header(length=4, unit_id=1)
        pdu = struct.pack("BB", MODBUS_FUNCTION_CODE_MEI, MODBUS_MEI_TYPE_DEVICE_ID)
        # Only 1 byte of response header instead of required 5
        pdu += b"\x01"
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_truncated_object_value(self):
        """Object with declared length exceeding available bytes is skipped."""
        # Build a response where object claims 20 bytes but only 5 are available
        mbap = _build_mbap_header(length=20, unit_id=1)
        pdu = struct.pack(
            "BBBBBBB",
            MODBUS_FUNCTION_CODE_MEI,
            MODBUS_MEI_TYPE_DEVICE_ID,
            0x01,  # device_id_code
            0x01,  # conformity_level
            0x00,  # more_follows
            0x00,  # next_object_id
            0x01,  # num_objects = 1
        )
        # Object header says 20 bytes but we only provide 5
        pdu += struct.pack("BB", 0x00, 20) + b"Short"
        raw = mbap + pdu

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        # Should handle gracefully - no objects parsed means no_identity
        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None

    def test_empty_bytes(self):
        """Empty byte input returns error."""
        result = parse_modbus(b"", source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None


class TestModbusParserEdgeCases:
    """Edge case tests."""

    def test_long_vendor_name_truncated(self):
        """Vendor name exceeding 128 chars is truncated."""
        long_vendor = "A" * 200
        objects = {
            OBJECT_ID_VENDOR_NAME: long_vendor,
            OBJECT_ID_PRODUCT_CODE: "Model1",
            OBJECT_ID_MAJOR_MINOR_REVISION: "1.0.0",
        }
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.fingerprint is not None
        assert len(result.fingerprint.vendor) == 128

    def test_null_terminated_strings(self):
        """Object values with null terminators are stripped."""
        objects = {
            OBJECT_ID_VENDOR_NAME: "Siemens\x00\x00",
            OBJECT_ID_PRODUCT_CODE: "S7-300\x00",
            OBJECT_ID_MAJOR_MINOR_REVISION: "6.0.3",
        }
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"
        assert result.fingerprint.model == "S7-300"

    def test_device_type_is_plc(self):
        """Modbus devices are typed as PLC."""
        objects = {OBJECT_ID_VENDOR_NAME: "TestVendor"}
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(raw, source_address="10.0.0.1", destination_address="10.0.0.2")

        assert result.fingerprint is not None
        assert result.fingerprint.device_type == "PLC"

    def test_source_and_destination_preserved(self):
        """Source and destination addresses are preserved in result."""
        objects = {OBJECT_ID_VENDOR_NAME: "TestVendor"}
        raw = _build_device_id_response(unit_id=1, objects=objects)

        result = parse_modbus(
            raw,
            source_address="192.168.100.50",
            destination_address="192.168.100.1",
        )

        assert result.source_address == "192.168.100.50"
        assert result.destination_address == "192.168.100.1"
        assert result.fingerprint.source_address == "192.168.100.50"
        assert result.fingerprint.destination_address == "192.168.100.1"
