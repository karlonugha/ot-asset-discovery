"""Unit tests for the DNP3 protocol parser.

Tests cover:
- Parsing Object Group 0 (Device Attributes) responses with full identity data
- Parsing responses with partial identity data
- Handling non-identity DNP3 packets
- Handling malformed/invalid packets
- Address extraction from data link layer

Requirements: 2.4, 2.5, 2.6
"""

import struct

import pytest

from app.parsers.dnp3 import parse_dnp3


def _build_dnp3_frame(
    source_address: int,
    destination_address: int,
    function_code: int,
    object_data: bytes,
    iin: bytes = b"\x00\x00",
) -> bytes:
    """Helper to build a minimal DNP3 frame for testing.

    Constructs a frame with:
    - Data link layer header (start bytes, length, control, dest, source, CRC)
    - Transport layer header (FIR+FIN, sequence 0)
    - Application layer (app control, function code, IIN, object data)
    """
    # Application layer: app_control + function_code + IIN + object_data
    app_control = 0xC0  # FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
    app_layer = bytes([app_control, function_code]) + iin + object_data

    # Transport layer: FIR=1, FIN=1, SEQ=0
    transport_header = 0xC0
    user_data = bytes([transport_header]) + app_layer

    # Data link layer
    # Length = 5 (control + dest + source) + len(user_data)
    length = 5 + len(user_data)
    control = 0x44  # DIR=0, PRM=1, FCB=0, FCV=0, FC=4 (unconfirmed user data)

    header = (
        b"\x05\x64"  # Start bytes
        + bytes([length])
        + bytes([control])
        + struct.pack("<H", destination_address)
        + struct.pack("<H", source_address)
    )
    # Add CRC placeholder for header (2 bytes)
    header_with_crc = header + b"\x00\x00"

    # Data blocks: up to 16 bytes + 2 CRC each
    frame = header_with_crc
    offset = 0
    while offset < len(user_data):
        block = user_data[offset : offset + 16]
        frame += block + b"\x00\x00"  # CRC placeholder
        offset += 16

    return frame


def _build_device_attribute_object(
    variation: int, value: str, data_type: int = 1
) -> bytes:
    """Build a single DNP3 Object Group 0 device attribute object.

    Uses qualifier 0x00 with start=0, stop=0 (single object).
    Object format: data_type(1) + length(1) + value_bytes
    """
    value_bytes = value.encode("ascii")
    # Object header: group(1) + variation(1) + qualifier(1) + start(1) + stop(1)
    obj_header = bytes([0x00, variation, 0x00, 0x00, 0x00])
    # Object data: data_type(1) + length(1) + value
    obj_data = bytes([data_type, len(value_bytes)]) + value_bytes
    return obj_header + obj_data


def _build_device_attributes_response(
    source_address: int = 10,
    destination_address: int = 1,
    manufacturer: str | None = None,
    model: str | None = None,
    firmware_version: str | None = None,
    serial_number: str | None = None,
) -> bytes:
    """Build a complete DNP3 response with device attribute objects."""
    object_data = bytearray()

    if manufacturer is not None:
        object_data.extend(
            _build_device_attribute_object(252, manufacturer)
        )
    if model is not None:
        object_data.extend(
            _build_device_attribute_object(253, model)
        )
    if firmware_version is not None:
        object_data.extend(
            _build_device_attribute_object(254, firmware_version)
        )
    if serial_number is not None:
        object_data.extend(
            _build_device_attribute_object(246, serial_number)
        )

    return _build_dnp3_frame(
        source_address=source_address,
        destination_address=destination_address,
        function_code=129,  # Response
        object_data=bytes(object_data),
    )


class TestDnp3ParserCompleteIdentity:
    """Test parsing DNP3 packets with complete device identity data."""

    def test_parse_full_device_attributes(self):
        """Parse a response with all identity fields present."""
        raw = _build_device_attributes_response(
            source_address=10,
            destination_address=1,
            manufacturer="Schweitzer Engineering",
            model="SEL-751",
            firmware_version="R302-V0",
            serial_number="2021000123",
        )

        result = parse_dnp3(raw)

        assert result.protocol == "dnp3"
        assert result.source_address == "10"
        assert result.destination_address == "1"
        assert result.parsing_status == "complete"
        assert result.error is None
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Schweitzer Engineering"
        assert result.fingerprint.model == "SEL-751"
        assert result.fingerprint.firmware_version == "R302-V0"
        assert result.fingerprint.serial_number == "2021000123"
        assert result.fingerprint.protocol == "dnp3"

    def test_parse_extracts_source_and_destination_addresses(self):
        """Verify source and destination addresses are correctly extracted."""
        raw = _build_device_attributes_response(
            source_address=1024,
            destination_address=5,
            manufacturer="ABB",
            model="RTU560",
            firmware_version="5.1.0",
            serial_number="SN12345",
        )

        result = parse_dnp3(raw)

        assert result.source_address == "1024"
        assert result.destination_address == "5"
        assert result.fingerprint is not None
        assert result.fingerprint.source_address == "1024"
        assert result.fingerprint.destination_address == "5"

    def test_fingerprint_protocol_data_contains_attributes(self):
        """Verify protocol_data includes raw attribute information."""
        raw = _build_device_attributes_response(
            manufacturer="GE",
            model="D60",
            firmware_version="7.30",
            serial_number="GE001",
        )

        result = parse_dnp3(raw)

        assert result.fingerprint is not None
        assert result.fingerprint.protocol_data["function_code"] == 129
        assert result.fingerprint.protocol_data["object_group"] == 0


class TestDnp3ParserPartialIdentity:
    """Test parsing DNP3 packets with partial device identity data."""

    def test_parse_manufacturer_only(self):
        """Parse response with only manufacturer attribute."""
        raw = _build_device_attributes_response(
            source_address=20,
            destination_address=1,
            manufacturer="Siemens",
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Siemens"
        assert result.fingerprint.model is None
        assert result.fingerprint.firmware_version is None
        assert result.fingerprint.serial_number is None

    def test_parse_manufacturer_and_model_only(self):
        """Parse response with manufacturer and model but no firmware/serial."""
        raw = _build_device_attributes_response(
            manufacturer="Honeywell",
            model="C300",
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor == "Honeywell"
        assert result.fingerprint.model == "C300"
        assert result.fingerprint.firmware_version is None
        assert result.fingerprint.serial_number is None

    def test_parse_firmware_only(self):
        """Parse response with only firmware version."""
        raw = _build_device_attributes_response(
            firmware_version="2.5.1",
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "partial"
        assert result.fingerprint is not None
        assert result.fingerprint.vendor is None
        assert result.fingerprint.firmware_version == "2.5.1"


class TestDnp3ParserNoIdentity:
    """Test parsing DNP3 packets without device identity data."""

    def test_non_response_function_code(self):
        """Non-response function codes should produce no_identity."""
        # Function code 1 = READ request (not a response)
        raw = _build_dnp3_frame(
            source_address=5,
            destination_address=10,
            function_code=1,  # READ request
            object_data=b"\x00\x00\x01\x00\x00",
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.protocol == "dnp3"
        assert result.source_address == "5"
        assert result.destination_address == "10"
        assert result.error is None

    def test_response_without_group0_objects(self):
        """Response with non-Group-0 objects should produce no_identity."""
        # Object Group 30 (Analog Input), Variation 1
        object_data = bytes([30, 1, 0x00, 0x00, 0x00])
        raw = _build_dnp3_frame(
            source_address=7,
            destination_address=2,
            function_code=129,
            object_data=object_data,
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.source_address == "7"
        assert result.destination_address == "2"

    def test_response_with_empty_object_data(self):
        """Response with no object data should produce no_identity."""
        raw = _build_dnp3_frame(
            source_address=3,
            destination_address=1,
            function_code=129,
            object_data=b"",
        )

        result = parse_dnp3(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None


class TestDnp3ParserMalformedPackets:
    """Test handling of malformed or invalid DNP3 packets."""

    def test_empty_bytes(self):
        """Empty input should return error."""
        result = parse_dnp3(b"")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None
        assert result.protocol == "dnp3"

    def test_too_short_packet(self):
        """Packet shorter than minimum frame should return error."""
        result = parse_dnp3(b"\x05\x64\x05")

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None

    def test_invalid_start_bytes(self):
        """Invalid start bytes should return error."""
        raw = b"\xFF\xFF" + b"\x00" * 20

        result = parse_dnp3(raw)

        assert result.parsing_status == "no_identity"
        assert result.fingerprint is None
        assert result.error is not None
        assert "start bytes" in result.error.lower()

    def test_random_bytes(self):
        """Random bytes should not crash the parser."""
        import os
        raw = os.urandom(100)

        result = parse_dnp3(raw)

        assert result.protocol == "dnp3"
        assert result.fingerprint is None or result.fingerprint is not None
        # Should not raise an exception

    def test_truncated_frame(self):
        """Truncated frame after valid header should handle gracefully."""
        # Valid header but truncated before user data
        raw = (
            b"\x05\x64"  # Start bytes
            + b"\x0A"  # Length = 10 (implies user data)
            + b"\x44"  # Control
            + struct.pack("<H", 1)  # Destination
            + struct.pack("<H", 10)  # Source
            + b"\x00\x00"  # CRC
        )

        result = parse_dnp3(raw)

        assert result.protocol == "dnp3"
        # Should not crash - either returns no_identity or error


class TestDnp3ParserAddressRange:
    """Test DNP3 address range handling (0-65519 valid range)."""

    def test_minimum_addresses(self):
        """Test with minimum valid addresses (0)."""
        raw = _build_device_attributes_response(
            source_address=0,
            destination_address=0,
            manufacturer="Test",
            model="Device",
            firmware_version="1.0",
            serial_number="SN0",
        )

        result = parse_dnp3(raw)

        assert result.source_address == "0"
        assert result.destination_address == "0"

    def test_large_addresses(self):
        """Test with large valid addresses."""
        raw = _build_device_attributes_response(
            source_address=65000,
            destination_address=64000,
            manufacturer="Test",
            model="Device",
            firmware_version="1.0",
            serial_number="SN1",
        )

        result = parse_dnp3(raw)

        assert result.source_address == "65000"
        assert result.destination_address == "64000"
