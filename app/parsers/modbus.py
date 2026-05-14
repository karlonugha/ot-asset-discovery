"""Modbus TCP protocol parser.

Parses Modbus TCP packets, specifically Read Device Identification responses
(function code 0x2B, MEI type 0x0E) to extract device identity information.

Modbus TCP frame structure:
  - MBAP Header (7 bytes):
    - Transaction ID: 2 bytes
    - Protocol ID: 2 bytes (0x0000 for Modbus)
    - Length: 2 bytes (remaining bytes including Unit ID)
    - Unit ID: 1 byte
  - PDU:
    - Function code: 1 byte (0x2B for MEI)
    - MEI type: 1 byte (0x0E for Read Device Identification)
    - Device ID code: 1 byte (read access level)
    - Conformity level: 1 byte
    - More follows: 1 byte
    - Next object ID: 1 byte
    - Number of objects: 1 byte
    - Object list:
      - Object ID: 1 byte
      - Object length: 1 byte
      - Object value: variable bytes (ASCII string)

Device Identification Object IDs (0x00-0x06):
  0x00: VendorName
  0x01: ProductCode
  0x02: MajorMinorRevision (firmware version)
  0x03: VendorUrl
  0x04: ProductName
  0x05: ModelName
  0x06: UserApplicationName

Requirements: 2.1, 2.5, 2.6
"""

import struct
from typing import Optional

from app.models.domain import DeviceFingerprint, ParseResult


# Modbus TCP constants
MODBUS_PROTOCOL_ID = 0x0000
MODBUS_FUNCTION_CODE_MEI = 0x2B
MODBUS_MEI_TYPE_DEVICE_ID = 0x0E

# Minimum sizes
MBAP_HEADER_SIZE = 7  # Transaction ID(2) + Protocol ID(2) + Length(2) + Unit ID(1)
MIN_PDU_SIZE = 2  # Function code(1) + at least 1 byte

# Device Identification Object IDs
OBJECT_ID_VENDOR_NAME = 0x00
OBJECT_ID_PRODUCT_CODE = 0x01
OBJECT_ID_MAJOR_MINOR_REVISION = 0x02
OBJECT_ID_VENDOR_URL = 0x03
OBJECT_ID_PRODUCT_NAME = 0x04
OBJECT_ID_MODEL_NAME = 0x05
OBJECT_ID_USER_APPLICATION_NAME = 0x06

# Mapping of object IDs to human-readable names
OBJECT_ID_NAMES = {
    OBJECT_ID_VENDOR_NAME: "VendorName",
    OBJECT_ID_PRODUCT_CODE: "ProductCode",
    OBJECT_ID_MAJOR_MINOR_REVISION: "MajorMinorRevision",
    OBJECT_ID_VENDOR_URL: "VendorUrl",
    OBJECT_ID_PRODUCT_NAME: "ProductName",
    OBJECT_ID_MODEL_NAME: "ModelName",
    OBJECT_ID_USER_APPLICATION_NAME: "UserApplicationName",
}


def parse_modbus(raw_bytes: bytes, source_address: str = "", destination_address: str = "") -> ParseResult:
    """Parse a Modbus TCP packet and extract device identification data.

    Args:
        raw_bytes: Raw Modbus TCP frame bytes (starting from MBAP header).
        source_address: Source IP/MAC address of the packet.
        destination_address: Destination IP/MAC address of the packet.

    Returns:
        ParseResult with fingerprint if identity data found, or appropriate
        parsing_status for non-identity or partial packets.
    """
    # Validate minimum packet size for MBAP header
    if len(raw_bytes) < MBAP_HEADER_SIZE + MIN_PDU_SIZE:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
            error="Packet too short for Modbus TCP frame",
        )

    # Parse MBAP header
    try:
        transaction_id, protocol_id, length, unit_id = struct.unpack_from(
            ">HHHB", raw_bytes, 0
        )
    except struct.error:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
            error="Failed to parse MBAP header",
        )

    # Validate Modbus protocol ID
    if protocol_id != MODBUS_PROTOCOL_ID:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
            error=f"Invalid protocol ID: 0x{protocol_id:04X}, expected 0x0000",
        )

    # Extract function code from PDU (byte after MBAP header)
    pdu_offset = MBAP_HEADER_SIZE
    function_code = raw_bytes[pdu_offset]

    # Check if this is a MEI (Read Device Identification) response
    if function_code != MODBUS_FUNCTION_CODE_MEI:
        # Valid Modbus packet but not a device identification response
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
        )

    # Check if we have enough bytes for MEI type
    if len(raw_bytes) < pdu_offset + 2:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
            error="Packet too short for MEI type",
        )

    mei_type = raw_bytes[pdu_offset + 1]

    if mei_type != MODBUS_MEI_TYPE_DEVICE_ID:
        # MEI but not Device Identification
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
        )

    # Parse Read Device Identification response
    # Expected structure after function code + MEI type:
    #   Device ID code (1 byte)
    #   Conformity level (1 byte)
    #   More follows (1 byte)
    #   Next object ID (1 byte)
    #   Number of objects (1 byte)
    #   Objects...
    response_header_offset = pdu_offset + 2  # After function code and MEI type
    min_response_header_size = 5  # device_id_code + conformity + more_follows + next_obj + num_objects

    if len(raw_bytes) < response_header_offset + min_response_header_size:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
            error="Packet too short for Device Identification response header",
        )

    device_id_code = raw_bytes[response_header_offset]
    conformity_level = raw_bytes[response_header_offset + 1]
    more_follows = raw_bytes[response_header_offset + 2]
    next_object_id = raw_bytes[response_header_offset + 3]
    num_objects = raw_bytes[response_header_offset + 4]

    # Parse device identification objects
    objects = _parse_device_id_objects(
        raw_bytes, response_header_offset + 5, num_objects
    )

    # Build fingerprint from extracted objects
    return _build_parse_result(
        objects=objects,
        unit_id=unit_id,
        function_code=function_code,
        device_id_code=device_id_code,
        conformity_level=conformity_level,
        source_address=source_address,
        destination_address=destination_address,
    )


def _parse_device_id_objects(
    raw_bytes: bytes, offset: int, num_objects: int
) -> dict[int, str]:
    """Parse device identification objects from the response payload.

    Args:
        raw_bytes: Full packet bytes.
        offset: Starting offset of the first object.
        num_objects: Number of objects declared in the response.

    Returns:
        Dictionary mapping object ID to decoded string value.
    """
    objects: dict[int, str] = {}
    current_offset = offset

    for _ in range(num_objects):
        # Each object: Object ID (1 byte) + Object Length (1 byte) + Value (variable)
        if current_offset + 2 > len(raw_bytes):
            break  # Not enough bytes for object header

        object_id = raw_bytes[current_offset]
        object_length = raw_bytes[current_offset + 1]
        current_offset += 2

        if current_offset + object_length > len(raw_bytes):
            break  # Not enough bytes for object value

        # Decode object value as ASCII/UTF-8 string
        try:
            object_value = raw_bytes[current_offset:current_offset + object_length].decode(
                "utf-8", errors="replace"
            )
            # Only store objects in the standard range (0x00-0x06)
            if 0x00 <= object_id <= 0x06:
                objects[object_id] = object_value.strip("\x00").strip()
        except (UnicodeDecodeError, ValueError):
            pass  # Skip objects that can't be decoded

        current_offset += object_length

    return objects


def _build_parse_result(
    objects: dict[int, str],
    unit_id: int,
    function_code: int,
    device_id_code: int,
    conformity_level: int,
    source_address: str,
    destination_address: str,
) -> ParseResult:
    """Build a ParseResult from extracted device identification objects.

    Maps Modbus device identification objects to DeviceFingerprint fields:
      - Object 0x00 (VendorName) -> vendor
      - Object 0x01 (ProductCode) -> model (used as product identifier)
      - Object 0x02 (MajorMinorRevision) -> firmware_version
      - Object 0x05 (ModelName) -> model (preferred over ProductCode if present)

    Args:
        objects: Parsed device identification objects (ID -> value).
        unit_id: Modbus Unit ID from MBAP header.
        function_code: Function code from PDU.
        device_id_code: Device ID code from response.
        conformity_level: Conformity level from response.
        source_address: Source address of the packet.
        destination_address: Destination address of the packet.

    Returns:
        ParseResult with appropriate parsing_status based on field completeness.
    """
    if not objects:
        # We got a valid Device Identification response but no objects were parsed
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="modbus_tcp",
            source_address=source_address,
            destination_address=destination_address,
        )

    # Map objects to fingerprint fields
    vendor = objects.get(OBJECT_ID_VENDOR_NAME)
    product_code = objects.get(OBJECT_ID_PRODUCT_CODE)
    firmware_version = objects.get(OBJECT_ID_MAJOR_MINOR_REVISION)
    model_name = objects.get(OBJECT_ID_MODEL_NAME)
    product_name = objects.get(OBJECT_ID_PRODUCT_NAME)

    # Use ModelName (0x05) as model if available, otherwise fall back to ProductCode (0x01)
    model = model_name if model_name else product_code

    # Truncate fields to max lengths per domain model constraints
    if vendor and len(vendor) > 128:
        vendor = vendor[:128]
    if model and len(model) > 128:
        model = model[:128]
    if firmware_version and len(firmware_version) > 64:
        firmware_version = firmware_version[:64]

    # Build protocol_data with all extracted objects and metadata
    protocol_data: dict = {
        "unit_id": unit_id,
        "function_code": function_code,
        "device_id_code": device_id_code,
        "conformity_level": conformity_level,
    }

    # Include all parsed objects by their standard names
    for obj_id, obj_value in objects.items():
        if obj_id in OBJECT_ID_NAMES:
            protocol_data[OBJECT_ID_NAMES[obj_id]] = obj_value

    # Determine parsing_status based on completeness of key identity fields
    # "complete" = vendor, model, and firmware all present
    # "partial" = at least one identity field present but not all three
    key_fields = [vendor, model, firmware_version]
    non_null_count = sum(1 for f in key_fields if f)

    if non_null_count == 3:
        parsing_status = "complete"
    elif non_null_count > 0:
        parsing_status = "partial"
    else:
        # This shouldn't happen since we checked objects is non-empty,
        # but handle gracefully
        parsing_status = "partial"

    fingerprint = DeviceFingerprint(
        protocol="modbus_tcp",
        source_address=source_address,
        destination_address=destination_address,
        vendor=vendor,
        model=model,
        firmware_version=firmware_version,
        device_type="PLC",  # Modbus devices are typically PLCs
        protocol_data=protocol_data,
        parsing_status=parsing_status,
    )

    return ParseResult(
        fingerprint=fingerprint,
        parsing_status=parsing_status,
        protocol="modbus_tcp",
        source_address=source_address,
        destination_address=destination_address,
    )
