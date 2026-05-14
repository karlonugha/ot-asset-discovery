"""DNP3 protocol parser for OT Asset Discovery.

Parses DNP3 (Distributed Network Protocol 3) packets to extract device identity
information from Object Group 0 (Device Attributes) responses.

DNP3 Frame Structure (simplified):
- Data Link Layer: Start bytes (0x0564), length, control, destination, source
- Transport Layer: Transport header byte
- Application Layer: Application control, function code, object headers + data

Object Group 0 (Device Attributes) contains device identity information such as
manufacturer name, device model, firmware version, and serial number.

Requirements: 2.4, 2.5, 2.6
"""

import struct
from typing import Optional

from app.models.domain import DeviceFingerprint, ParseResult


# DNP3 constants
DNP3_START_BYTES = b"\x05\x64"
DNP3_MIN_FRAME_LENGTH = 10  # Minimum valid DNP3 data link layer frame

# DNP3 Function Codes
FC_RESPONSE = 129  # 0x81 - Response function code

# DNP3 Object Group 0 - Device Attributes
OBJECT_GROUP_DEVICE_ATTRIBUTES = 0

# Device Attribute Variations (Object Group 0)
# These map to specific device identity fields
VARIATION_MANUFACTURER_NAME = 252  # Manufacturer/Vendor name
VARIATION_DEVICE_MODEL = 253  # Device model
VARIATION_FIRMWARE_VERSION = 254  # Firmware version
VARIATION_SERIAL_NUMBER = 246  # Serial number
VARIATION_DEVICE_ID = 245  # Device ID string
VARIATION_HARDWARE_VERSION = 251  # Hardware version
VARIATION_LOCATION = 250  # Device location

# Data type codes for Device Attribute objects
DATA_TYPE_VISIBLE_STRING = 1  # Visible string (ASCII)
DATA_TYPE_UNSIGNED_INT = 2  # Unsigned integer
DATA_TYPE_SIGNED_INT = 3  # Signed integer
DATA_TYPE_FLOATING_POINT = 4  # Floating point
DATA_TYPE_OCTET_STRING = 5  # Octet string (binary)
DATA_TYPE_BIT_STRING = 6  # Bit string


def parse_dnp3(raw_bytes: bytes) -> ParseResult:
    """Parse a DNP3 packet and extract device identity information.

    Handles Object Group 0 (Device Attributes) responses to extract
    manufacturer, model, firmware version, and serial number.

    Args:
        raw_bytes: Raw packet bytes starting from the DNP3 data link layer.

    Returns:
        ParseResult with fingerprint if identity data found, or with
        parsing_status "no_identity" if the packet doesn't contain
        device attribute data.
    """
    try:
        return _parse_dnp3_internal(raw_bytes)
    except Exception as e:
        # Malformed packet - return error indication
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address="unknown",
            destination_address="unknown",
            error=f"Failed to parse DNP3 packet: {str(e)}",
        )


def _parse_dnp3_internal(raw_bytes: bytes) -> ParseResult:
    """Internal DNP3 parsing logic.

    Raises exceptions on malformed data which are caught by the outer function.
    """
    if len(raw_bytes) < DNP3_MIN_FRAME_LENGTH:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address="unknown",
            destination_address="unknown",
            error=f"Packet too short for DNP3 frame: {len(raw_bytes)} bytes",
        )

    # Parse Data Link Layer header
    start_bytes = raw_bytes[0:2]
    if start_bytes != DNP3_START_BYTES:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address="unknown",
            destination_address="unknown",
            error=f"Invalid DNP3 start bytes: {start_bytes.hex()}",
        )

    # Data Link Layer fields
    # Byte 2: Length (number of octets following, excluding CRC)
    length = raw_bytes[2]
    # Byte 3: Control byte
    control = raw_bytes[3]
    # Bytes 4-5: Destination address (little-endian)
    destination_address = struct.unpack_from("<H", raw_bytes, 4)[0]
    # Bytes 6-7: Source address (little-endian)
    source_address = struct.unpack_from("<H", raw_bytes, 6)[0]

    source_addr_str = str(source_address)
    dest_addr_str = str(destination_address)

    # After the 8-byte header + 2-byte CRC = 10 bytes for data link layer header
    # The remaining data contains transport + application layers
    # In real DNP3, data blocks are 16 bytes each followed by 2-byte CRC
    # For parsing purposes, we'll extract the user data (removing CRCs)
    user_data = _extract_user_data(raw_bytes)

    if user_data is None or len(user_data) < 2:
        # Valid DNP3 frame but no application layer data
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    # Parse Transport Layer (first byte of user data)
    # Bit 7: FIN (final fragment), Bit 6: FIR (first fragment), Bits 0-5: sequence
    transport_header = user_data[0]
    app_data = user_data[1:]

    if len(app_data) < 2:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    # Parse Application Layer
    # Byte 0: Application control (FIR, FIN, CON, UNS, sequence)
    # Byte 1: Function code
    app_control = app_data[0]
    function_code = app_data[1]

    # We're looking for Response messages (FC 129 / 0x81)
    if function_code != FC_RESPONSE:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    # Parse object headers from the response
    # Skip application control (1 byte) + function code (1 byte) + IIN (2 bytes)
    if len(app_data) < 4:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    # Internal Indications (IIN) - 2 bytes after function code
    object_data = app_data[4:]  # Skip app_control + FC + IIN1 + IIN2

    # Parse device attributes from Object Group 0
    attributes = _parse_device_attributes(object_data)

    if not attributes:
        # Valid DNP3 response but no device attribute objects
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    # Build DeviceFingerprint from extracted attributes
    vendor = attributes.get("manufacturer")
    model = attributes.get("model")
    firmware_version = attributes.get("firmware_version")
    serial_number = attributes.get("serial_number")

    # Determine parsing status based on field completeness
    identity_fields = [vendor, model, firmware_version, serial_number]
    non_null_count = sum(1 for f in identity_fields if f is not None)

    if non_null_count == 0:
        # We have device attribute objects but couldn't extract identity fields
        parsing_status = "no_identity"
        fingerprint = None
    elif non_null_count < len(identity_fields):
        parsing_status = "partial"
    else:
        parsing_status = "complete"

    # Build protocol_data with all raw attributes
    protocol_data = {
        "function_code": function_code,
        "object_group": OBJECT_GROUP_DEVICE_ATTRIBUTES,
    }
    # Include all extracted attributes in protocol_data
    for key, value in attributes.items():
        protocol_data[f"attr_{key}"] = value

    if parsing_status == "no_identity":
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="dnp3",
            source_address=source_addr_str,
            destination_address=dest_addr_str,
            error=None,
        )

    fingerprint = DeviceFingerprint(
        protocol="dnp3",
        source_address=source_addr_str,
        destination_address=dest_addr_str,
        vendor=_truncate(vendor, 128),
        model=_truncate(model, 128),
        firmware_version=_truncate(firmware_version, 64),
        serial_number=serial_number,
        device_type=None,  # DNP3 doesn't directly specify PLC/RTU/HMI/IED
        protocol_data=protocol_data,
        parsing_status=parsing_status,
    )

    return ParseResult(
        fingerprint=fingerprint,
        parsing_status=parsing_status,
        protocol="dnp3",
        source_address=source_addr_str,
        destination_address=dest_addr_str,
        error=None,
    )


def _extract_user_data(raw_bytes: bytes) -> Optional[bytes]:
    """Extract user data from DNP3 frame, removing CRC bytes.

    DNP3 data link layer format:
    - Header block: 10 bytes (start[2] + length[1] + control[1] + dest[2] + source[2] + CRC[2])
    - Data blocks: up to 16 bytes of data + 2 bytes CRC each

    Returns the concatenated user data with CRCs stripped, or None if invalid.
    """
    if len(raw_bytes) < DNP3_MIN_FRAME_LENGTH:
        return None

    # The length field indicates bytes in the frame after length byte,
    # not counting CRCs. It includes control + dest + source + user data.
    length = raw_bytes[2]

    # Skip the 10-byte header block (including its CRC)
    if len(raw_bytes) <= 10:
        return None

    # Extract data blocks (each is up to 16 data bytes + 2 CRC bytes)
    user_data = bytearray()
    offset = 10  # Start after header block (8 header + 2 CRC)

    # Calculate expected user data length from the length field
    # length = 5 (control + dest + source) + user_data_length
    user_data_length = length - 5
    if user_data_length <= 0:
        return None

    remaining = user_data_length
    while offset < len(raw_bytes) and remaining > 0:
        # Each data block is up to 16 bytes + 2 CRC bytes
        block_size = min(16, remaining)
        if offset + block_size > len(raw_bytes):
            # Take what's available
            block_size = len(raw_bytes) - offset

        user_data.extend(raw_bytes[offset : offset + block_size])
        remaining -= block_size
        offset += block_size + 2  # Skip CRC after each block

    return bytes(user_data) if user_data else None


def _parse_device_attributes(data: bytes) -> dict[str, str]:
    """Parse DNP3 Object Group 0 (Device Attributes) from object data.

    Object header format for Group 0:
    - Byte 0: Object group (0x00 for Device Attributes)
    - Byte 1: Variation (identifies which attribute)
    - Byte 2: Qualifier code (determines how objects are indexed)
    - Following bytes: range specifier and object data

    Returns a dictionary of extracted attribute name -> value mappings.
    """
    attributes: dict[str, str] = {}
    offset = 0

    while offset + 3 <= len(data):
        # Read object header
        group = data[offset]
        variation = data[offset + 1]
        qualifier = data[offset + 2]
        offset += 3

        # Only process Object Group 0 (Device Attributes)
        if group != OBJECT_GROUP_DEVICE_ATTRIBUTES:
            # Try to skip this object - we don't know its size so we stop
            break

        # Parse based on qualifier code
        # Qualifier 0x00: 1-byte start/stop range (index)
        # Qualifier 0x17: 1-byte count, 1-byte index prefix
        # Qualifier 0x5B: 1-byte count, variable-size objects with length prefix
        if qualifier == 0x00:
            # 1-byte start, 1-byte stop range
            if offset + 2 > len(data):
                break
            start_index = data[offset]
            stop_index = data[offset + 1]
            offset += 2
            count = stop_index - start_index + 1

            for _ in range(count):
                value, offset = _read_device_attribute_value(data, offset)
                if value is not None:
                    attr_name = _variation_to_attribute_name(variation)
                    if attr_name:
                        attributes[attr_name] = value

        elif qualifier == 0x17:
            # 1-byte count with 1-byte object prefix (index)
            if offset + 1 > len(data):
                break
            count = data[offset]
            offset += 1

            for _ in range(count):
                if offset + 1 > len(data):
                    break
                # Skip index prefix byte
                offset += 1
                value, offset = _read_device_attribute_value(data, offset)
                if value is not None:
                    attr_name = _variation_to_attribute_name(variation)
                    if attr_name:
                        attributes[attr_name] = value

        elif qualifier == 0x5B:
            # 1-byte count, variable-size objects with 2-byte length prefix
            if offset + 1 > len(data):
                break
            count = data[offset]
            offset += 1

            for _ in range(count):
                if offset + 2 > len(data):
                    break
                # 2-byte object length prefix (little-endian)
                obj_length = struct.unpack_from("<H", data, offset)[0]
                offset += 2

                if offset + obj_length > len(data):
                    break

                # The object data contains the attribute value
                obj_data = data[offset : offset + obj_length]
                offset += obj_length

                value = _parse_attribute_object_data(obj_data)
                if value is not None:
                    attr_name = _variation_to_attribute_name(variation)
                    if attr_name:
                        attributes[attr_name] = value

        elif qualifier == 0x28:
            # 2-byte count with 2-byte index prefix
            if offset + 2 > len(data):
                break
            count = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            for _ in range(count):
                if offset + 2 > len(data):
                    break
                # Skip 2-byte index prefix
                offset += 2
                value, offset = _read_device_attribute_value(data, offset)
                if value is not None:
                    attr_name = _variation_to_attribute_name(variation)
                    if attr_name:
                        attributes[attr_name] = value
        else:
            # Unknown qualifier - can't determine object size, stop parsing
            break

    return attributes


def _read_device_attribute_value(
    data: bytes, offset: int
) -> tuple[Optional[str], int]:
    """Read a single device attribute value from the data.

    Device Attribute objects (Group 0) have the format:
    - Byte 0: Data type code
    - Byte 1: Length of value
    - Bytes 2+: Value data

    Returns (value_string, new_offset) tuple.
    """
    if offset + 2 > len(data):
        return None, offset

    data_type = data[offset]
    value_length = data[offset + 1]
    offset += 2

    if offset + value_length > len(data):
        return None, offset

    value_bytes = data[offset : offset + value_length]
    offset += value_length

    return _decode_attribute_value(data_type, value_bytes), offset


def _parse_attribute_object_data(obj_data: bytes) -> Optional[str]:
    """Parse attribute value from a variable-length object data block.

    The object data format:
    - Byte 0: Data type code
    - Byte 1: Length of value
    - Bytes 2+: Value data
    """
    if len(obj_data) < 2:
        return None

    data_type = obj_data[0]
    value_length = obj_data[1]

    if len(obj_data) < 2 + value_length:
        return None

    value_bytes = obj_data[2 : 2 + value_length]
    return _decode_attribute_value(data_type, value_bytes)


def _decode_attribute_value(data_type: int, value_bytes: bytes) -> Optional[str]:
    """Decode an attribute value based on its data type code.

    Returns the value as a string representation.
    """
    if not value_bytes:
        return None

    if data_type == DATA_TYPE_VISIBLE_STRING:
        # ASCII string - strip null terminators and whitespace
        try:
            return value_bytes.decode("ascii").rstrip("\x00").strip()
        except (UnicodeDecodeError, ValueError):
            return value_bytes.hex()

    elif data_type == DATA_TYPE_UNSIGNED_INT:
        # Unsigned integer (little-endian)
        if len(value_bytes) == 1:
            return str(value_bytes[0])
        elif len(value_bytes) == 2:
            return str(struct.unpack_from("<H", value_bytes)[0])
        elif len(value_bytes) == 4:
            return str(struct.unpack_from("<I", value_bytes)[0])
        else:
            return str(int.from_bytes(value_bytes, byteorder="little", signed=False))

    elif data_type == DATA_TYPE_SIGNED_INT:
        # Signed integer (little-endian)
        if len(value_bytes) == 1:
            return str(struct.unpack_from("<b", value_bytes)[0])
        elif len(value_bytes) == 2:
            return str(struct.unpack_from("<h", value_bytes)[0])
        elif len(value_bytes) == 4:
            return str(struct.unpack_from("<i", value_bytes)[0])
        else:
            return str(int.from_bytes(value_bytes, byteorder="little", signed=True))

    elif data_type == DATA_TYPE_FLOATING_POINT:
        # IEEE 754 floating point
        if len(value_bytes) == 4:
            return str(struct.unpack_from("<f", value_bytes)[0])
        elif len(value_bytes) == 8:
            return str(struct.unpack_from("<d", value_bytes)[0])
        else:
            return value_bytes.hex()

    elif data_type == DATA_TYPE_OCTET_STRING:
        # Binary data - return as hex string
        return value_bytes.hex()

    elif data_type == DATA_TYPE_BIT_STRING:
        # Bit string - return as hex
        return value_bytes.hex()

    else:
        # Unknown data type - try ASCII, fall back to hex
        try:
            decoded = value_bytes.decode("ascii").rstrip("\x00").strip()
            if decoded and all(32 <= ord(c) < 127 for c in decoded):
                return decoded
        except (UnicodeDecodeError, ValueError):
            pass
        return value_bytes.hex()


def _variation_to_attribute_name(variation: int) -> Optional[str]:
    """Map DNP3 Object Group 0 variation number to attribute name.

    Returns the attribute name key used in the attributes dictionary,
    or None if the variation is not a recognized identity attribute.
    """
    mapping = {
        VARIATION_MANUFACTURER_NAME: "manufacturer",
        VARIATION_DEVICE_MODEL: "model",
        VARIATION_FIRMWARE_VERSION: "firmware_version",
        VARIATION_SERIAL_NUMBER: "serial_number",
        VARIATION_DEVICE_ID: "device_id",
        VARIATION_HARDWARE_VERSION: "hardware_version",
        VARIATION_LOCATION: "location",
    }
    return mapping.get(variation)


def _truncate(value: Optional[str], max_length: int) -> Optional[str]:
    """Truncate a string value to max_length if it exceeds the limit."""
    if value is None:
        return None
    if len(value) > max_length:
        return value[:max_length]
    return value
