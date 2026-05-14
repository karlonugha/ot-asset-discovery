"""EtherNet/IP protocol parser for CIP Identity object extraction.

Parses EtherNet/IP encapsulation packets to extract CIP Identity objects,
which contain device identification data including vendor ID, device type,
product code, revision, serial number, and product name.

EtherNet/IP uses TCP port 44818 and UDP port 44818 for explicit messaging,
and UDP port 2222 for implicit (I/O) messaging.

Packet structure:
- EtherNet/IP Encapsulation Header (24 bytes):
  - Command (2 bytes): e.g., 0x0063 = List Identity
  - Length (2 bytes): data length following header
  - Session Handle (4 bytes)
  - Status (4 bytes)
  - Sender Context (8 bytes)
  - Options (4 bytes)
- Command-specific data (variable)

CIP Identity Object (in List Identity response):
  - Item Count (2 bytes)
  - Item Type ID (2 bytes): 0x000C = List Identity Response
  - Item Length (2 bytes)
  - Encapsulation Protocol Version (2 bytes)
  - Socket Address (16 bytes)
  - Vendor ID (2 bytes)
  - Device Type (2 bytes)
  - Product Code (2 bytes)
  - Revision Major (1 byte)
  - Revision Minor (1 byte)
  - Status (2 bytes)
  - Serial Number (4 bytes)
  - Product Name Length (1 byte)
  - Product Name (variable)
  - State (1 byte)

Requirements: 2.2, 2.5, 2.6
"""

import struct
from typing import Optional

from app.models.domain import DeviceFingerprint, ParseResult


# EtherNet/IP command codes
ENCAP_CMD_LIST_IDENTITY = 0x0063
ENCAP_CMD_LIST_SERVICES = 0x0004
ENCAP_CMD_REGISTER_SESSION = 0x0065
ENCAP_CMD_UNREGISTER_SESSION = 0x0066
ENCAP_CMD_SEND_RR_DATA = 0x006F
ENCAP_CMD_SEND_UNIT_DATA = 0x0070

# CIP Identity item type
CIP_ITEM_ID_LIST_IDENTITY = 0x000C

# EtherNet/IP encapsulation header size
ENCAP_HEADER_SIZE = 24

# Minimum size for a CIP Identity item (without product name)
# Item Type (2) + Item Length (2) + Protocol Version (2) + Socket Address (16) +
# Vendor ID (2) + Device Type (2) + Product Code (2) + Revision (2) +
# Status (2) + Serial Number (4) + Product Name Length (1) + State (1)
CIP_IDENTITY_MIN_SIZE = 33


def parse_ethernetip(raw_bytes: bytes) -> ParseResult:
    """Parse an EtherNet/IP packet and extract CIP Identity data if present.

    Args:
        raw_bytes: Raw packet bytes starting from the EtherNet/IP encapsulation header.
                   Expected to begin with the 24-byte encapsulation header.

    Returns:
        ParseResult with:
        - fingerprint populated if CIP Identity data was found
        - parsing_status "complete" if all identity fields extracted
        - parsing_status "partial" if some fields missing
        - parsing_status "no_identity" if valid EtherNet/IP but no identity data
        - error set if packet is malformed

    Requirements: 2.2, 2.5, 2.6
    """
    # Validate minimum packet size for encapsulation header
    if len(raw_bytes) < ENCAP_HEADER_SIZE:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address="",
            destination_address="",
            error=f"Packet too short for EtherNet/IP header: {len(raw_bytes)} bytes, need {ENCAP_HEADER_SIZE}",
        )

    # Parse encapsulation header
    try:
        command, length, session_handle, status = struct.unpack_from(
            "<HHI I", raw_bytes, 0
        )
    except struct.error as e:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address="",
            destination_address="",
            error=f"Failed to parse encapsulation header: {e}",
        )

    # Extract sender context for source identification
    sender_context = raw_bytes[12:20]
    source_address = _extract_source_address(raw_bytes)
    destination_address = _extract_destination_address(raw_bytes)

    # Check if this is a List Identity response (command 0x0063)
    if command != ENCAP_CMD_LIST_IDENTITY:
        # Valid EtherNet/IP packet but not a List Identity response
        # Record source/dest and protocol without fingerprint (Requirement 2.5)
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error=None,
        )

    # Validate data length
    data_start = ENCAP_HEADER_SIZE
    if data_start + length > len(raw_bytes):
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error=f"Declared data length {length} exceeds available bytes {len(raw_bytes) - data_start}",
        )

    # Parse the List Identity response data
    return _parse_list_identity_response(
        raw_bytes, data_start, length, source_address, destination_address
    )


def _extract_source_address(raw_bytes: bytes) -> str:
    """Extract source address from the packet.

    For EtherNet/IP, the source is typically identified by the socket address
    embedded in the CIP Identity response, or from the IP header if available.
    If the packet contains a socket address in the identity data, that is used.
    Otherwise, returns the sender context as a hex string identifier.
    """
    # The sender context (bytes 12-20) can serve as a source identifier
    # when no IP header is available
    if len(raw_bytes) >= 20:
        context = raw_bytes[12:20]
        # If context is all zeros, return empty
        if context == b"\x00" * 8:
            return "0.0.0.0"
        # Try to interpret first 4 bytes as IP if they look like one
        return context.hex()
    return ""


def _extract_destination_address(raw_bytes: bytes) -> str:
    """Extract destination address from the packet.

    For EtherNet/IP responses, the destination is typically the requesting device.
    Uses session handle as an identifier when IP header is not available.
    """
    if len(raw_bytes) >= 8:
        session_handle = struct.unpack_from("<I", raw_bytes, 4)[0]
        return f"session:{session_handle}"
    return ""


def _parse_list_identity_response(
    raw_bytes: bytes,
    data_start: int,
    data_length: int,
    source_address: str,
    destination_address: str,
) -> ParseResult:
    """Parse the data portion of a List Identity response.

    The response contains:
    - Item Count (2 bytes)
    - For each item:
      - Item Type ID (2 bytes)
      - Item Length (2 bytes)
      - Item Data (variable)

    For CIP Identity items (type 0x000C), the data contains device identity fields.
    """
    offset = data_start

    # Need at least 2 bytes for item count
    if data_length < 2:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error="List Identity response too short for item count",
        )

    try:
        item_count = struct.unpack_from("<H", raw_bytes, offset)[0]
    except struct.error:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error="Failed to parse item count",
        )
    offset += 2

    if item_count == 0:
        # Valid response but no identity items (Requirement 2.5)
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error=None,
        )

    # Parse items looking for CIP Identity (type 0x000C)
    for _ in range(item_count):
        # Need at least 4 bytes for item type + item length
        if offset + 4 > len(raw_bytes):
            break

        try:
            item_type, item_length = struct.unpack_from("<HH", raw_bytes, offset)
        except struct.error:
            break
        offset += 4

        if item_type == CIP_ITEM_ID_LIST_IDENTITY:
            # Found a CIP Identity item - parse it
            return _parse_cip_identity_item(
                raw_bytes, offset, item_length, source_address, destination_address
            )

        # Skip non-identity items
        offset += item_length

    # No CIP Identity item found (Requirement 2.5)
    return ParseResult(
        fingerprint=None,
        parsing_status="no_identity",
        protocol="ethernetip",
        source_address=source_address,
        destination_address=destination_address,
        error=None,
    )


def _parse_cip_identity_item(
    raw_bytes: bytes,
    offset: int,
    item_length: int,
    source_address: str,
    destination_address: str,
) -> ParseResult:
    """Parse a CIP Identity item to extract device identification fields.

    CIP Identity item structure:
    - Encapsulation Protocol Version (2 bytes)
    - Socket Address (16 bytes):
      - sin_family (2 bytes, big-endian)
      - sin_port (2 bytes, big-endian)
      - sin_addr (4 bytes, big-endian)
      - sin_zero (8 bytes)
    - Vendor ID (2 bytes, little-endian)
    - Device Type (2 bytes, little-endian)
    - Product Code (2 bytes, little-endian)
    - Revision Major (1 byte)
    - Revision Minor (1 byte)
    - Status (2 bytes, little-endian)
    - Serial Number (4 bytes, little-endian)
    - Product Name Length (1 byte)
    - Product Name (variable, ASCII)
    - State (1 byte)

    Requirements: 2.2, 2.6
    """
    item_end = offset + item_length
    vendor_id: Optional[int] = None
    device_type: Optional[int] = None
    product_code: Optional[int] = None
    revision_major: Optional[int] = None
    revision_minor: Optional[int] = None
    serial_number: Optional[int] = None
    product_name: Optional[str] = None
    device_ip: Optional[str] = None
    has_any_field = False

    try:
        # Encapsulation Protocol Version (2 bytes)
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        offset += 2  # Skip protocol version

        # Socket Address (16 bytes) - contains device IP
        if offset + 16 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )

        # Parse socket address to get device IP
        # sin_family (2, big-endian), sin_port (2, big-endian), sin_addr (4, big-endian)
        sin_port = struct.unpack_from(">H", raw_bytes, offset + 2)[0]
        ip_bytes = raw_bytes[offset + 4 : offset + 8]
        device_ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
        # Update source address with the actual device IP from the identity
        source_address = device_ip
        offset += 16

        # Vendor ID (2 bytes)
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        vendor_id = struct.unpack_from("<H", raw_bytes, offset)[0]
        has_any_field = True
        offset += 2

        # Device Type (2 bytes)
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        device_type = struct.unpack_from("<H", raw_bytes, offset)[0]
        has_any_field = True
        offset += 2

        # Product Code (2 bytes)
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        product_code = struct.unpack_from("<H", raw_bytes, offset)[0]
        has_any_field = True
        offset += 2

        # Revision (2 bytes: major + minor)
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        revision_major = raw_bytes[offset]
        revision_minor = raw_bytes[offset + 1]
        has_any_field = True
        offset += 2

        # Status (2 bytes) - skip
        if offset + 2 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        offset += 2

        # Serial Number (4 bytes)
        if offset + 4 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        serial_number = struct.unpack_from("<I", raw_bytes, offset)[0]
        has_any_field = True
        offset += 4

        # Product Name Length (1 byte)
        if offset + 1 > item_end:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        name_length = raw_bytes[offset]
        offset += 1

        # Product Name (variable)
        if offset + name_length > item_end:
            # Partial name - extract what we can
            available = item_end - offset
            if available > 0:
                product_name = raw_bytes[offset : offset + available].decode(
                    "ascii", errors="replace"
                )
                has_any_field = True
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )

        if name_length > 0:
            product_name = raw_bytes[offset : offset + name_length].decode(
                "ascii", errors="replace"
            )
            has_any_field = True
        offset += name_length

    except (struct.error, IndexError) as e:
        # If we've extracted some fields, return partial result (Requirement 2.6)
        if has_any_field:
            return _build_partial_result(
                source_address, destination_address, device_ip,
                vendor_id, device_type, product_code,
                revision_major, revision_minor, serial_number, product_name,
                has_any_field,
            )
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error=f"Error parsing CIP Identity item: {e}",
        )

    # All fields successfully extracted - build complete fingerprint
    return _build_complete_result(
        source_address, destination_address, device_ip,
        vendor_id, device_type, product_code,
        revision_major, revision_minor, serial_number, product_name,
    )


def _build_complete_result(
    source_address: str,
    destination_address: str,
    device_ip: Optional[str],
    vendor_id: Optional[int],
    device_type: Optional[int],
    product_code: Optional[int],
    revision_major: Optional[int],
    revision_minor: Optional[int],
    serial_number: Optional[int],
    product_name: Optional[str],
) -> ParseResult:
    """Build a ParseResult with parsing_status 'complete' when all fields are present."""
    firmware_version = None
    if revision_major is not None and revision_minor is not None:
        firmware_version = f"{revision_major}.{revision_minor}"

    vendor_str = None
    if vendor_id is not None:
        vendor_str = f"VendorID:{vendor_id}"

    model_str = None
    if product_name is not None:
        model_str = product_name

    serial_str = None
    if serial_number is not None:
        serial_str = f"{serial_number:08X}"

    # Determine device type category from CIP device type code
    device_type_category = _map_device_type(device_type)

    fingerprint = DeviceFingerprint(
        schema_version="1.0.0",
        protocol="ethernetip",
        source_address=source_address,
        destination_address=destination_address,
        ip_address=device_ip,
        vendor=vendor_str,
        model=model_str,
        firmware_version=firmware_version,
        device_type=device_type_category,
        serial_number=serial_str,
        protocol_data={
            "vendor_id": vendor_id,
            "device_type_code": device_type,
            "product_code": product_code,
            "revision_major": revision_major,
            "revision_minor": revision_minor,
            "serial_number_raw": serial_number,
        },
        parsing_status="complete",
    )

    return ParseResult(
        fingerprint=fingerprint,
        parsing_status="complete",
        protocol="ethernetip",
        source_address=source_address,
        destination_address=destination_address,
        error=None,
    )


def _build_partial_result(
    source_address: str,
    destination_address: str,
    device_ip: Optional[str],
    vendor_id: Optional[int],
    device_type: Optional[int],
    product_code: Optional[int],
    revision_major: Optional[int],
    revision_minor: Optional[int],
    serial_number: Optional[int],
    product_name: Optional[str],
    has_any_field: bool,
) -> ParseResult:
    """Build a ParseResult with parsing_status 'partial' for incomplete identity data.

    Requirement 2.6: Extract all available fields, leave missing as null,
    set parsing_status to 'partial'.
    """
    if not has_any_field:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="ethernetip",
            source_address=source_address,
            destination_address=destination_address,
            error=None,
        )

    firmware_version = None
    if revision_major is not None and revision_minor is not None:
        firmware_version = f"{revision_major}.{revision_minor}"

    vendor_str = None
    if vendor_id is not None:
        vendor_str = f"VendorID:{vendor_id}"

    model_str = None
    if product_name is not None:
        model_str = product_name

    serial_str = None
    if serial_number is not None:
        serial_str = f"{serial_number:08X}"

    device_type_category = _map_device_type(device_type)

    # Build protocol_data with only available fields
    protocol_data: dict = {}
    if vendor_id is not None:
        protocol_data["vendor_id"] = vendor_id
    if device_type is not None:
        protocol_data["device_type_code"] = device_type
    if product_code is not None:
        protocol_data["product_code"] = product_code
    if revision_major is not None:
        protocol_data["revision_major"] = revision_major
    if revision_minor is not None:
        protocol_data["revision_minor"] = revision_minor
    if serial_number is not None:
        protocol_data["serial_number_raw"] = serial_number

    fingerprint = DeviceFingerprint(
        schema_version="1.0.0",
        protocol="ethernetip",
        source_address=source_address,
        destination_address=destination_address,
        ip_address=device_ip,
        vendor=vendor_str,
        model=model_str,
        firmware_version=firmware_version,
        device_type=device_type_category,
        serial_number=serial_str,
        protocol_data=protocol_data,
        parsing_status="partial",
    )

    return ParseResult(
        fingerprint=fingerprint,
        parsing_status="partial",
        protocol="ethernetip",
        source_address=source_address,
        destination_address=destination_address,
        error=None,
    )


def _map_device_type(device_type_code: Optional[int]) -> Optional[str]:
    """Map CIP device type code to OT device category.

    Common CIP device type codes:
    - 0x00: Generic Device
    - 0x02: AC Drive
    - 0x0E: Programmable Logic Controller (PLC)
    - 0x12: Human-Machine Interface (HMI)
    - 0x21: Remote Terminal Unit (RTU) / Adapter
    - 0x2B: IED (Intelligent Electronic Device)

    Returns one of: "PLC", "RTU", "HMI", "IED", or None for unknown types.
    """
    if device_type_code is None:
        return None

    # Map known CIP device types to OT categories
    PLC_TYPES = {0x0E, 0x0F, 0x10}  # PLC, Motion Controller, Safety Controller
    HMI_TYPES = {0x12, 0x18}  # HMI, Display
    RTU_TYPES = {0x21, 0x07, 0x09}  # Adapter, I/O, DC Drive
    IED_TYPES = {0x2B, 0x2C}  # IED, Protection Relay

    if device_type_code in PLC_TYPES:
        return "PLC"
    elif device_type_code in HMI_TYPES:
        return "HMI"
    elif device_type_code in RTU_TYPES:
        return "RTU"
    elif device_type_code in IED_TYPES:
        return "IED"
    return None
