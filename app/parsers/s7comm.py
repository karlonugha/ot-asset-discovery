"""S7comm protocol parser for OT Asset Discovery.

Parses S7comm packets containing SZL (System Status List) responses
to extract PLC type, module name, firmware version, and serial number.

S7comm protocol structure:
  TPKT Header (4 bytes): version(1) + reserved(1) + length(2)
  COTP Header (variable): length(1) + PDU type(1) + ...
  S7comm Header (10+ bytes): protocol_id(1) + msg_type(1) + reserved(2) +
                              pdu_ref(2) + param_length(2) + data_length(2)
  S7comm Parameters (variable)
  S7comm Data (variable): contains SZL data for userdata responses

SZL IDs for device identification:
  0x0011 - Module Identification (module name, serial number)
  0x001C - Component Identification (PLC type, firmware version)

Requirements: 2.3, 2.5, 2.6
"""

import struct
from typing import Optional

from app.models.domain import DeviceFingerprint, ParseResult


# S7comm constants
S7COMM_PROTOCOL_ID = 0x32
S7COMM_MSG_TYPE_USERDATA = 0x07
S7COMM_MSG_TYPE_ACK_DATA = 0x03

# TPKT constants
TPKT_VERSION = 0x03
TPKT_HEADER_LENGTH = 4

# COTP constants
COTP_PDU_TYPE_DATA = 0xF0
COTP_PDU_TYPE_CONNECT_CONFIRM = 0xD0
COTP_PDU_TYPE_CONNECT_REQUEST = 0xE0

# SZL IDs for device identification
SZL_ID_MODULE_IDENTIFICATION = 0x0011
SZL_ID_COMPONENT_IDENTIFICATION = 0x001C

# Minimum packet sizes
MIN_TPKT_LENGTH = 4
MIN_COTP_DATA_LENGTH = 3  # length byte + PDU type + TPDU number
MIN_S7COMM_HEADER_LENGTH = 10
MIN_S7COMM_USERDATA_PARAM_LENGTH = 12


def parse_s7comm(raw_bytes: bytes) -> ParseResult:
    """Parse an S7comm packet and extract device identity from SZL responses.

    Args:
        raw_bytes: Raw packet bytes starting from the TPKT header.

    Returns:
        ParseResult with fingerprint if SZL identity data found,
        or with parsing_status="no_identity" for non-identity packets,
        or with parsing_status="partial" for incomplete identity data.
    """
    source_address = ""
    destination_address = ""

    try:
        # Extract IP addresses if Ethernet/IP headers are present
        source_address, destination_address, payload = _extract_addresses(raw_bytes)

        # Parse TPKT header
        tpkt_payload = _parse_tpkt(payload)
        if tpkt_payload is None:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
                error="Invalid TPKT header",
            )

        # Parse COTP header
        cotp_payload = _parse_cotp(tpkt_payload)
        if cotp_payload is None:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
                error="Invalid COTP header or non-data PDU",
            )

        # Parse S7comm header
        s7_header = _parse_s7comm_header(cotp_payload)
        if s7_header is None:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
                error="Invalid S7comm header",
            )

        msg_type, pdu_ref, param_length, data_length = s7_header
        s7_body = cotp_payload[MIN_S7COMM_HEADER_LENGTH:]

        # Only userdata responses contain SZL data
        if msg_type not in (S7COMM_MSG_TYPE_USERDATA, S7COMM_MSG_TYPE_ACK_DATA):
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
            )

        # Check if this is an SZL response
        szl_data = _extract_szl_data(s7_body, param_length, data_length)
        if szl_data is None:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
            )

        # Parse SZL records for device identity
        szl_id, records = szl_data
        identity = _parse_szl_identity(szl_id, records)

        if not identity:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
            )

        plc_type = identity.get("plc_type")
        module_name = identity.get("module_name")
        firmware_version = identity.get("firmware_version")
        serial_number = identity.get("serial_number")

        # Determine parsing status based on field completeness
        identity_fields = [plc_type, module_name, firmware_version, serial_number]
        non_null_count = sum(1 for f in identity_fields if f is not None)

        if non_null_count == 0:
            return ParseResult(
                fingerprint=None,
                parsing_status="no_identity",
                protocol="s7comm",
                source_address=source_address,
                destination_address=destination_address,
            )

        if non_null_count == len(identity_fields):
            parsing_status = "complete"
        else:
            parsing_status = "partial"

        fingerprint = DeviceFingerprint(
            schema_version="1.0.0",
            protocol="s7comm",
            source_address=source_address,
            destination_address=destination_address,
            vendor="Siemens",
            model=plc_type,
            firmware_version=firmware_version,
            device_type="PLC",
            serial_number=serial_number,
            protocol_data={
                "module_name": module_name,
                "szl_id": hex(szl_id),
                "pdu_reference": pdu_ref,
            },
            parsing_status=parsing_status,
        )

        return ParseResult(
            fingerprint=fingerprint,
            parsing_status=parsing_status,
            protocol="s7comm",
            source_address=source_address,
            destination_address=destination_address,
        )

    except Exception as e:
        return ParseResult(
            fingerprint=None,
            parsing_status="no_identity",
            protocol="s7comm",
            source_address=source_address,
            destination_address=destination_address,
            error=f"Parse error: {str(e)}",
        )


def _extract_addresses(raw_bytes: bytes) -> tuple[str, str, bytes]:
    """Extract source and destination IP addresses from packet.

    If the packet starts with an IP header (version 4), extract addresses.
    Otherwise, treat the entire packet as the TPKT payload and use
    empty strings for addresses.

    Returns:
        Tuple of (source_address, destination_address, remaining_payload)
    """
    if len(raw_bytes) < 20:
        return ("", "", raw_bytes)

    # Check for IPv4 header (version 4, IHL in first nibble)
    version = (raw_bytes[0] >> 4) & 0x0F
    if version == 4:
        ihl = (raw_bytes[0] & 0x0F) * 4
        if len(raw_bytes) < ihl:
            return ("", "", raw_bytes)

        src_ip = f"{raw_bytes[12]}.{raw_bytes[13]}.{raw_bytes[14]}.{raw_bytes[15]}"
        dst_ip = f"{raw_bytes[16]}.{raw_bytes[17]}.{raw_bytes[18]}.{raw_bytes[19]}"

        # Skip IP header + TCP header (assume 20 bytes TCP minimum)
        # TCP header starts at IHL offset
        tcp_offset = ihl
        if len(raw_bytes) < tcp_offset + 20:
            return (src_ip, dst_ip, raw_bytes[tcp_offset:])

        # TCP data offset is in the 4 high bits of byte 12 of TCP header
        tcp_data_offset = ((raw_bytes[tcp_offset + 12] >> 4) & 0x0F) * 4
        payload_start = tcp_offset + tcp_data_offset

        return (src_ip, dst_ip, raw_bytes[payload_start:])

    # Not an IP packet, treat as raw TPKT data
    return ("", "", raw_bytes)


def _parse_tpkt(data: bytes) -> Optional[bytes]:
    """Parse TPKT header and return the payload.

    TPKT Header format:
      Byte 0: Version (0x03)
      Byte 1: Reserved (0x00)
      Bytes 2-3: Length (big-endian, includes header)

    Returns:
        TPKT payload bytes, or None if invalid.
    """
    if len(data) < MIN_TPKT_LENGTH:
        return None

    version = data[0]
    if version != TPKT_VERSION:
        return None

    length = struct.unpack(">H", data[2:4])[0]
    if length < MIN_TPKT_LENGTH or length > len(data):
        return None

    return data[TPKT_HEADER_LENGTH:length]


def _parse_cotp(data: bytes) -> Optional[bytes]:
    """Parse COTP header and return the payload.

    COTP Data PDU format:
      Byte 0: Header length (not including this byte)
      Byte 1: PDU type (0xF0 for DT Data)
      Byte 2: TPDU number and EOT flag

    Returns:
        COTP payload bytes, or None if invalid or non-data PDU.
    """
    if len(data) < MIN_COTP_DATA_LENGTH:
        return None

    cotp_length = data[0]
    pdu_type = data[1]

    # We only process Data Transfer PDUs
    if pdu_type != COTP_PDU_TYPE_DATA:
        return None

    # Skip COTP header (length byte + header content)
    header_end = 1 + cotp_length
    if header_end > len(data):
        return None

    return data[header_end:]


def _parse_s7comm_header(data: bytes) -> Optional[tuple[int, int, int, int]]:
    """Parse S7comm header.

    S7comm Header format:
      Byte 0: Protocol ID (0x32)
      Byte 1: Message type (0x01=Job, 0x02=Ack, 0x03=AckData, 0x07=Userdata)
      Bytes 2-3: Reserved
      Bytes 4-5: PDU reference (big-endian)
      Bytes 6-7: Parameter length (big-endian)
      Bytes 8-9: Data length (big-endian)
      (For Ack-Data/Userdata: Bytes 10-11: Error class + error code)

    Returns:
        Tuple of (msg_type, pdu_ref, param_length, data_length) or None.
    """
    if len(data) < MIN_S7COMM_HEADER_LENGTH:
        return None

    protocol_id = data[0]
    if protocol_id != S7COMM_PROTOCOL_ID:
        return None

    msg_type = data[1]
    pdu_ref = struct.unpack(">H", data[4:6])[0]
    param_length = struct.unpack(">H", data[6:8])[0]
    data_length = struct.unpack(">H", data[8:10])[0]

    return (msg_type, pdu_ref, param_length, data_length)


def _extract_szl_data(
    s7_body: bytes, param_length: int, data_length: int
) -> Optional[tuple[int, bytes]]:
    """Extract SZL data from S7comm userdata response.

    Userdata parameter structure (12 bytes for SZL read response):
      Bytes 0-2: Parameter head (3 bytes)
      Byte 3: Parameter length (remaining)
      Byte 4: Method (0x12 = request/response)
      Byte 5: Type/Function (high nibble: type, low nibble: function group)
              Type: 0x4 = request, 0x8 = response
              Function group: 0x4 = CPU functions
      Byte 6: Subfunction (0x01 = Read SZL)
      Byte 7: Sequence number

    Data section for SZL response:
      Byte 0: Return code (0xFF = success)
      Byte 1: Transport size
      Bytes 2-3: Data length (big-endian, in bytes or bits depending on transport size)
      Bytes 4-5: SZL ID (big-endian)
      Bytes 6-7: SZL Index (big-endian)
      Bytes 8-9: SZL list length (length of one record)
      Bytes 10-11: SZL list count (number of records)
      Bytes 12+: SZL records

    Returns:
        Tuple of (szl_id, records_bytes) or None if not an SZL response.
    """
    if param_length < MIN_S7COMM_USERDATA_PARAM_LENGTH:
        return None

    if len(s7_body) < param_length:
        return None

    # Check parameter header for SZL read response
    # Byte 4 should be 0x12 (type/function indicator)
    if len(s7_body) < 8:
        return None

    method = s7_body[4] if len(s7_body) > 4 else 0
    if method != 0x12:
        return None

    type_func = s7_body[5] if len(s7_body) > 5 else 0
    # High nibble 0x8 = response, function group 0x4 = CPU functions
    response_type = (type_func >> 4) & 0x0F
    func_group = type_func & 0x0F

    if response_type != 0x08 or func_group != 0x04:
        return None

    subfunction = s7_body[6] if len(s7_body) > 6 else 0
    if subfunction != 0x01:  # Read SZL
        return None

    # Parse data section
    data_start = param_length
    data_section = s7_body[data_start:]

    if len(data_section) < 12:
        return None

    return_code = data_section[0]
    if return_code != 0xFF:  # Success
        return None

    # Extract SZL header
    szl_data_length = struct.unpack(">H", data_section[2:4])[0]
    szl_id = struct.unpack(">H", data_section[4:6])[0]
    # szl_index = struct.unpack(">H", data_section[6:8])[0]
    # record_length = struct.unpack(">H", data_section[8:10])[0]
    # record_count = struct.unpack(">H", data_section[10:12])[0]

    # SZL records start at offset 12 in the data section
    records = data_section[12:]

    # Only process identity-related SZL IDs
    if szl_id not in (SZL_ID_MODULE_IDENTIFICATION, SZL_ID_COMPONENT_IDENTIFICATION):
        return None

    return (szl_id, records)


def _parse_szl_identity(
    szl_id: int, records: bytes
) -> dict[str, Optional[str]]:
    """Parse SZL records to extract device identity fields.

    SZL 0x0011 (Module Identification) record format (28 bytes per record):
      Bytes 0-1: Index
      Bytes 2-21: Module name (20 bytes, null-padded ASCII)
      Bytes 22-27: Serial number (6 bytes, null-padded ASCII)
      (Some implementations use longer records with additional fields)

    SZL 0x001C (Component Identification) record format (34 bytes per record):
      Bytes 0-1: Index
      Bytes 2-25: Component name (24 bytes, null-padded ASCII)
      Bytes 26-33: Additional info (8 bytes)
      (Index 1 = PLC name, Index 2 = Module name, Index 3 = Plant ID,
       Index 7 = Module type, Index 9 = Serial number, Index 11 = OMS serial)

    Returns:
        Dictionary with extracted identity fields.
    """
    identity: dict[str, Optional[str]] = {
        "plc_type": None,
        "module_name": None,
        "firmware_version": None,
        "serial_number": None,
    }

    if szl_id == SZL_ID_MODULE_IDENTIFICATION:
        identity = _parse_szl_0011(records, identity)
    elif szl_id == SZL_ID_COMPONENT_IDENTIFICATION:
        identity = _parse_szl_001c(records, identity)

    return identity


def _parse_szl_0011(
    records: bytes, identity: dict[str, Optional[str]]
) -> dict[str, Optional[str]]:
    """Parse SZL 0x0011 (Module Identification) records.

    Each record is typically 28 bytes:
      Bytes 0-1: Index (1=Module, 2=Basic Hardware, 3=Basic Firmware)
      Bytes 2-21: Name/Order number (20 bytes, null-padded)
      Bytes 22-27: Serial number or version (6 bytes, null-padded)

    Index meanings:
      1 = Module order number (e.g., "6ES7 315-2AG10-0AB0")
      2 = Basic hardware version
      3 = Basic firmware version
    """
    record_size = 28
    offset = 0

    while offset + record_size <= len(records):
        index = struct.unpack(">H", records[offset : offset + 2])[0]
        name_bytes = records[offset + 2 : offset + 22]
        extra_bytes = records[offset + 22 : offset + 28]

        name = _decode_null_padded(name_bytes)
        extra = _decode_null_padded(extra_bytes)

        if index == 1:
            # Module order number → used as PLC type / model
            if name:
                identity["plc_type"] = name
            if extra:
                identity["serial_number"] = extra
        elif index == 2:
            # Basic hardware → module name
            if name:
                identity["module_name"] = name
        elif index == 3:
            # Basic firmware version
            if name:
                identity["firmware_version"] = name
            elif extra:
                identity["firmware_version"] = extra

        offset += record_size

    return identity


def _parse_szl_001c(
    records: bytes, identity: dict[str, Optional[str]]
) -> dict[str, Optional[str]]:
    """Parse SZL 0x001C (Component Identification) records.

    Each record is typically 34 bytes:
      Bytes 0-1: Index
      Bytes 2-25: Component name (24 bytes, null-padded)
      Bytes 26-33: Additional info (8 bytes, null-padded)

    Index meanings:
      1 = PLC name (user-assigned name)
      2 = Module name
      3 = Plant identification
      4 = Copyright
      5 = Serial number of module
      7 = Module type name
      9 = Serial number (alternative location)
      11 = OMS serial number
    """
    record_size = 34
    offset = 0

    while offset + record_size <= len(records):
        index = struct.unpack(">H", records[offset : offset + 2])[0]
        name_bytes = records[offset + 2 : offset + 26]
        extra_bytes = records[offset + 26 : offset + 34]

        name = _decode_null_padded(name_bytes)
        extra = _decode_null_padded(extra_bytes)

        if index == 1:
            # PLC name
            if name:
                identity["plc_type"] = name
        elif index == 2:
            # Module name
            if name:
                identity["module_name"] = name
        elif index == 5:
            # Serial number
            if name:
                identity["serial_number"] = name
            elif extra:
                identity["serial_number"] = extra
        elif index == 7:
            # Module type name → can serve as PLC type if index 1 not present
            if name and identity["plc_type"] is None:
                identity["plc_type"] = name
        elif index == 9:
            # Alternative serial number location
            if identity["serial_number"] is None:
                if name:
                    identity["serial_number"] = name
                elif extra:
                    identity["serial_number"] = extra

        offset += record_size

    # Try to extract firmware version from extra field of module name record
    # Re-scan for firmware info (index 2 extra field often contains version)
    offset = 0
    while offset + record_size <= len(records):
        index = struct.unpack(">H", records[offset : offset + 2])[0]
        extra_bytes = records[offset + 26 : offset + 34]
        extra = _decode_null_padded(extra_bytes)

        if index == 2 and extra:
            # Module name's extra field often contains firmware version
            identity["firmware_version"] = extra
            break
        elif index == 4 and identity["firmware_version"] is None:
            # Copyright field sometimes contains version info
            name_bytes = records[offset + 2 : offset + 26]
            name = _decode_null_padded(name_bytes)
            if name and _looks_like_version(name):
                identity["firmware_version"] = name

        offset += record_size

    return identity


def _decode_null_padded(data: bytes) -> Optional[str]:
    """Decode null-padded ASCII bytes to a string.

    Returns None if the result is empty after stripping.
    """
    try:
        # Strip null bytes and whitespace
        text = data.split(b"\x00")[0].decode("ascii", errors="replace").strip()
        return text if text else None
    except (UnicodeDecodeError, ValueError):
        return None


def _looks_like_version(text: str) -> bool:
    """Check if a string looks like a version number (e.g., 'V4.2.1')."""
    if not text:
        return False
    # Common version patterns: V4.2, V4.2.1, 4.2.1, etc.
    stripped = text.lstrip("Vv ")
    parts = stripped.split(".")
    if len(parts) >= 2:
        return all(p.isdigit() for p in parts[:2])
    return False
