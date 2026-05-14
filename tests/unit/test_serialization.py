"""Unit tests for DeviceFingerprint serialization and deserialization.

Tests cover:
- serialize_fingerprint() produces valid JSON with base64-encoded binary fields
- deserialize_fingerprint() validates against JSON Schema and restores data types
- Round-trip serialization preserves all fields
- Error handling for invalid JSON, missing fields, and unsupported schema versions

Requirements: 2.7, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
"""

import base64
import json

import pytest

from app.models.domain import DeviceFingerprint
from app.parsers.serialization import (
    DeserializationError,
    SerializationError,
    deserialize_fingerprint,
    get_schema,
    get_supported_versions,
    serialize_fingerprint,
    SUPPORTED_SCHEMA_VERSIONS,
)


# --- Fixtures ---


@pytest.fixture
def complete_fingerprint() -> DeviceFingerprint:
    """A fully populated DeviceFingerprint for testing."""
    return DeviceFingerprint(
        schema_version="1.0.0",
        protocol="modbus_tcp",
        source_address="192.168.1.10",
        destination_address="192.168.1.20",
        mac_address="00:1A:2B:3C:4D:5E",
        ip_address="192.168.1.10",
        vendor="Siemens",
        model="S7-1200",
        firmware_version="V4.5.2",
        device_type="PLC",
        serial_number="SN-12345",
        protocol_data={"unit_id": 1, "function_code": 43},
        parsing_status="complete",
        binary_fields={"raw_payload": base64.b64encode(b"\x00\x01\x02\x03").decode()},
    )


@pytest.fixture
def minimal_fingerprint() -> DeviceFingerprint:
    """A minimally populated DeviceFingerprint with only required fields."""
    return DeviceFingerprint(
        protocol="ethernetip",
        source_address="10.0.0.1",
        destination_address="10.0.0.2",
    )


@pytest.fixture
def partial_fingerprint() -> DeviceFingerprint:
    """A partially populated DeviceFingerprint with some optional fields."""
    return DeviceFingerprint(
        schema_version="1.0.0",
        protocol="s7comm",
        source_address="172.16.0.5",
        destination_address="172.16.0.10",
        vendor="Schneider Electric",
        firmware_version="FW3.1",
        parsing_status="partial",
    )


# --- Serialization Tests ---


class TestSerializeFingerprint:
    """Tests for serialize_fingerprint()."""

    def test_produces_valid_json(self, complete_fingerprint: DeviceFingerprint):
        """Serialized output is valid JSON."""
        result = serialize_fingerprint(complete_fingerprint)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_includes_schema_version(self, complete_fingerprint: DeviceFingerprint):
        """Serialized output includes schema_version field."""
        result = serialize_fingerprint(complete_fingerprint)
        parsed = json.loads(result)
        assert parsed["schema_version"] == "1.0.0"

    def test_preserves_all_fields(self, complete_fingerprint: DeviceFingerprint):
        """All fields from the fingerprint are present in serialized output."""
        result = serialize_fingerprint(complete_fingerprint)
        parsed = json.loads(result)

        assert parsed["protocol"] == "modbus_tcp"
        assert parsed["source_address"] == "192.168.1.10"
        assert parsed["destination_address"] == "192.168.1.20"
        assert parsed["mac_address"] == "00:1A:2B:3C:4D:5E"
        assert parsed["ip_address"] == "192.168.1.10"
        assert parsed["vendor"] == "Siemens"
        assert parsed["model"] == "S7-1200"
        assert parsed["firmware_version"] == "V4.5.2"
        assert parsed["device_type"] == "PLC"
        assert parsed["serial_number"] == "SN-12345"
        assert parsed["protocol_data"] == {"unit_id": 1, "function_code": 43}
        assert parsed["parsing_status"] == "complete"

    def test_binary_fields_are_base64_encoded(
        self, complete_fingerprint: DeviceFingerprint
    ):
        """Binary fields are stored as base64-encoded strings."""
        result = serialize_fingerprint(complete_fingerprint)
        parsed = json.loads(result)

        raw_payload_b64 = parsed["binary_fields"]["raw_payload"]
        decoded = base64.b64decode(raw_payload_b64)
        assert decoded == b"\x00\x01\x02\x03"

    def test_minimal_fingerprint_serializes(
        self, minimal_fingerprint: DeviceFingerprint
    ):
        """Minimal fingerprint with only required fields serializes correctly."""
        result = serialize_fingerprint(minimal_fingerprint)
        parsed = json.loads(result)

        assert parsed["protocol"] == "ethernetip"
        assert parsed["source_address"] == "10.0.0.1"
        assert parsed["destination_address"] == "10.0.0.2"
        assert parsed["schema_version"] == "1.0.0"
        assert parsed["mac_address"] is None
        assert parsed["vendor"] is None

    def test_null_optional_fields_serialized(
        self, minimal_fingerprint: DeviceFingerprint
    ):
        """Optional fields that are None are serialized as null."""
        result = serialize_fingerprint(minimal_fingerprint)
        parsed = json.loads(result)

        assert parsed["mac_address"] is None
        assert parsed["ip_address"] is None
        assert parsed["vendor"] is None
        assert parsed["model"] is None
        assert parsed["firmware_version"] is None
        assert parsed["device_type"] is None
        assert parsed["serial_number"] is None

    def test_numeric_precision_preserved(self):
        """Numeric values in protocol_data preserve their precision."""
        fp = DeviceFingerprint(
            protocol="dnp3",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            protocol_data={"float_val": 3.14159, "int_val": 42, "large_int": 2**31},
        )
        result = serialize_fingerprint(fp)
        parsed = json.loads(result)

        assert parsed["protocol_data"]["float_val"] == 3.14159
        assert parsed["protocol_data"]["int_val"] == 42
        assert parsed["protocol_data"]["large_int"] == 2**31


# --- Deserialization Tests ---


class TestDeserializeFingerprint:
    """Tests for deserialize_fingerprint()."""

    def test_deserializes_valid_json(self, complete_fingerprint: DeviceFingerprint):
        """Valid JSON deserializes to a DeviceFingerprint."""
        json_str = serialize_fingerprint(complete_fingerprint)
        result = deserialize_fingerprint(json_str)
        assert isinstance(result, DeviceFingerprint)

    def test_restores_all_fields(self, complete_fingerprint: DeviceFingerprint):
        """Deserialized object has all fields matching the original."""
        json_str = serialize_fingerprint(complete_fingerprint)
        result = deserialize_fingerprint(json_str)

        assert result.protocol == complete_fingerprint.protocol
        assert result.source_address == complete_fingerprint.source_address
        assert result.destination_address == complete_fingerprint.destination_address
        assert result.mac_address == complete_fingerprint.mac_address
        assert result.vendor == complete_fingerprint.vendor
        assert result.model == complete_fingerprint.model
        assert result.firmware_version == complete_fingerprint.firmware_version
        assert result.device_type == complete_fingerprint.device_type
        assert result.serial_number == complete_fingerprint.serial_number
        assert result.protocol_data == complete_fingerprint.protocol_data
        assert result.parsing_status == complete_fingerprint.parsing_status
        assert result.binary_fields == complete_fingerprint.binary_fields

    def test_round_trip_preserves_equality(
        self, complete_fingerprint: DeviceFingerprint
    ):
        """Serialize then deserialize produces an equal object."""
        json_str = serialize_fingerprint(complete_fingerprint)
        result = deserialize_fingerprint(json_str)
        assert result == complete_fingerprint

    def test_round_trip_minimal(self, minimal_fingerprint: DeviceFingerprint):
        """Round-trip works for minimal fingerprints."""
        json_str = serialize_fingerprint(minimal_fingerprint)
        result = deserialize_fingerprint(json_str)
        assert result == minimal_fingerprint

    def test_round_trip_partial(self, partial_fingerprint: DeviceFingerprint):
        """Round-trip works for partial fingerprints."""
        json_str = serialize_fingerprint(partial_fingerprint)
        result = deserialize_fingerprint(json_str)
        assert result == partial_fingerprint

    def test_binary_fields_round_trip(self):
        """Binary fields survive round-trip as base64 strings."""
        original_bytes = b"\xff\xfe\xfd\xfc\xfb"
        fp = DeviceFingerprint(
            protocol="modbus_tcp",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            binary_fields={"data": base64.b64encode(original_bytes).decode()},
        )
        json_str = serialize_fingerprint(fp)
        result = deserialize_fingerprint(json_str)

        decoded = base64.b64decode(result.binary_fields["data"])
        assert decoded == original_bytes


# --- Error Handling Tests ---


class TestDeserializationErrors:
    """Tests for error handling in deserialization."""

    def test_invalid_json_rejected(self):
        """Malformed JSON is rejected with specific error."""
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint("not valid json {{{")
        assert "Invalid JSON" in str(exc_info.value)
        assert exc_info.value.constraint == "valid_json"

    def test_empty_string_rejected(self):
        """Empty string is rejected as invalid JSON."""
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint("")
        assert "Invalid JSON" in str(exc_info.value)

    def test_json_array_rejected(self):
        """JSON array (not object) is rejected."""
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint("[1, 2, 3]")
        assert "expected a JSON object" in str(exc_info.value)
        assert exc_info.value.constraint == "json_object"

    def test_missing_schema_version_rejected(self):
        """JSON missing schema_version field is rejected."""
        data = {
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "schema_version" in str(exc_info.value)
        assert exc_info.value.constraint == "required_field"

    def test_unsupported_schema_version_rejected(self):
        """Unsupported schema version is rejected with specific error."""
        data = {
            "schema_version": "99.0.0",
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "Unsupported schema version" in str(exc_info.value)
        assert "99.0.0" in str(exc_info.value)
        assert exc_info.value.constraint == "schema_version"

    def test_missing_required_protocol_rejected(self):
        """JSON missing required 'protocol' field is rejected."""
        data = {
            "schema_version": "1.0.0",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "protocol" in str(exc_info.value).lower()

    def test_missing_required_source_address_rejected(self):
        """JSON missing required 'source_address' field is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": "modbus_tcp",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "source_address" in str(exc_info.value)

    def test_missing_required_destination_address_rejected(self):
        """JSON missing required 'destination_address' field is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "destination_address" in str(exc_info.value)

    def test_invalid_protocol_value_rejected(self):
        """Invalid protocol enum value is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": "invalid_protocol",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "protocol" in str(exc_info.value).lower()

    def test_invalid_schema_version_format_rejected(self):
        """Schema version not matching semver pattern is rejected."""
        data = {
            "schema_version": "not-a-version",
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        # Should be rejected as unsupported version
        assert exc_info.value.constraint in ("schema_version", "schema_validation")

    def test_additional_properties_rejected(self):
        """JSON with unknown additional properties is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
            "unknown_field": "should not be here",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "additional" in str(exc_info.value).lower() or "unknown_field" in str(
            exc_info.value
        )

    def test_wrong_type_for_protocol_rejected(self):
        """Wrong type for protocol field is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": 123,
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "protocol" in str(exc_info.value).lower()

    def test_vendor_exceeds_max_length_rejected(self):
        """Vendor field exceeding 128 characters is rejected."""
        data = {
            "schema_version": "1.0.0",
            "protocol": "modbus_tcp",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
            "vendor": "x" * 129,
        }
        with pytest.raises(DeserializationError) as exc_info:
            deserialize_fingerprint(json.dumps(data))
        assert "vendor" in str(exc_info.value).lower()


# --- Schema Utility Tests ---


class TestSchemaUtilities:
    """Tests for schema utility functions."""

    def test_get_schema_returns_valid_schema(self):
        """get_schema returns the schema for a supported version."""
        schema = get_schema("1.0.0")
        assert schema is not None
        assert schema["title"] == "DeviceFingerprint"
        assert "properties" in schema
        assert "required" in schema

    def test_get_schema_returns_none_for_unsupported(self):
        """get_schema returns None for unsupported versions."""
        assert get_schema("99.0.0") is None

    def test_get_supported_versions(self):
        """get_supported_versions returns the set of supported versions."""
        versions = get_supported_versions()
        assert "1.0.0" in versions
        assert isinstance(versions, set)

    def test_supported_versions_is_copy(self):
        """get_supported_versions returns a copy, not the original set."""
        versions = get_supported_versions()
        versions.add("99.0.0")
        assert "99.0.0" not in SUPPORTED_SCHEMA_VERSIONS
