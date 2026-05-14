"""DeviceFingerprint serialization and deserialization with JSON Schema validation.

Implements:
- serialize_fingerprint(): Produces JSON with base64-encoded binary fields and schema_version
- deserialize_fingerprint(): Validates against JSON Schema and restores data types
- JSON Schema validation with versioned schema document
- Error handling for invalid JSON, missing fields, and unsupported schema versions

Requirements: 2.7, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
"""

import base64
import json
from typing import Any

from app.models.domain import DeviceFingerprint


# Supported schema versions for deserialization
SUPPORTED_SCHEMA_VERSIONS = {"1.0.0"}

# JSON Schema document for DeviceFingerprint validation (version 1.0.0)
DEVICE_FINGERPRINT_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DeviceFingerprint",
    "description": "Schema for OT device fingerprint serialization (v1.0.0)",
    "type": "object",
    "required": [
        "schema_version",
        "protocol",
        "source_address",
        "destination_address",
    ],
    "properties": {
        "schema_version": {
            "type": "string",
            "pattern": r"^\d+\.\d+\.\d+$",
            "description": "Semantic version (MAJOR.MINOR.PATCH)",
        },
        "protocol": {
            "type": "string",
            "enum": ["modbus_tcp", "ethernetip", "s7comm", "dnp3"],
        },
        "source_address": {"type": "string", "minLength": 1},
        "destination_address": {"type": "string", "minLength": 1},
        "mac_address": {"type": ["string", "null"]},
        "ip_address": {"type": ["string", "null"]},
        "vendor": {"type": ["string", "null"], "maxLength": 128},
        "model": {"type": ["string", "null"], "maxLength": 128},
        "firmware_version": {"type": ["string", "null"], "maxLength": 64},
        "device_type": {
            "type": ["string", "null"],
            "enum": ["PLC", "RTU", "HMI", "IED", None],
        },
        "serial_number": {"type": ["string", "null"]},
        "protocol_data": {"type": "object"},
        "parsing_status": {
            "type": "string",
            "enum": ["complete", "partial", "no_identity"],
        },
        "binary_fields": {
            "type": "object",
            "additionalProperties": {"type": "string"},
            "description": "Base64-encoded binary field values",
        },
    },
    "additionalProperties": False,
}

# Registry of schemas by version
SCHEMA_REGISTRY: dict[str, dict[str, Any]] = {
    "1.0.0": DEVICE_FINGERPRINT_SCHEMA_V1,
}


class SerializationError(Exception):
    """Raised when serialization fails."""

    pass


class DeserializationError(Exception):
    """Raised when deserialization fails due to validation errors."""

    def __init__(self, message: str, constraint: str | None = None):
        self.constraint = constraint
        super().__init__(message)


def serialize_fingerprint(fp: DeviceFingerprint) -> str:
    """Serialize a DeviceFingerprint to JSON string.

    Produces JSON with:
    - All fields from the DeviceFingerprint model
    - Binary fields encoded as base64 strings
    - schema_version field for forward compatibility
    - Numeric values preserved at original precision

    Args:
        fp: A valid DeviceFingerprint instance.

    Returns:
        JSON string representation of the fingerprint.

    Raises:
        SerializationError: If serialization fails.
    """
    try:
        # Use Pydantic's model_dump to get a dict, then serialize to JSON
        data = fp.model_dump()

        # Ensure binary_fields values are valid base64 strings
        # (they should already be base64-encoded in the model)
        if data.get("binary_fields"):
            for key, value in data["binary_fields"].items():
                if isinstance(value, bytes):
                    data["binary_fields"][key] = base64.b64encode(value).decode("ascii")

        return json.dumps(data, ensure_ascii=False)
    except Exception as e:
        raise SerializationError(f"Failed to serialize DeviceFingerprint: {e}") from e


def deserialize_fingerprint(json_str: str) -> DeviceFingerprint:
    """Deserialize a JSON string to a DeviceFingerprint.

    Validates the input against the versioned JSON Schema and restores
    all data types to their original form.

    Args:
        json_str: JSON string to deserialize.

    Returns:
        A validated DeviceFingerprint instance.

    Raises:
        DeserializationError: If the input is invalid JSON, missing required
            fields, or has an unsupported schema version.
    """
    # Step 1: Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise DeserializationError(
            f"Invalid JSON: {e}",
            constraint="valid_json",
        ) from e

    # Step 2: Verify it's a JSON object
    if not isinstance(data, dict):
        raise DeserializationError(
            "Invalid JSON: expected a JSON object, got "
            f"{type(data).__name__}",
            constraint="json_object",
        )

    # Step 3: Check schema_version field exists
    if "schema_version" not in data:
        raise DeserializationError(
            "Missing required field: 'schema_version'",
            constraint="required_field",
        )

    # Step 4: Validate schema version is supported
    schema_version = data["schema_version"]
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise DeserializationError(
            f"Unsupported schema version: '{schema_version}'. "
            f"Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}",
            constraint="schema_version",
        )

    # Step 5: Validate against JSON Schema
    schema = SCHEMA_REGISTRY[schema_version]
    validation_errors = _validate_against_schema(data, schema)
    if validation_errors:
        raise DeserializationError(
            f"Schema validation failed: {'; '.join(validation_errors)}",
            constraint="schema_validation",
        )

    # Step 6: Construct DeviceFingerprint from validated data
    try:
        return DeviceFingerprint(**data)
    except Exception as e:
        raise DeserializationError(
            f"Failed to construct DeviceFingerprint: {e}",
            constraint="model_validation",
        ) from e


def _validate_against_schema(data: dict, schema: dict[str, Any]) -> list[str]:
    """Validate data against a JSON Schema document.

    Performs structural validation without requiring jsonschema library.
    Returns a list of validation error messages (empty if valid).
    """
    errors: list[str] = []
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    # Check required fields
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return errors

    # Check additionalProperties
    if schema.get("additionalProperties") is False:
        allowed_keys = set(properties.keys())
        extra_keys = set(data.keys()) - allowed_keys
        if extra_keys:
            errors.append(
                f"Additional properties not allowed: {sorted(extra_keys)}"
            )

    # Validate each field against its schema
    for field_name, field_value in data.items():
        if field_name not in properties:
            continue

        field_schema = properties[field_name]
        field_errors = _validate_field(field_name, field_value, field_schema)
        errors.extend(field_errors)

    return errors


def _validate_field(
    field_name: str, value: Any, field_schema: dict[str, Any]
) -> list[str]:
    """Validate a single field value against its schema definition."""
    errors: list[str] = []

    # Handle type validation
    field_type = field_schema.get("type")
    if field_type:
        if not _check_type(value, field_type):
            errors.append(
                f"Field '{field_name}': expected type {field_type}, "
                f"got {type(value).__name__}"
            )
            return errors  # Skip further checks if type is wrong

    # Handle enum validation
    if "enum" in field_schema and value is not None:
        if value not in field_schema["enum"]:
            errors.append(
                f"Field '{field_name}': value '{value}' not in allowed values "
                f"{field_schema['enum']}"
            )

    # Handle maxLength validation
    if "maxLength" in field_schema and isinstance(value, str):
        if len(value) > field_schema["maxLength"]:
            errors.append(
                f"Field '{field_name}': string length {len(value)} exceeds "
                f"maximum {field_schema['maxLength']}"
            )

    # Handle minLength validation
    if "minLength" in field_schema and isinstance(value, str):
        if len(value) < field_schema["minLength"]:
            errors.append(
                f"Field '{field_name}': string length {len(value)} is less than "
                f"minimum {field_schema['minLength']}"
            )

    # Handle pattern validation
    if "pattern" in field_schema and isinstance(value, str):
        import re

        if not re.match(field_schema["pattern"], value):
            errors.append(
                f"Field '{field_name}': value '{value}' does not match "
                f"pattern '{field_schema['pattern']}'"
            )

    # Handle nested object validation (for protocol_data and binary_fields)
    if field_type == "object" and isinstance(value, dict):
        additional_props = field_schema.get("additionalProperties")
        if isinstance(additional_props, dict):
            for k, v in value.items():
                sub_errors = _validate_field(f"{field_name}.{k}", v, additional_props)
                errors.extend(sub_errors)

    return errors


def _check_type(value: Any, type_spec: str | list[str]) -> bool:
    """Check if a value matches the JSON Schema type specification."""
    if isinstance(type_spec, list):
        return any(_check_single_type(value, t) for t in type_spec)
    return _check_single_type(value, type_spec)


def _check_single_type(value: Any, type_name: str) -> bool:
    """Check if a value matches a single JSON Schema type."""
    if type_name == "null":
        return value is None
    elif type_name == "string":
        return isinstance(value, str)
    elif type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    elif type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    elif type_name == "boolean":
        return isinstance(value, bool)
    elif type_name == "array":
        return isinstance(value, list)
    elif type_name == "object":
        return isinstance(value, dict)
    return False


def get_schema(version: str) -> dict[str, Any] | None:
    """Get the JSON Schema document for a given version.

    Args:
        version: Semantic version string (e.g., "1.0.0").

    Returns:
        The schema dict if the version is supported, None otherwise.
    """
    return SCHEMA_REGISTRY.get(version)


def get_supported_versions() -> set[str]:
    """Get the set of supported schema versions."""
    return SUPPORTED_SCHEMA_VERSIONS.copy()
