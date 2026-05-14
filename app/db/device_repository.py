"""Device Inventory data access layer.

Implements device creation, re-detection merge logic, MAC+IP uniqueness
enforcement, audit history recording, and protocol/history limits.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import Device, DeviceHistory


# Maximum number of protocols per device (Requirement 4.1)
MAX_PROTOCOLS_PER_DEVICE = 20

# Minimum number of history entries to retain per device (Requirement 4.5)
MAX_HISTORY_ENTRIES_PER_DEVICE = 1000


class DeviceInventoryError(Exception):
    """Base exception for device inventory operations."""
    pass


class DuplicateDeviceError(DeviceInventoryError):
    """Raised when attempting to insert a device with an existing MAC+IP combination."""
    pass


class ProtocolLimitExceededError(DeviceInventoryError):
    """Raised when attempting to add more than 20 protocols to a device."""
    pass


class DeviceRepository:
    """Data access layer for the Device_Inventory.

    Provides methods for device creation, re-detection merge, uniqueness
    enforcement, audit history recording, and constraint enforcement.
    """

    def __init__(self, session: AsyncSession):
        self._session = session

    async def create_device(
        self,
        mac_address: str,
        ip_address: str,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        firmware_version: Optional[str] = None,
        device_type: Optional[str] = None,
        protocols: Optional[list[str]] = None,
        fingerprint: Optional[dict] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
    ) -> Device:
        """Create a new device record in the inventory.

        Enforces MAC+IP uniqueness (Requirement 4.3). If a device with the
        same MAC+IP already exists, raises DuplicateDeviceError (Requirement 4.4).
        Enforces maximum 20 protocols per device (Requirement 4.1).

        Args:
            mac_address: Device MAC address.
            ip_address: Device IP address.
            vendor: Device vendor (max 128 chars), may be None.
            model: Device model (max 128 chars), may be None.
            firmware_version: Firmware version (max 64 chars), may be None.
            device_type: Device type (PLC, RTU, HMI, IED), may be None.
            protocols: List of detected protocols (max 20).
            fingerprint: Full DeviceFingerprint data as dict.
            first_seen: First detection timestamp (defaults to now).
            last_seen: Last detection timestamp (defaults to now).

        Returns:
            The created Device record.

        Raises:
            DuplicateDeviceError: If MAC+IP combination already exists.
            ProtocolLimitExceededError: If protocols list exceeds 20 entries.
        """
        if protocols is None:
            protocols = []

        if len(protocols) > MAX_PROTOCOLS_PER_DEVICE:
            raise ProtocolLimitExceededError(
                f"Cannot assign more than {MAX_PROTOCOLS_PER_DEVICE} protocols to a device. "
                f"Got {len(protocols)}."
            )

        # Check for existing device with same MAC+IP (Requirement 4.3, 4.4)
        existing = await self.get_device_by_mac_ip(mac_address, ip_address)
        if existing is not None:
            raise DuplicateDeviceError(
                f"Device with MAC={mac_address} and IP={ip_address} already exists. "
                f"Use upsert_device() for re-detection."
            )

        now = datetime.now(timezone.utc)
        device = Device(
            mac_address=mac_address,
            ip_address=ip_address,
            vendor=vendor,
            model=model,
            firmware_version=firmware_version,
            device_type=device_type,
            protocols=protocols,
            fingerprint=fingerprint,
            first_seen=first_seen or now,
            last_seen=last_seen or now,
            created_at=now,
            updated_at=now,
        )

        self._session.add(device)
        await self._session.flush()
        return device

    async def get_device_by_mac_ip(
        self, mac_address: str, ip_address: str
    ) -> Optional[Device]:
        """Look up a device by its MAC+IP combination.

        Args:
            mac_address: Device MAC address.
            ip_address: Device IP address.

        Returns:
            The Device record if found, None otherwise.
        """
        stmt = select(Device).where(
            Device.mac_address == mac_address,
            Device.ip_address == ip_address,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_device_by_id(self, device_id: UUID) -> Optional[Device]:
        """Look up a device by its primary key.

        Args:
            device_id: The device UUID.

        Returns:
            The Device record if found, None otherwise.
        """
        stmt = select(Device).where(Device.id == device_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert_device(
        self,
        mac_address: str,
        ip_address: str,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        firmware_version: Optional[str] = None,
        device_type: Optional[str] = None,
        protocols: Optional[list[str]] = None,
        fingerprint: Optional[dict] = None,
        last_seen: Optional[datetime] = None,
    ) -> tuple[Device, bool]:
        """Create or re-detect a device.

        If the device does not exist, creates it. If it already exists,
        performs re-detection merge logic (Requirement 4.2):
        - Updates last_seen timestamp
        - Fills null fields only (never overwrites non-null values)
        - Records audit history for attribute changes

        Args:
            mac_address: Device MAC address.
            ip_address: Device IP address.
            vendor: Device vendor (max 128 chars).
            model: Device model (max 128 chars).
            firmware_version: Firmware version (max 64 chars).
            device_type: Device type.
            protocols: List of detected protocols.
            fingerprint: Full DeviceFingerprint data as dict.
            last_seen: Detection timestamp (defaults to now).

        Returns:
            Tuple of (device, is_new) where is_new indicates if the device
            was newly created (True) or re-detected (False).

        Raises:
            ProtocolLimitExceededError: If protocols would exceed 20 entries.
        """
        existing = await self.get_device_by_mac_ip(mac_address, ip_address)

        if existing is None:
            # New device - create it
            device = await self.create_device(
                mac_address=mac_address,
                ip_address=ip_address,
                vendor=vendor,
                model=model,
                firmware_version=firmware_version,
                device_type=device_type,
                protocols=protocols,
                fingerprint=fingerprint,
                last_seen=last_seen,
            )
            return device, True

        # Re-detection - merge logic (Requirement 4.2)
        now = last_seen or datetime.now(timezone.utc)
        await self._merge_device(existing, vendor, model, firmware_version,
                                 device_type, protocols, fingerprint, now)
        return existing, False

    async def _merge_device(
        self,
        device: Device,
        vendor: Optional[str],
        model: Optional[str],
        firmware_version: Optional[str],
        device_type: Optional[str],
        protocols: Optional[list[str]],
        fingerprint: Optional[dict],
        last_seen: datetime,
    ) -> None:
        """Apply re-detection merge logic to an existing device.

        Updates last_seen, fills null fields only, never overwrites non-null.
        Records audit history for tracked attribute changes.

        Requirement 4.2: Update last-seen timestamp and merge newly discovered
        attributes into fields that are currently null, without overwriting
        fields that already contain a stored value.
        """
        now = last_seen

        # Always update last_seen
        device.last_seen = now
        device.updated_at = datetime.now(timezone.utc)

        # Fill null fields only - never overwrite non-null (Requirement 4.2)
        # For vendor, model, device_type: fill if currently null
        if device.vendor is None and vendor is not None:
            await self._record_history(device.id, "vendor", device.vendor, vendor, now)
            device.vendor = vendor

        if device.model is None and model is not None:
            await self._record_history(device.id, "model", device.model, model, now)
            device.model = model

        if device.firmware_version is None and firmware_version is not None:
            await self._record_history(
                device.id, "firmware_version", device.firmware_version, firmware_version, now
            )
            device.firmware_version = firmware_version

        if device.device_type is None and device_type is not None:
            await self._record_history(device.id, "device_type", device.device_type, device_type, now)
            device.device_type = device_type

        # Merge protocols: add new protocols not already in the list
        if protocols:
            current_protocols = device.protocols or []
            new_protocols = [p for p in protocols if p not in current_protocols]
            if new_protocols:
                merged = current_protocols + new_protocols
                if len(merged) > MAX_PROTOCOLS_PER_DEVICE:
                    raise ProtocolLimitExceededError(
                        f"Cannot assign more than {MAX_PROTOCOLS_PER_DEVICE} protocols to a device. "
                        f"Merge would result in {len(merged)} protocols."
                    )
                old_value = ",".join(current_protocols) if current_protocols else None
                device.protocols = merged
                new_value = ",".join(merged)
                await self._record_history(device.id, "protocols", old_value, new_value, now)

        # Update fingerprint if device has none
        if device.fingerprint is None and fingerprint is not None:
            device.fingerprint = fingerprint

        await self._session.flush()

    async def update_device_attribute(
        self,
        device_id: UUID,
        field_name: str,
        new_value: Optional[str],
    ) -> Device:
        """Update a specific device attribute and record audit history.

        This method is for explicit attribute changes (e.g., firmware update
        detected). Unlike merge logic, this WILL overwrite existing values
        and always records history.

        Args:
            device_id: The device UUID.
            field_name: The attribute to update (firmware_version, protocols, ip_address).
            new_value: The new value for the attribute.

        Returns:
            The updated Device record.

        Raises:
            ValueError: If the device is not found or field_name is invalid.
        """
        device = await self.get_device_by_id(device_id)
        if device is None:
            raise ValueError(f"Device {device_id} not found.")

        allowed_fields = {"firmware_version", "protocols", "ip_address", "vendor", "model", "device_type"}
        if field_name not in allowed_fields:
            raise ValueError(
                f"Field '{field_name}' is not a tracked attribute. "
                f"Allowed: {allowed_fields}"
            )

        now = datetime.now(timezone.utc)
        old_value = getattr(device, field_name)

        # Convert old_value to string for history
        if isinstance(old_value, list):
            old_value_str = ",".join(old_value) if old_value else None
        else:
            old_value_str = str(old_value) if old_value is not None else None

        # Handle protocols field specially
        if field_name == "protocols":
            if new_value is not None:
                new_protocols = [p.strip() for p in new_value.split(",") if p.strip()]
                if len(new_protocols) > MAX_PROTOCOLS_PER_DEVICE:
                    raise ProtocolLimitExceededError(
                        f"Cannot assign more than {MAX_PROTOCOLS_PER_DEVICE} protocols."
                    )
                setattr(device, field_name, new_protocols)
            else:
                setattr(device, field_name, [])
        else:
            setattr(device, field_name, new_value)

        device.updated_at = now

        # Record history
        await self._record_history(device.id, field_name, old_value_str, new_value, now)
        await self._session.flush()

        return device

    async def _record_history(
        self,
        device_id: UUID,
        field_name: str,
        old_value: Optional[str],
        new_value: Optional[str],
        changed_at: datetime,
    ) -> None:
        """Record an attribute change in the audit history table.

        Enforces maximum 1000 history entries per device (Requirement 4.5).
        When the limit is reached, the oldest entries are removed to make room.

        Args:
            device_id: The device UUID.
            field_name: Name of the changed field.
            old_value: Previous value (as string).
            new_value: New value (as string).
            changed_at: Timestamp of the change.
        """
        # Create the new history entry
        history_entry = DeviceHistory(
            device_id=device_id,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            changed_at=changed_at,
        )
        self._session.add(history_entry)

        # Enforce maximum history entries per device
        await self._enforce_history_limit(device_id)

    async def _enforce_history_limit(self, device_id: UUID) -> None:
        """Ensure no more than MAX_HISTORY_ENTRIES_PER_DEVICE history entries exist.

        If the count exceeds the limit, removes the oldest entries to bring
        the total back to the maximum.
        """
        # Count current entries
        count_stmt = select(func.count(DeviceHistory.id)).where(
            DeviceHistory.device_id == device_id
        )
        result = await self._session.execute(count_stmt)
        count = result.scalar_one()

        if count > MAX_HISTORY_ENTRIES_PER_DEVICE:
            # Find IDs of entries to delete (oldest ones beyond the limit)
            excess = count - MAX_HISTORY_ENTRIES_PER_DEVICE
            oldest_stmt = (
                select(DeviceHistory.id)
                .where(DeviceHistory.device_id == device_id)
                .order_by(DeviceHistory.changed_at.asc())
                .limit(excess)
            )
            oldest_result = await self._session.execute(oldest_stmt)
            ids_to_delete = [row[0] for row in oldest_result.fetchall()]

            if ids_to_delete:
                delete_stmt = delete(DeviceHistory).where(
                    DeviceHistory.id.in_(ids_to_delete)
                )
                await self._session.execute(delete_stmt)

    async def get_device_history(
        self,
        device_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DeviceHistory]:
        """Retrieve audit history for a device, paginated.

        Args:
            device_id: The device UUID.
            limit: Maximum entries to return (default 100).
            offset: Number of entries to skip.

        Returns:
            List of DeviceHistory entries, ordered by changed_at descending.
        """
        stmt = (
            select(DeviceHistory)
            .where(DeviceHistory.device_id == device_id)
            .order_by(DeviceHistory.changed_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_device_history_count(self, device_id: UUID) -> int:
        """Get the total number of history entries for a device.

        Args:
            device_id: The device UUID.

        Returns:
            Total count of history entries.
        """
        stmt = select(func.count(DeviceHistory.id)).where(
            DeviceHistory.device_id == device_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one()

    async def list_devices(
        self,
        limit: int = 50,
        offset: int = 0,
        vendor: Optional[str] = None,
        model: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> list[Device]:
        """List devices with optional filtering.

        Args:
            limit: Maximum devices to return (default 50, max 500).
            offset: Number of devices to skip.
            vendor: Filter by vendor name (case-insensitive partial match).
            model: Filter by model name (case-insensitive partial match).
            protocol: Filter by protocol (must be in protocols array).

        Returns:
            List of Device records matching the criteria.
        """
        limit = min(limit, 500)
        stmt = select(Device)

        if vendor is not None:
            stmt = stmt.where(Device.vendor.ilike(f"%{vendor}%"))
        if model is not None:
            stmt = stmt.where(Device.model.ilike(f"%{model}%"))
        if protocol is not None:
            stmt = stmt.where(Device.protocols.any(protocol))

        stmt = stmt.order_by(Device.last_seen.desc()).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def delete_device(self, device_id: UUID) -> bool:
        """Delete a device and its associated history (cascade).

        Args:
            device_id: The device UUID.

        Returns:
            True if the device was deleted, False if not found.
        """
        device = await self.get_device_by_id(device_id)
        if device is None:
            return False

        await self._session.delete(device)
        await self._session.flush()
        return True
