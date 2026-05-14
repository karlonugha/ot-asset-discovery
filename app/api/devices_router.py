"""Device CRUD endpoints with filtering, pagination, and RBAC.

Implements:
- GET /api/devices: List devices with filtering by vendor, model, protocol, subnet, risk score
- GET /api/devices/{device_id}: Get device detail with paginated historical attribute changes
- POST /api/devices: Create a new device (admin only)
- PUT /api/devices/{device_id}: Update a device (admin only)
- DELETE /api/devices/{device_id}: Delete a device (admin only)

Pagination: default 50 records, max 500 per response.
Historical changes: paginated with default 100 entries per response.

Requirements: 4.6, 4.7
"""

import ipaddress
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_admin, require_viewer
from app.api.auth import TokenData
from app.db.device_repository import (
    DeviceRepository,
    DuplicateDeviceError,
    ProtocolLimitExceededError,
)
from app.db.session import get_session
from app.models.database import Device as DeviceModel, DeviceHistory

devices_router = APIRouter(prefix="/api/devices", tags=["devices"])


# --- Request/Response Models ---


class DeviceCreateRequest(BaseModel):
    """Request body for creating a new device."""

    mac_address: str = Field(description="Device MAC address")
    ip_address: str = Field(description="Device IP address")
    vendor: Optional[str] = Field(None, max_length=128)
    model: Optional[str] = Field(None, max_length=128)
    firmware_version: Optional[str] = Field(None, max_length=64)
    device_type: Optional[str] = Field(None, description="PLC, RTU, HMI, or IED")
    protocols: list[str] = Field(default_factory=list, description="Detected protocols (max 20)")
    fingerprint: Optional[dict] = None


class DeviceUpdateRequest(BaseModel):
    """Request body for updating a device."""

    vendor: Optional[str] = Field(None, max_length=128)
    model: Optional[str] = Field(None, max_length=128)
    firmware_version: Optional[str] = Field(None, max_length=64)
    device_type: Optional[str] = None
    protocols: Optional[list[str]] = Field(None, description="Detected protocols (max 20)")
    risk_score: Optional[int] = Field(None, ge=0, le=100)


class DeviceHistoryResponse(BaseModel):
    """Response model for a single device history entry."""

    id: UUID
    device_id: UUID
    field_name: str
    old_value: Optional[str]
    new_value: Optional[str]
    changed_at: datetime


class DeviceResponse(BaseModel):
    """Response model for a device record."""

    id: UUID
    mac_address: str
    ip_address: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    device_type: Optional[str] = None
    protocols: list[str] = Field(default_factory=list)
    risk_score: int = 0
    fingerprint: Optional[dict] = None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


class DeviceDetailResponse(DeviceResponse):
    """Response model for device detail including historical changes."""

    history: list[DeviceHistoryResponse] = Field(default_factory=list)
    history_total: int = 0


class PaginatedDeviceResponse(BaseModel):
    """Paginated response for device listing."""

    items: list[DeviceResponse]
    total: int
    limit: int
    offset: int


# --- Helper Functions ---


def _device_to_response(device: DeviceModel) -> DeviceResponse:
    """Convert a SQLAlchemy Device model to a DeviceResponse."""
    return DeviceResponse(
        id=device.id,
        mac_address=str(device.mac_address),
        ip_address=str(device.ip_address),
        vendor=device.vendor,
        model=device.model,
        firmware_version=device.firmware_version,
        device_type=device.device_type,
        protocols=device.protocols or [],
        risk_score=device.risk_score or 0,
        fingerprint=device.fingerprint,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        created_at=device.created_at,
        updated_at=device.updated_at,
    )


def _history_to_response(entry: DeviceHistory) -> DeviceHistoryResponse:
    """Convert a SQLAlchemy DeviceHistory model to a DeviceHistoryResponse."""
    return DeviceHistoryResponse(
        id=entry.id,
        device_id=entry.device_id,
        field_name=entry.field_name,
        old_value=entry.old_value,
        new_value=entry.new_value,
        changed_at=entry.changed_at,
    )


def _validate_subnet_filter(subnet: str) -> bool:
    """Validate that a subnet string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False


# --- Endpoints ---


@devices_router.get("", response_model=PaginatedDeviceResponse)
async def list_devices(
    limit: int = Query(default=50, ge=1, le=500, description="Records per page (max 500)"),
    offset: int = Query(default=0, ge=0, description="Number of records to skip"),
    vendor: Optional[str] = Query(None, description="Filter by vendor (case-insensitive partial match)"),
    model: Optional[str] = Query(None, description="Filter by model (case-insensitive partial match)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    subnet: Optional[str] = Query(None, description="Filter by subnet (CIDR notation, e.g. 192.168.1.0/24)"),
    risk_score_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    risk_score_max: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score"),
    current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> PaginatedDeviceResponse:
    """List devices with optional filtering and pagination.

    Filters:
    - vendor: Case-insensitive partial match on vendor name
    - model: Case-insensitive partial match on model name
    - protocol: Device must have this protocol in its protocols list
    - subnet: Device IP must be within this CIDR subnet
    - risk_score_min/risk_score_max: Risk score range filter

    Pagination defaults to 50 records per page, max 500.

    Requires: viewer role (read access).
    """
    # Enforce max limit
    limit = min(limit, 500)

    # Build query
    stmt = select(DeviceModel)
    count_stmt = select(func.count(DeviceModel.id))

    # Apply filters
    if vendor is not None:
        stmt = stmt.where(DeviceModel.vendor.ilike(f"%{vendor}%"))
        count_stmt = count_stmt.where(DeviceModel.vendor.ilike(f"%{vendor}%"))

    if model is not None:
        stmt = stmt.where(DeviceModel.model.ilike(f"%{model}%"))
        count_stmt = count_stmt.where(DeviceModel.model.ilike(f"%{model}%"))

    if protocol is not None:
        stmt = stmt.where(DeviceModel.protocols.any(protocol))
        count_stmt = count_stmt.where(DeviceModel.protocols.any(protocol))

    if subnet is not None:
        if not _validate_subnet_filter(subnet):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid subnet CIDR notation: '{subnet}'",
            )
        # Use PostgreSQL inet operator for subnet containment
        subnet_filter = DeviceModel.ip_address.op("<<=")(text(f"'{subnet}'::cidr"))
        stmt = stmt.where(subnet_filter)
        count_stmt = count_stmt.where(subnet_filter)

    if risk_score_min is not None:
        stmt = stmt.where(DeviceModel.risk_score >= risk_score_min)
        count_stmt = count_stmt.where(DeviceModel.risk_score >= risk_score_min)

    if risk_score_max is not None:
        stmt = stmt.where(DeviceModel.risk_score <= risk_score_max)
        count_stmt = count_stmt.where(DeviceModel.risk_score <= risk_score_max)

    # Get total count
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Apply pagination and ordering
    stmt = stmt.order_by(DeviceModel.last_seen.desc()).limit(limit).offset(offset)

    result = await session.execute(stmt)
    devices = result.scalars().all()

    return PaginatedDeviceResponse(
        items=[_device_to_response(d) for d in devices],
        total=total,
        limit=limit,
        offset=offset,
    )


@devices_router.get("/{device_id}", response_model=DeviceDetailResponse)
async def get_device(
    device_id: UUID,
    history_limit: int = Query(default=100, ge=1, le=1000, description="History entries per page"),
    history_offset: int = Query(default=0, ge=0, description="History entries to skip"),
    current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> DeviceDetailResponse:
    """Get device detail including paginated historical attribute changes.

    Returns the complete device record plus its audit history,
    paginated with a default of 100 change entries per response.

    Requires: viewer role (read access).
    """
    repo = DeviceRepository(session)
    device = await repo.get_device_by_id(device_id)

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    # Get paginated history
    history_entries = await repo.get_device_history(
        device_id=device_id,
        limit=history_limit,
        offset=history_offset,
    )
    history_total = await repo.get_device_history_count(device_id)

    return DeviceDetailResponse(
        id=device.id,
        mac_address=str(device.mac_address),
        ip_address=str(device.ip_address),
        vendor=device.vendor,
        model=device.model,
        firmware_version=device.firmware_version,
        device_type=device.device_type,
        protocols=device.protocols or [],
        risk_score=device.risk_score or 0,
        fingerprint=device.fingerprint,
        first_seen=device.first_seen,
        last_seen=device.last_seen,
        created_at=device.created_at,
        updated_at=device.updated_at,
        history=[_history_to_response(h) for h in history_entries],
        history_total=history_total,
    )


@devices_router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def create_device(
    request: DeviceCreateRequest,
    current_user: TokenData = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> DeviceResponse:
    """Create a new device record.

    Enforces MAC+IP uniqueness. If a device with the same MAC+IP
    already exists, returns 409 Conflict.

    Requires: admin role (write access).
    """
    repo = DeviceRepository(session)

    try:
        device = await repo.create_device(
            mac_address=request.mac_address,
            ip_address=request.ip_address,
            vendor=request.vendor,
            model=request.model,
            firmware_version=request.firmware_version,
            device_type=request.device_type,
            protocols=request.protocols,
            fingerprint=request.fingerprint,
        )
        await session.commit()
        return _device_to_response(device)

    except DuplicateDeviceError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except ProtocolLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@devices_router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: UUID,
    request: DeviceUpdateRequest,
    current_user: TokenData = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> DeviceResponse:
    """Update a device record.

    Updates only the fields provided in the request body.
    Records audit history for attribute changes.

    Requires: admin role (write access).
    """
    repo = DeviceRepository(session)
    device = await repo.get_device_by_id(device_id)

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    from datetime import timezone

    now = datetime.now(timezone.utc)

    # Update provided fields and record history for changes
    try:
        if request.vendor is not None and request.vendor != device.vendor:
            await repo.update_device_attribute(device_id, "vendor", request.vendor)
            # Refresh device after update
            device = await repo.get_device_by_id(device_id)

        if request.model is not None and request.model != device.model:
            await repo.update_device_attribute(device_id, "model", request.model)
            device = await repo.get_device_by_id(device_id)

        if request.firmware_version is not None and request.firmware_version != device.firmware_version:
            await repo.update_device_attribute(device_id, "firmware_version", request.firmware_version)
            device = await repo.get_device_by_id(device_id)

        if request.device_type is not None and request.device_type != device.device_type:
            await repo.update_device_attribute(device_id, "device_type", request.device_type)
            device = await repo.get_device_by_id(device_id)

        if request.protocols is not None:
            protocols_str = ",".join(request.protocols) if request.protocols else None
            current_protocols_str = ",".join(device.protocols) if device.protocols else None
            if protocols_str != current_protocols_str:
                await repo.update_device_attribute(device_id, "protocols", protocols_str)
                device = await repo.get_device_by_id(device_id)

        if request.risk_score is not None and request.risk_score != device.risk_score:
            device.risk_score = request.risk_score
            device.updated_at = now
            await session.flush()

        await session.commit()
        # Refresh to get final state
        device = await repo.get_device_by_id(device_id)
        return _device_to_response(device)

    except ProtocolLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@devices_router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    current_user: TokenData = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Delete a device and its associated history.

    Requires: admin role (write access).
    """
    repo = DeviceRepository(session)
    deleted = await repo.delete_device(device_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_id} not found",
        )

    await session.commit()
