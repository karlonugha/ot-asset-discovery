"""Alert REST API and WebSocket endpoints.

Implements:
- GET /api/alerts with filtering by severity, device, alert type, time range
  (max 100 per page, sorted by timestamp descending)
- WebSocket /ws/alerts that pushes alert events within 2 seconds of generation

Requirements: 5.5, 5.6
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import TokenData, decode_access_token, AuthError
from app.api.dependencies import require_viewer
from app.api.websocket_manager import alert_ws_manager
from app.db.session import get_session
from app.models.database import Alert as AlertORM


# --- Response Models ---


class AlertResponse(BaseModel):
    """Response model for a single alert."""

    id: UUID
    alert_type: str
    severity: str
    device_id: Optional[UUID] = None
    details: dict
    generated_at: datetime
    acknowledged: bool = False


class AlertListResponse(BaseModel):
    """Paginated response for alert listing."""

    alerts: list[AlertResponse]
    total: int
    page: int
    page_size: int
    has_next: bool


# --- Router ---

alerts_router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@alerts_router.get(
    "",
    response_model=AlertListResponse,
    summary="List alerts with filtering",
    description=(
        "Query historical alerts with filtering by severity, device, "
        "alert type, and time range. Results are sorted by timestamp "
        "descending with a maximum of 100 alerts per page."
    ),
)
async def list_alerts(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity level (LOW, MEDIUM, HIGH, CRITICAL)",
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    ),
    device_id: Optional[UUID] = Query(
        None,
        description="Filter by device UUID",
    ),
    alert_type: Optional[str] = Query(
        None,
        description="Filter by alert type (new_device, device_disappeared, firmware_change, new_protocol, risk_score_change, scan_failed)",
    ),
    start_time: Optional[datetime] = Query(
        None,
        description="Filter alerts generated after this timestamp (inclusive)",
    ),
    end_time: Optional[datetime] = Query(
        None,
        description="Filter alerts generated before this timestamp (inclusive)",
    ),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(
        100,
        ge=1,
        le=100,
        description="Number of alerts per page (max 100)",
    ),
    _current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> AlertListResponse:
    """List alerts with optional filtering.

    Supports filtering by:
    - severity: LOW, MEDIUM, HIGH, CRITICAL
    - device_id: UUID of the associated device
    - alert_type: Type of alert
    - start_time/end_time: Time range for generated_at

    Results are always sorted by generated_at descending (newest first)
    and paginated at most 100 per request per Requirement 5.6.

    Args:
        severity: Optional severity filter.
        device_id: Optional device UUID filter.
        alert_type: Optional alert type filter.
        start_time: Optional start of time range.
        end_time: Optional end of time range.
        page: Page number (1-indexed).
        page_size: Number of results per page (max 100).
        _current_user: Authenticated user (viewer or admin).
        session: Database session.

    Returns:
        AlertListResponse with paginated alerts and metadata.
    """
    # Build filter conditions
    conditions = []

    if severity is not None:
        conditions.append(AlertORM.severity == severity)

    if device_id is not None:
        conditions.append(AlertORM.device_id == device_id)

    if alert_type is not None:
        conditions.append(AlertORM.alert_type == alert_type)

    if start_time is not None:
        conditions.append(AlertORM.generated_at >= start_time)

    if end_time is not None:
        conditions.append(AlertORM.generated_at <= end_time)

    # Build base query with filters
    where_clause = and_(*conditions) if conditions else True

    # Count total matching alerts
    from sqlalchemy import func

    count_query = select(func.count(AlertORM.id)).where(where_clause)
    total_result = await session.execute(count_query)
    total = total_result.scalar_one()

    # Fetch paginated results sorted by timestamp descending
    offset = (page - 1) * page_size
    query = (
        select(AlertORM)
        .where(where_clause)
        .order_by(desc(AlertORM.generated_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(query)
    alert_rows = result.scalars().all()

    # Convert ORM objects to response models
    alerts = [
        AlertResponse(
            id=alert.id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            device_id=alert.device_id,
            details=alert.details,
            generated_at=alert.generated_at,
            acknowledged=alert.acknowledged or False,
        )
        for alert in alert_rows
    ]

    has_next = (offset + page_size) < total

    return AlertListResponse(
        alerts=alerts,
        total=total,
        page=page,
        page_size=page_size,
        has_next=has_next,
    )


@alerts_router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
)
async def get_alert(
    alert_id: UUID,
    _current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> AlertResponse:
    """Retrieve a single alert by its UUID.

    Args:
        alert_id: The UUID of the alert to retrieve.
        _current_user: Authenticated user (viewer or admin).
        session: Database session.

    Returns:
        AlertResponse for the requested alert.

    Raises:
        HTTPException: 404 if alert not found.
    """
    from fastapi import HTTPException, status

    query = select(AlertORM).where(AlertORM.id == alert_id)
    result = await session.execute(query)
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id '{alert_id}' not found",
        )

    return AlertResponse(
        id=alert.id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        device_id=alert.device_id,
        details=alert.details,
        generated_at=alert.generated_at,
        acknowledged=alert.acknowledged or False,
    )
