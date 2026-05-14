"""Scan management API router.

Implements CRUD endpoints for Scan_Job schedules at /api/scans:
- GET /api/scans - List scan jobs (viewer)
- POST /api/scans - Create scan job (admin)
- GET /api/scans/{scan_id} - Get scan job details (viewer)
- PUT /api/scans/{scan_id} - Update scan job (admin)
- DELETE /api/scans/{scan_id} - Delete scan job (admin)
- POST /api/scans/{scan_id}/trigger - Manual scan trigger (admin)
- GET /api/scans/{scan_id}/history - Get historical scan results (viewer)

Protects writes with admin RBAC, reads with viewer RBAC.
Validates cron schedule minimum interval of 5 minutes.

Requirements: 11.1, 11.3, 11.4, 11.5
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_admin, require_viewer
from app.db.session import get_session
from app.models.database import ScanJob, ScanHistory

scans_router = APIRouter(prefix="/api/scans", tags=["scans"])

# Minimum interval between scan executions (5 minutes)
MIN_INTERVAL_MINUTES = 5


# --- Request/Response Models ---


class ScanJobCreateRequest(BaseModel):
    """Request body for creating a scan job."""

    name: str = Field(min_length=1, max_length=128)
    schedule: Optional[str] = None
    target_subnet: Optional[str] = None
    active_probing_enabled: bool = False


class ScanJobUpdateRequest(BaseModel):
    """Request body for updating a scan job."""

    name: Optional[str] = Field(None, min_length=1, max_length=128)
    schedule: Optional[str] = None
    target_subnet: Optional[str] = None
    active_probing_enabled: Optional[bool] = None


class ScanJobResponse(BaseModel):
    """Response model for a scan job."""

    id: UUID
    name: str
    schedule: Optional[str] = None
    target_subnet: Optional[str] = None
    active_probing_enabled: bool
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    devices_discovered: int
    new_devices: int
    alerts_generated: int
    failure_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Response model for a scan history entry."""

    id: UUID
    scan_job_id: UUID
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    devices_discovered: int
    new_devices: int
    alerts_generated: int
    failure_reason: Optional[str] = None

    model_config = {"from_attributes": True}


class PaginatedScanJobsResponse(BaseModel):
    """Paginated response for scan jobs list."""

    items: list[ScanJobResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class PaginatedScanHistoryResponse(BaseModel):
    """Paginated response for scan history."""

    items: list[ScanHistoryResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class ManualTriggerResponse(BaseModel):
    """Response for manual scan trigger."""

    scan_job_id: UUID
    status: str
    message: str
    triggered_at: datetime


# --- Cron Validation ---


def validate_cron_schedule(schedule: str) -> None:
    """Validate a cron expression and ensure minimum interval of 5 minutes.

    Args:
        schedule: Cron expression string.

    Raises:
        HTTPException: 422 if cron expression is invalid or interval < 5 minutes.
    """
    # Validate cron expression syntax
    if not croniter.is_valid(schedule):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid cron expression: '{schedule}'",
        )

    # Check minimum interval by computing the gap between two consecutive executions
    try:
        base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        cron = croniter(schedule, base_time)
        first_execution = cron.get_next(datetime)
        second_execution = cron.get_next(datetime)
        interval_seconds = (second_execution - first_execution).total_seconds()

        if interval_seconds < MIN_INTERVAL_MINUTES * 60:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cron schedule interval must be at least {MIN_INTERVAL_MINUTES} minutes. "
                f"Provided schedule executes every {interval_seconds / 60:.1f} minutes.",
            )
    except (ValueError, KeyError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid cron expression: {str(e)}",
        )


# --- Endpoints ---


@scans_router.get("", response_model=PaginatedScanJobsResponse)
async def list_scan_jobs(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_viewer),
) -> PaginatedScanJobsResponse:
    """List all scan job schedules with pagination.

    Returns scan jobs ordered by creation date descending.
    Default page size is 20, maximum is 100.

    Requirements: 11.3
    """
    # Count total records
    count_query = select(func.count()).select_from(ScanJob)
    total_result = await session.execute(count_query)
    total = total_result.scalar_one()

    # Fetch paginated results
    offset = (page - 1) * page_size
    query = (
        select(ScanJob)
        .order_by(ScanJob.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(query)
    scan_jobs = result.scalars().all()

    total_pages = max(1, (total + page_size - 1) // page_size)

    return PaginatedScanJobsResponse(
        items=[ScanJobResponse.model_validate(job) for job in scan_jobs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@scans_router.post("", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def create_scan_job(
    request: ScanJobCreateRequest,
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_admin),
) -> ScanJobResponse:
    """Create a new scan job schedule.

    Validates cron schedule minimum interval of 5 minutes.
    Requires admin role.

    Requirements: 11.1, 11.3
    """
    # Validate cron schedule if provided
    if request.schedule:
        validate_cron_schedule(request.schedule)

    # Create scan job record
    scan_job = ScanJob(
        name=request.name,
        schedule=request.schedule,
        target_subnet=request.target_subnet,
        active_probing_enabled=request.active_probing_enabled,
        status="scheduled",
    )

    session.add(scan_job)
    await session.commit()
    await session.refresh(scan_job)

    return ScanJobResponse.model_validate(scan_job)


@scans_router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan_job(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_viewer),
) -> ScanJobResponse:
    """Get a specific scan job by ID.

    Requirements: 11.3
    """
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan_job = result.scalar_one_or_none()

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job with id '{scan_id}' not found",
        )

    return ScanJobResponse.model_validate(scan_job)


@scans_router.put("/{scan_id}", response_model=ScanJobResponse)
async def update_scan_job(
    scan_id: UUID,
    request: ScanJobUpdateRequest,
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_admin),
) -> ScanJobResponse:
    """Update an existing scan job schedule.

    Validates cron schedule minimum interval of 5 minutes if schedule is updated.
    Requires admin role.

    Requirements: 11.1, 11.3
    """
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan_job = result.scalar_one_or_none()

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job with id '{scan_id}' not found",
        )

    # Validate new cron schedule if provided
    if request.schedule is not None:
        if request.schedule:  # Non-empty string
            validate_cron_schedule(request.schedule)
        scan_job.schedule = request.schedule if request.schedule else None

    if request.name is not None:
        scan_job.name = request.name

    if request.target_subnet is not None:
        scan_job.target_subnet = request.target_subnet if request.target_subnet else None

    if request.active_probing_enabled is not None:
        scan_job.active_probing_enabled = request.active_probing_enabled

    scan_job.updated_at = datetime.now(timezone.utc)

    await session.commit()
    await session.refresh(scan_job)

    return ScanJobResponse.model_validate(scan_job)


@scans_router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_job(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_admin),
) -> None:
    """Delete a scan job schedule.

    Also deletes associated scan history records (cascade).
    Requires admin role.

    Requirements: 11.3
    """
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan_job = result.scalar_one_or_none()

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job with id '{scan_id}' not found",
        )

    await session.delete(scan_job)
    await session.commit()


@scans_router.post("/{scan_id}/trigger", response_model=ManualTriggerResponse)
async def trigger_manual_scan(
    scan_id: UUID,
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_admin),
) -> ManualTriggerResponse:
    """Manually trigger a scan job for immediate execution.

    The scan will begin executing within 5 seconds regardless of the
    configured schedule. Requires admin role.

    If the scan is already running, returns a conflict error.

    Requirements: 11.5
    """
    result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan_job = result.scalar_one_or_none()

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job with id '{scan_id}' not found",
        )

    # Check if scan is already running (overlap detection)
    if scan_job.status == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan job is already running. Cannot trigger while previous execution is in progress.",
        )

    # Update scan job status to running and record start time
    triggered_at = datetime.now(timezone.utc)
    scan_job.status = "running"
    scan_job.started_at = triggered_at
    scan_job.updated_at = triggered_at

    # Create a scan history entry for this manual trigger
    history_entry = ScanHistory(
        scan_job_id=scan_job.id,
        status="running",
        started_at=triggered_at,
    )
    session.add(history_entry)

    await session.commit()
    await session.refresh(scan_job)

    return ManualTriggerResponse(
        scan_job_id=scan_job.id,
        status="running",
        message="Scan triggered successfully. Execution will begin within 5 seconds.",
        triggered_at=triggered_at,
    )


@scans_router.get("/{scan_id}/history", response_model=PaginatedScanHistoryResponse)
async def get_scan_history(
    scan_id: UUID,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (default 20, max 100)"),
    start_date: Optional[datetime] = Query(None, description="Filter results from this date (inclusive)"),
    end_date: Optional[datetime] = Query(None, description="Filter results until this date (inclusive)"),
    session: AsyncSession = Depends(get_session),
    _current_user=Depends(require_viewer),
) -> PaginatedScanHistoryResponse:
    """Get historical scan results for a specific scan job.

    Supports pagination (default 20 results per page, maximum 100)
    and filtering by date range.

    Requirements: 11.4
    """
    # Verify scan job exists
    job_result = await session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan_job = job_result.scalar_one_or_none()

    if scan_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan job with id '{scan_id}' not found",
        )

    # Build query with filters
    base_filter = ScanHistory.scan_job_id == scan_id
    filters = [base_filter]

    if start_date is not None:
        filters.append(ScanHistory.started_at >= start_date)
    if end_date is not None:
        filters.append(ScanHistory.started_at <= end_date)

    combined_filter = and_(*filters)

    # Count total matching records
    count_query = select(func.count()).select_from(ScanHistory).where(combined_filter)
    total_result = await session.execute(count_query)
    total = total_result.scalar_one()

    # Fetch paginated results ordered by started_at descending
    offset = (page - 1) * page_size
    query = (
        select(ScanHistory)
        .where(combined_filter)
        .order_by(ScanHistory.started_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(query)
    history_entries = result.scalars().all()

    total_pages = max(1, (total + page_size - 1) // page_size)

    return PaginatedScanHistoryResponse(
        items=[ScanHistoryResponse.model_validate(entry) for entry in history_entries],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
