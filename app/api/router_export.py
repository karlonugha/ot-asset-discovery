"""Export API endpoints for CSV, JSON, and PDF report generation.

Implements:
- GET /api/export/csv: Export device inventory as CSV
- GET /api/export/json: Export device inventory as JSON
- GET /api/export/pdf: Export device inventory as PDF report

All endpoints support the same filter parameters as the device query endpoints.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import TokenData
from app.api.dependencies import require_viewer
from app.db.session import get_session
from app.export.service import (
    ExportService,
    ExportRecordLimitExceeded,
    ExportTimeoutError,
)

export_router = APIRouter(prefix="/api/export", tags=["export"])


@export_router.get("/csv")
async def export_csv(
    vendor: Optional[str] = Query(None, description="Filter by vendor (case-insensitive partial match)"),
    model: Optional[str] = Query(None, description="Filter by model (case-insensitive partial match)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    subnet: Optional[str] = Query(None, description="Filter by subnet (CIDR notation)"),
    risk_score_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    risk_score_max: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score"),
    current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Export device inventory as CSV file.

    Returns a CSV file with a header row listing all DeviceFingerprint fields
    and one data row per matching device. Completes within 30 seconds for
    up to 10,000 records.

    For empty results, returns a CSV with headers only (Requirement 10.5).
    Rejects requests exceeding 50,000 records (Requirement 10.7).
    Returns error if export exceeds 60 seconds (Requirement 10.6).

    Requires: viewer role (read access).
    """
    service = ExportService(session)

    try:
        csv_content = await service.export_csv(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
    except ExportRecordLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except ExportTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(e),
        )

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=device_inventory.csv",
        },
    )


@export_router.get("/json")
async def export_json(
    vendor: Optional[str] = Query(None, description="Filter by vendor (case-insensitive partial match)"),
    model: Optional[str] = Query(None, description="Filter by model (case-insensitive partial match)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    subnet: Optional[str] = Query(None, description="Filter by subnet (CIDR notation)"),
    risk_score_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    risk_score_max: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score"),
    current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Export device inventory as JSON file.

    Returns a JSON file containing a valid JSON array where each element
    is a DeviceFingerprint object conforming to the schema.

    For empty results, returns an empty array (Requirement 10.5).
    Rejects requests exceeding 50,000 records (Requirement 10.7).
    Returns error if export exceeds 60 seconds (Requirement 10.6).

    Requires: viewer role (read access).
    """
    service = ExportService(session)

    try:
        json_content = await service.export_json(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
    except ExportRecordLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except ExportTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(e),
        )

    return Response(
        content=json_content,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=device_inventory.json",
        },
    )


@export_router.get("/pdf")
async def export_pdf(
    vendor: Optional[str] = Query(None, description="Filter by vendor (case-insensitive partial match)"),
    model: Optional[str] = Query(None, description="Filter by model (case-insensitive partial match)"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    subnet: Optional[str] = Query(None, description="Filter by subnet (CIDR notation)"),
    risk_score_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    risk_score_max: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score"),
    current_user: TokenData = Depends(require_viewer),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Export device inventory as PDF report.

    Returns a PDF report containing:
    - Device count summary with breakdown by vendor and protocol
    - Device inventory table listing all matching devices
    - Textual description of observed communication paths
    - Histogram of risk score distribution
    - Summary of alerts generated within the preceding 30 days

    For empty results, returns a report stating "no devices matched"
    (Requirement 10.5).
    Rejects requests exceeding 50,000 records (Requirement 10.7).
    Returns error if export exceeds 60 seconds (Requirement 10.6).

    Requires: viewer role (read access).
    """
    service = ExportService(session)

    try:
        pdf_content = await service.export_pdf(
            vendor=vendor,
            model=model,
            protocol=protocol,
            subnet=subnet,
            risk_score_min=risk_score_min,
            risk_score_max=risk_score_max,
        )
    except ExportRecordLimitExceeded as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except ExportTimeoutError as e:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(e),
        )

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=device_inventory_report.pdf",
        },
    )
