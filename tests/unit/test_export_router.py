"""Unit tests for the export API router endpoints.

Tests the FastAPI router endpoints for CSV, JSON, and PDF export
including authentication, error handling, and response formats.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from app.api.auth import TokenData
from app.api.dependencies import get_current_user
from app.api.router_export import export_router
from app.db.session import get_session
from app.export.service import ExportRecordLimitExceeded, ExportTimeoutError


# --- Test App Setup ---


def _create_test_app() -> FastAPI:
    """Create a test FastAPI app with the export router."""
    app = FastAPI()
    app.include_router(export_router)
    return app


def _mock_viewer_user():
    """Create a mock viewer user for auth dependency override."""
    return TokenData(username="testuser", role="viewer")


def _mock_session():
    """Create a mock async session."""
    session = AsyncMock()
    return session


# --- CSV Endpoint Tests ---


class TestCSVEndpoint:
    """Tests for GET /api/export/csv endpoint."""

    @pytest.mark.asyncio
    async def test_csv_export_returns_csv_content_type(self):
        """CSV endpoint should return text/csv content type."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_csv = AsyncMock(return_value="header1,header2\nval1,val2\n")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/csv")

            assert response.status_code == 200
            assert "text/csv" in response.headers["content-type"]
            assert "attachment" in response.headers["content-disposition"]
            assert "device_inventory.csv" in response.headers["content-disposition"]

    @pytest.mark.asyncio
    async def test_csv_export_passes_filter_params(self):
        """CSV endpoint should pass filter parameters to the service."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_csv = AsyncMock(return_value="headers\n")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get(
                    "/api/export/csv",
                    params={
                        "vendor": "Siemens",
                        "model": "S7",
                        "protocol": "modbus_tcp",
                        "risk_score_min": 20,
                        "risk_score_max": 80,
                    },
                )

            assert response.status_code == 200
            instance.export_csv.assert_called_once_with(
                vendor="Siemens",
                model="S7",
                protocol="modbus_tcp",
                subnet=None,
                risk_score_min=20,
                risk_score_max=80,
            )

    @pytest.mark.asyncio
    async def test_csv_export_record_limit_returns_400(self):
        """CSV endpoint should return 400 when record limit exceeded."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_csv = AsyncMock(
                side_effect=ExportRecordLimitExceeded(55_000)
            )

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/csv")

            assert response.status_code == 400
            assert "55000" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_csv_export_timeout_returns_504(self):
        """CSV endpoint should return 504 when export times out."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_csv = AsyncMock(side_effect=ExportTimeoutError())

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/csv")

            assert response.status_code == 504
            assert "60" in response.json()["detail"]


# --- JSON Endpoint Tests ---


class TestJSONEndpoint:
    """Tests for GET /api/export/json endpoint."""

    @pytest.mark.asyncio
    async def test_json_export_returns_json_content_type(self):
        """JSON endpoint should return application/json content type."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_json = AsyncMock(return_value="[]")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/json")

            assert response.status_code == 200
            assert "application/json" in response.headers["content-type"]
            assert "attachment" in response.headers["content-disposition"]
            assert "device_inventory.json" in response.headers["content-disposition"]

    @pytest.mark.asyncio
    async def test_json_export_record_limit_returns_400(self):
        """JSON endpoint should return 400 when record limit exceeded."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_json = AsyncMock(
                side_effect=ExportRecordLimitExceeded(60_000)
            )

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/json")

            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_json_export_timeout_returns_504(self):
        """JSON endpoint should return 504 when export times out."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_json = AsyncMock(side_effect=ExportTimeoutError())

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/json")

            assert response.status_code == 504


# --- PDF Endpoint Tests ---


class TestPDFEndpoint:
    """Tests for GET /api/export/pdf endpoint."""

    @pytest.mark.asyncio
    async def test_pdf_export_returns_pdf_content_type(self):
        """PDF endpoint should return application/pdf content type."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_pdf = AsyncMock(return_value="Report content")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/pdf")

            assert response.status_code == 200
            assert "application/pdf" in response.headers["content-type"]
            assert "attachment" in response.headers["content-disposition"]
            assert "device_inventory_report.pdf" in response.headers["content-disposition"]

    @pytest.mark.asyncio
    async def test_pdf_export_passes_filter_params(self):
        """PDF endpoint should pass filter parameters to the service."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_pdf = AsyncMock(return_value="Report")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get(
                    "/api/export/pdf",
                    params={
                        "vendor": "Allen-Bradley",
                        "subnet": "10.0.0.0/8",
                        "risk_score_min": 50,
                    },
                )

            assert response.status_code == 200
            instance.export_pdf.assert_called_once_with(
                vendor="Allen-Bradley",
                model=None,
                protocol=None,
                subnet="10.0.0.0/8",
                risk_score_min=50,
                risk_score_max=None,
            )

    @pytest.mark.asyncio
    async def test_pdf_export_record_limit_returns_400(self):
        """PDF endpoint should return 400 when record limit exceeded."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_pdf = AsyncMock(
                side_effect=ExportRecordLimitExceeded(100_000)
            )

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/pdf")

            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_pdf_export_timeout_returns_504(self):
        """PDF endpoint should return 504 when export times out."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: _mock_viewer_user()
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_pdf = AsyncMock(side_effect=ExportTimeoutError())

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/pdf")

            assert response.status_code == 504


# --- Authentication Tests ---


class TestExportAuthentication:
    """Tests for export endpoint authentication requirements."""

    @pytest.mark.asyncio
    async def test_csv_requires_authentication(self):
        """CSV endpoint should require authentication."""
        app = _create_test_app()
        # Don't override auth dependency - should fail

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/export/csv")

        # Should get 401 or 403 (depends on auth middleware behavior)
        assert response.status_code in [401, 403, 422]

    @pytest.mark.asyncio
    async def test_viewer_role_can_export(self):
        """Viewer role should be able to access export endpoints."""
        app = _create_test_app()
        mock_session = _mock_session()

        app.dependency_overrides[get_current_user] = lambda: TokenData(
            username="viewer_user", role="viewer"
        )
        app.dependency_overrides[get_session] = lambda: mock_session

        with patch("app.api.router_export.ExportService") as MockService:
            instance = MockService.return_value
            instance.export_csv = AsyncMock(return_value="headers\n")

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/api/export/csv")

            assert response.status_code == 200
