"""Integration tests for auth middleware with FastAPI test client.

Tests the HTTP-level behavior of authentication and RBAC:
- Missing token returns 401 with "missing token"
- Expired token returns 401 with "token expired"
- Invalid token returns 401 with "invalid token"
- Viewer accessing admin endpoint returns 403
- Admin accessing all endpoints succeeds

Requirements: 8.1, 8.3, 8.4, 8.5
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt

from app.api.auth import JWT_ALGORITHM, JWT_SECRET_KEY, create_access_token
from app.api.dependencies import get_current_user, require_admin, require_viewer


# Create a test FastAPI app with protected endpoints
app = FastAPI()


@app.get("/protected/viewer")
async def viewer_endpoint(user=Depends(require_viewer)):
    return {"message": "viewer content", "user": user.username, "role": user.role}


@app.get("/protected/admin")
async def admin_endpoint(user=Depends(require_admin)):
    return {"message": "admin content", "user": user.username, "role": user.role}


@app.get("/protected/basic")
async def basic_protected(user=Depends(get_current_user)):
    return {"message": "authenticated", "user": user.username}


client = TestClient(app)


class TestMissingToken:
    """Tests for requests without any token."""

    def test_no_auth_header_returns_401(self):
        """Request without Authorization header should return 401."""
        response = client.get("/protected/basic")
        assert response.status_code == 401

    def test_no_auth_header_returns_missing_token_message(self):
        """Response should contain 'missing token' detail."""
        response = client.get("/protected/basic")
        assert response.json()["detail"] == "missing token"

    def test_no_auth_header_on_viewer_endpoint(self):
        """Viewer endpoint without token returns 401 with 'missing token'."""
        response = client.get("/protected/viewer")
        assert response.status_code == 401
        assert response.json()["detail"] == "missing token"

    def test_no_auth_header_on_admin_endpoint(self):
        """Admin endpoint without token returns 401 with 'missing token'."""
        response = client.get("/protected/admin")
        assert response.status_code == 401
        assert response.json()["detail"] == "missing token"


class TestExpiredToken:
    """Tests for requests with expired JWT tokens."""

    def test_expired_token_returns_401(self):
        """Expired token should return 401."""
        payload = {
            "sub": "testuser",
            "role": "admin",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=9),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        response = client.get(
            "/protected/basic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    def test_expired_token_returns_token_expired_message(self):
        """Response should contain 'token expired' detail."""
        payload = {
            "sub": "testuser",
            "role": "admin",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=8),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        response = client.get(
            "/protected/basic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.json()["detail"] == "token expired"


class TestInvalidToken:
    """Tests for requests with invalid JWT tokens."""

    def test_wrong_signature_returns_401(self):
        """Token signed with wrong key should return 401."""
        payload = {
            "sub": "testuser",
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, "wrong-secret", algorithm=JWT_ALGORITHM)
        response = client.get(
            "/protected/basic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid token"

    def test_malformed_token_returns_401(self):
        """Malformed token string should return 401."""
        response = client.get(
            "/protected/basic",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid token"

    def test_token_missing_sub_claim_returns_401(self):
        """Token without 'sub' claim should return 401 with 'invalid token'."""
        payload = {
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        response = client.get(
            "/protected/basic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid token"

    def test_token_missing_role_claim_returns_401(self):
        """Token without 'role' claim should return 401 with 'invalid token'."""
        payload = {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        response = client.get(
            "/protected/basic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid token"


class TestRBACHTTPLevel:
    """Tests for role-based access control at the HTTP level."""

    def test_admin_accesses_admin_endpoint(self):
        """Admin token should access admin endpoints successfully."""
        token = create_access_token("admin_user", "admin")
        response = client.get(
            "/protected/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["user"] == "admin_user"
        assert response.json()["role"] == "admin"

    def test_admin_accesses_viewer_endpoint(self):
        """Admin token should also access viewer endpoints."""
        token = create_access_token("admin_user", "admin")
        response = client.get(
            "/protected/viewer",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    def test_viewer_accesses_viewer_endpoint(self):
        """Viewer token should access viewer endpoints successfully."""
        token = create_access_token("viewer_user", "viewer")
        response = client.get(
            "/protected/viewer",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["user"] == "viewer_user"
        assert response.json()["role"] == "viewer"

    def test_viewer_denied_admin_endpoint_returns_403(self):
        """Viewer token on admin endpoint should return 403."""
        token = create_access_token("viewer_user", "viewer")
        response = client.get(
            "/protected/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 403

    def test_viewer_denied_admin_endpoint_has_descriptive_message(self):
        """403 response should have descriptive message about insufficient permissions."""
        token = create_access_token("viewer_user", "viewer")
        response = client.get(
            "/protected/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        detail = response.json()["detail"]
        assert "Insufficient permissions" in detail
        assert "viewer" in detail
        assert "admin" in detail
