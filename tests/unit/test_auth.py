"""Unit tests for the authentication system.

Tests JWT token generation, password hashing, auth middleware,
and role-based access control.

Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from jose import jwt

from app.api.auth import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    AuthError,
    TokenData,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    """Tests for password hashing with passlib/bcrypt."""

    def test_hash_password_produces_bcrypt_hash(self):
        """Hash should be a valid bcrypt string."""
        hashed = hash_password("mysecretpassword")
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
        assert len(hashed) == 60

    def test_verify_password_correct(self):
        """Correct password should verify successfully."""
        password = "test_password_123"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Incorrect password should fail verification."""
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_hash_password_unique_salts(self):
        """Same password should produce different hashes (unique salts)."""
        password = "same_password"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2
        # Both should still verify
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True

    def test_empty_password_hashes(self):
        """Empty password should still hash and verify."""
        hashed = hash_password("")
        assert verify_password("", hashed) is True
        assert verify_password("notempty", hashed) is False


class TestJWTTokenGeneration:
    """Tests for JWT token creation with role claim and configurable expiration."""

    def test_create_token_contains_username(self):
        """Token should contain the username in 'sub' claim."""
        token = create_access_token("testuser", "viewer")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["sub"] == "testuser"

    def test_create_token_contains_role_claim(self):
        """Token should contain the role claim."""
        token = create_access_token("admin_user", "admin")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["role"] == "admin"

    def test_create_token_viewer_role(self):
        """Token with viewer role should have role='viewer'."""
        token = create_access_token("viewer_user", "viewer")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert payload["role"] == "viewer"

    def test_create_token_default_expiration(self):
        """Token should have default 8-hour expiration."""
        token = create_access_token("testuser", "viewer")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        # Should expire approximately 8 hours from now (within 10 seconds tolerance)
        expected_exp = now + timedelta(hours=8)
        assert abs((exp - expected_exp).total_seconds()) < 10

    def test_create_token_custom_expiration(self):
        """Token should respect custom expiration hours."""
        token = create_access_token("testuser", "viewer", expiration_hours=2.0)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        expected_exp = now + timedelta(hours=2)
        assert abs((exp - expected_exp).total_seconds()) < 10

    def test_create_token_expiration_clamped_min(self):
        """Expiration below 1 hour should be clamped to 1 hour."""
        token = create_access_token("testuser", "viewer", expiration_hours=0.1)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        expected_exp = now + timedelta(hours=1)
        assert abs((exp - expected_exp).total_seconds()) < 10

    def test_create_token_expiration_clamped_max(self):
        """Expiration above 24 hours should be clamped to 24 hours."""
        token = create_access_token("testuser", "viewer", expiration_hours=48.0)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        expected_exp = now + timedelta(hours=24)
        assert abs((exp - expected_exp).total_seconds()) < 10

    def test_create_token_contains_iat_claim(self):
        """Token should contain issued-at (iat) claim."""
        token = create_access_token("testuser", "viewer")
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        assert "iat" in payload


class TestJWTTokenValidation:
    """Tests for JWT token decoding and validation with specific error messages."""

    def test_decode_valid_token(self):
        """Valid token should decode successfully."""
        token = create_access_token("testuser", "admin")
        result = decode_access_token(token)
        assert isinstance(result, TokenData)
        assert result.username == "testuser"
        assert result.role == "admin"

    def test_decode_expired_token_raises_token_expired(self):
        """Expired token should raise AuthError with 'token expired' message."""
        # Create a token that's already expired
        expire = datetime.now(timezone.utc) - timedelta(hours=1)
        payload = {
            "sub": "testuser",
            "role": "viewer",
            "exp": expire,
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with pytest.raises(AuthError) as exc_info:
            decode_access_token(token)
        assert exc_info.value.detail == "token expired"

    def test_decode_invalid_signature_raises_invalid_token(self):
        """Token with wrong signature should raise AuthError with 'invalid token'."""
        payload = {
            "sub": "testuser",
            "role": "viewer",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, "wrong-secret-key", algorithm=JWT_ALGORITHM)

        with pytest.raises(AuthError) as exc_info:
            decode_access_token(token)
        assert exc_info.value.detail == "invalid token"

    def test_decode_malformed_token_raises_invalid_token(self):
        """Malformed token string should raise AuthError with 'invalid token'."""
        with pytest.raises(AuthError) as exc_info:
            decode_access_token("not.a.valid.jwt.token")
        assert exc_info.value.detail == "invalid token"

    def test_decode_empty_token_raises_invalid_token(self):
        """Empty token string should raise AuthError with 'invalid token'."""
        with pytest.raises(AuthError) as exc_info:
            decode_access_token("")
        assert exc_info.value.detail == "invalid token"

    def test_decode_token_missing_sub_raises_invalid_token(self):
        """Token without 'sub' claim should raise AuthError with 'invalid token'."""
        payload = {
            "role": "viewer",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with pytest.raises(AuthError) as exc_info:
            decode_access_token(token)
        assert exc_info.value.detail == "invalid token"

    def test_decode_token_missing_role_raises_invalid_token(self):
        """Token without 'role' claim should raise AuthError with 'invalid token'."""
        payload = {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with pytest.raises(AuthError) as exc_info:
            decode_access_token(token)
        assert exc_info.value.detail == "invalid token"


class TestRBACDependencies:
    """Tests for role-based access control enforcement."""

    def test_admin_role_accesses_admin_endpoints(self):
        """Admin role should have access to admin-level endpoints."""
        from app.api.dependencies import require_role

        checker = require_role("admin")
        # Admin user should pass
        admin_user = TokenData(username="admin", role="admin")
        # We test the logic directly - in real usage this is async
        import asyncio

        result = asyncio.run(checker(current_user=admin_user))
        assert result.role == "admin"

    def test_admin_role_accesses_viewer_endpoints(self):
        """Admin role should also have access to viewer-level endpoints."""
        from app.api.dependencies import require_role

        checker = require_role("viewer")
        admin_user = TokenData(username="admin", role="admin")
        import asyncio

        result = asyncio.run(checker(current_user=admin_user))
        assert result.role == "admin"

    def test_viewer_role_accesses_viewer_endpoints(self):
        """Viewer role should have access to viewer-level endpoints."""
        from app.api.dependencies import require_role

        checker = require_role("viewer")
        viewer_user = TokenData(username="viewer", role="viewer")
        import asyncio

        result = asyncio.run(checker(current_user=viewer_user))
        assert result.role == "viewer"

    def test_viewer_role_denied_admin_endpoints(self):
        """Viewer role should be denied access to admin-level endpoints with HTTP 403."""
        from fastapi import HTTPException

        from app.api.dependencies import require_role

        checker = require_role("admin")
        viewer_user = TokenData(username="viewer", role="viewer")
        import asyncio

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(checker(current_user=viewer_user))
        assert exc_info.value.status_code == 403
        assert "Insufficient permissions" in exc_info.value.detail
        assert "viewer" in exc_info.value.detail
        assert "admin" in exc_info.value.detail
