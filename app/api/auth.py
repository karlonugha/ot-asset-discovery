"""Authentication service for JWT token management and password hashing.

Implements:
- JWT token generation with role claim and configurable expiration (1-24h, default 8h)
- Password hashing with passlib (bcrypt)
- Token validation with specific error messages

Requirements: 8.1, 8.2, 8.3
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, ExpiredSignatureError, jwt
from pydantic import BaseModel, Field

# Configuration from environment with sensible defaults
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-this-to-a-secure-random-string")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_HOURS = float(os.environ.get("JWT_EXPIRATION_HOURS", "8"))

# Clamp expiration to valid range (1-24 hours)
JWT_EXPIRATION_HOURS = max(1.0, min(24.0, JWT_EXPIRATION_HOURS))


class TokenData(BaseModel):
    """Decoded JWT token payload."""

    username: str
    role: str
    exp: Optional[datetime] = None


class TokenResponse(BaseModel):
    """Response model for successful authentication."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Token expiration time in seconds")


class AuthError(Exception):
    """Authentication error with specific reason."""

    def __init__(self, detail: str, status_code: int = 401):
        self.detail = detail
        self.status_code = status_code


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Uses the bcrypt library directly for compatibility with bcrypt 5.x.

    Args:
        password: Plain text password to hash.

    Returns:
        Bcrypt hash string.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash.

    Args:
        plain_password: Plain text password to verify.
        hashed_password: Stored bcrypt hash.

    Returns:
        True if password matches, False otherwise.
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(
    username: str,
    role: str,
    expiration_hours: Optional[float] = None,
) -> str:
    """Create a JWT access token with role claim.

    Args:
        username: The username to encode in the token.
        role: The user's role ('viewer' or 'admin').
        expiration_hours: Token lifetime in hours (1-24, default from config).

    Returns:
        Encoded JWT token string.
    """
    if expiration_hours is None:
        expiration_hours = JWT_EXPIRATION_HOURS

    # Clamp to valid range
    expiration_hours = max(1.0, min(24.0, expiration_hours))

    expire = datetime.now(timezone.utc) + timedelta(hours=expiration_hours)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> TokenData:
    """Decode and validate a JWT access token.

    Args:
        token: The JWT token string to decode.

    Returns:
        TokenData with username and role.

    Raises:
        AuthError: With specific message for expired or invalid tokens.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")

        if username is None or role is None:
            raise AuthError("invalid token")

        return TokenData(username=username, role=role)

    except ExpiredSignatureError:
        raise AuthError("token expired")
    except JWTError:
        raise AuthError("invalid token")
