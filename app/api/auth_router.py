"""Authentication router for login endpoint with rate limiting.

Implements the authentication endpoint that issues JWT tokens.
This is the only unprotected endpoint per Requirement 8.1.
Integrates rate limiting per Requirements 8.6, 8.7:
- Track failed auth attempts per IP in auth_attempts table
- Enforce max 5 failed attempts per IP within 15-minute sliding window
- Return HTTP 429 when limit exceeded until window elapses

Requirements: 8.1, 8.2, 8.6, 8.7
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import (
    TokenResponse,
    create_access_token,
    verify_password,
    JWT_EXPIRATION_HOURS,
)
from app.api.rate_limiter import check_rate_limit, record_auth_attempt
from app.db.session import get_session
from app.models.database import User

auth_router = APIRouter(prefix="/api/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    """Request body for the login endpoint."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)


def get_client_ip(request: Request) -> str:
    """Extract client IP address from the request.

    Checks X-Forwarded-For header first (for reverse proxy setups),
    then falls back to the direct client address.

    Args:
        request: The FastAPI request object.

    Returns:
        Client IP address string.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        401: {"description": "Invalid credentials"},
        429: {"description": "Too many failed attempts"},
    },
)
async def login(
    login_request: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """Authenticate user and return JWT token.

    Enforces rate limiting: max 5 failed attempts per IP within a
    15-minute sliding window. Returns HTTP 429 when limit exceeded.

    Args:
        login_request: Username and password.
        request: The HTTP request (for IP extraction).
        session: Database session dependency.

    Returns:
        TokenResponse with access_token, token_type, and expires_in.

    Raises:
        HTTPException: 401 if credentials are invalid, 429 if rate-limited.
    """
    client_ip = get_client_ip(request)

    # Check rate limit before processing authentication
    rate_limit_error = await check_rate_limit(session, client_ip)
    if rate_limit_error:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_limit_error["detail"],
            headers={"Retry-After": str(rate_limit_error["retry_after_seconds"])},
        )

    # Look up user by username
    result = await session.execute(
        select(User).where(User.username == login_request.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(login_request.password, user.password_hash):
        # Record failed attempt for rate limiting
        await record_auth_attempt(session, client_ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Record successful attempt
    await record_auth_attempt(session, client_ip, success=True)

    # Generate JWT token with role claim
    access_token = create_access_token(
        username=user.username,
        role=user.role,
    )

    # Update last_login timestamp
    user.last_login = datetime.now(timezone.utc)
    await session.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(JWT_EXPIRATION_HOURS * 3600),
    )
