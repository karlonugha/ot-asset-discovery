"""Authentication API router with rate limiting.

Implements the /api/auth/login endpoint that:
- Validates credentials against the users table
- Enforces rate limiting (max 5 failed attempts per IP in 15-minute window)
- Returns JWT token on success
- Returns HTTP 429 when rate limit exceeded

Requirements: 8.1, 8.2, 8.6, 8.7
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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
    """Request body for authentication."""

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
        session: Database session.

    Returns:
        TokenResponse with JWT access token.

    Raises:
        HTTPException: 401 for invalid credentials, 429 for rate limiting.
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

    # Look up user
    result = await session.execute(
        select(User).where(User.username == login_request.username)
    )
    user = result.scalar_one_or_none()

    # Verify credentials
    if user is None or not verify_password(login_request.password, user.password_hash):
        # Record failed attempt
        await record_auth_attempt(session, client_ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Record successful attempt
    await record_auth_attempt(session, client_ip, success=True)

    # Generate JWT token
    token = create_access_token(username=user.username, role=user.role)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=int(JWT_EXPIRATION_HOURS * 3600),
    )
