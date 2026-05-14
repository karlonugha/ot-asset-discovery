"""Rate limiting for authentication attempts.

Implements:
- Track failed auth attempts per IP in `auth_attempts` table
- Enforce max 5 failed attempts per IP within 15-minute sliding window
- Return HTTP 429 when limit exceeded until window elapses

Requirements: 8.6, 8.7
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import AuthAttempt

# Rate limiting configuration
MAX_FAILED_ATTEMPTS = 5
WINDOW_MINUTES = 15


async def record_auth_attempt(
    session: AsyncSession,
    ip_address: str,
    success: bool,
) -> None:
    """Record an authentication attempt for the given IP address.

    Args:
        session: Async database session.
        ip_address: The client IP address.
        success: Whether the authentication attempt was successful.
    """
    attempt = AuthAttempt(
        ip_address=ip_address,
        attempted_at=datetime.now(timezone.utc),
        success=success,
    )
    session.add(attempt)
    await session.commit()


async def get_failed_attempt_count(
    session: AsyncSession,
    ip_address: str,
) -> int:
    """Count failed authentication attempts for an IP within the sliding window.

    Args:
        session: Async database session.
        ip_address: The client IP address to check.

    Returns:
        Number of failed attempts within the 15-minute window.
    """
    window_start = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)

    result = await session.execute(
        select(func.count(AuthAttempt.id)).where(
            AuthAttempt.ip_address == ip_address,
            AuthAttempt.attempted_at >= window_start,
            AuthAttempt.success == False,  # noqa: E712
        )
    )
    return result.scalar_one()


async def is_rate_limited(
    session: AsyncSession,
    ip_address: str,
) -> bool:
    """Check if an IP address is currently rate-limited.

    An IP is rate-limited when it has accumulated 5 or more failed
    authentication attempts within the 15-minute sliding window.

    Args:
        session: Async database session.
        ip_address: The client IP address to check.

    Returns:
        True if the IP is rate-limited, False otherwise.
    """
    failed_count = await get_failed_attempt_count(session, ip_address)
    return failed_count >= MAX_FAILED_ATTEMPTS


async def check_rate_limit(
    session: AsyncSession,
    ip_address: str,
) -> dict | None:
    """Check rate limit and return error details if exceeded.

    This is the main entry point for rate limit checking in the auth flow.
    Call this before processing an authentication request.

    Args:
        session: Async database session.
        ip_address: The client IP address.

    Returns:
        None if the request is allowed, or a dict with error details if rate-limited.
        The dict contains:
        - "detail": Error message string
        - "retry_after_seconds": Approximate seconds until the window elapses
    """
    if await is_rate_limited(session, ip_address):
        # Calculate approximate retry-after based on oldest counted attempt
        window_start = datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)

        # Get the oldest failed attempt in the current window
        result = await session.execute(
            select(AuthAttempt.attempted_at)
            .where(
                AuthAttempt.ip_address == ip_address,
                AuthAttempt.attempted_at >= window_start,
                AuthAttempt.success == False,  # noqa: E712
            )
            .order_by(AuthAttempt.attempted_at.asc())
            .limit(1)
        )
        oldest_attempt = result.scalar_one_or_none()

        if oldest_attempt:
            # Window elapses when the oldest attempt falls outside the 15-min window
            window_end = oldest_attempt + timedelta(minutes=WINDOW_MINUTES)
            retry_after = max(0, int((window_end - datetime.now(timezone.utc)).total_seconds()))
        else:
            retry_after = WINDOW_MINUTES * 60

        return {
            "detail": "Too many failed authentication attempts. Please try again later.",
            "retry_after_seconds": retry_after,
        }

    return None
