"""Unit tests for the authentication rate limiter.

Tests rate limiting enforcement:
- Track failed auth attempts per IP in auth_attempts table
- Enforce max 5 failed attempts per IP within 15-minute sliding window
- Return HTTP 429 when limit exceeded until window elapses

Requirements: 8.6, 8.7
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.rate_limiter import (
    MAX_FAILED_ATTEMPTS,
    WINDOW_MINUTES,
    check_rate_limit,
    get_failed_attempt_count,
    is_rate_limited,
    record_auth_attempt,
)


class TestRateLimiterConstants:
    """Tests for rate limiter configuration constants."""

    def test_max_failed_attempts_is_5(self):
        """Rate limit should trigger after 5 failed attempts."""
        assert MAX_FAILED_ATTEMPTS == 5

    def test_window_is_15_minutes(self):
        """Sliding window should be 15 minutes."""
        assert WINDOW_MINUTES == 15


class TestRecordAuthAttempt:
    """Tests for recording authentication attempts."""

    @pytest.mark.asyncio
    async def test_record_failed_attempt(self):
        """Should record a failed attempt with success=False."""
        session = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()

        await record_auth_attempt(session, "192.168.1.100", success=False)

        session.add.assert_called_once()
        added_obj = session.add.call_args[0][0]
        assert added_obj.ip_address == "192.168.1.100"
        assert added_obj.success is False
        assert added_obj.attempted_at is not None
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_record_successful_attempt(self):
        """Should record a successful attempt with success=True."""
        session = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()

        await record_auth_attempt(session, "10.0.0.1", success=True)

        session.add.assert_called_once()
        added_obj = session.add.call_args[0][0]
        assert added_obj.ip_address == "10.0.0.1"
        assert added_obj.success is True
        session.commit.assert_awaited_once()


class TestGetFailedAttemptCount:
    """Tests for counting failed attempts within the window."""

    @pytest.mark.asyncio
    async def test_returns_count_from_query(self):
        """Should return the count of failed attempts from the database."""
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 3
        session.execute = AsyncMock(return_value=mock_result)

        count = await get_failed_attempt_count(session, "192.168.1.100")

        assert count == 3
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_zero_for_no_attempts(self):
        """Should return 0 when no failed attempts exist."""
        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        session.execute = AsyncMock(return_value=mock_result)

        count = await get_failed_attempt_count(session, "10.0.0.1")

        assert count == 0


class TestIsRateLimited:
    """Tests for rate limit checking logic."""

    @pytest.mark.asyncio
    async def test_not_rate_limited_below_threshold(self):
        """Should not be rate-limited with fewer than 5 failed attempts."""
        with patch(
            "app.api.rate_limiter.get_failed_attempt_count",
            new_callable=AsyncMock,
            return_value=4,
        ):
            session = AsyncMock()
            result = await is_rate_limited(session, "192.168.1.100")
            assert result is False

    @pytest.mark.asyncio
    async def test_rate_limited_at_threshold(self):
        """Should be rate-limited at exactly 5 failed attempts."""
        with patch(
            "app.api.rate_limiter.get_failed_attempt_count",
            new_callable=AsyncMock,
            return_value=5,
        ):
            session = AsyncMock()
            result = await is_rate_limited(session, "192.168.1.100")
            assert result is True

    @pytest.mark.asyncio
    async def test_rate_limited_above_threshold(self):
        """Should be rate-limited with more than 5 failed attempts."""
        with patch(
            "app.api.rate_limiter.get_failed_attempt_count",
            new_callable=AsyncMock,
            return_value=10,
        ):
            session = AsyncMock()
            result = await is_rate_limited(session, "192.168.1.100")
            assert result is True

    @pytest.mark.asyncio
    async def test_not_rate_limited_with_zero_attempts(self):
        """Should not be rate-limited with zero failed attempts."""
        with patch(
            "app.api.rate_limiter.get_failed_attempt_count",
            new_callable=AsyncMock,
            return_value=0,
        ):
            session = AsyncMock()
            result = await is_rate_limited(session, "192.168.1.100")
            assert result is False


class TestCheckRateLimit:
    """Tests for the main rate limit check entry point."""

    @pytest.mark.asyncio
    async def test_returns_none_when_not_limited(self):
        """Should return None when IP is not rate-limited."""
        with patch(
            "app.api.rate_limiter.is_rate_limited",
            new_callable=AsyncMock,
            return_value=False,
        ):
            session = AsyncMock()
            result = await check_rate_limit(session, "192.168.1.100")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_error_dict_when_limited(self):
        """Should return error details when IP is rate-limited."""
        oldest_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        with patch(
            "app.api.rate_limiter.is_rate_limited",
            new_callable=AsyncMock,
            return_value=True,
        ):
            session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = oldest_time
            session.execute = AsyncMock(return_value=mock_result)

            result = await check_rate_limit(session, "192.168.1.100")

            assert result is not None
            assert "detail" in result
            assert "retry_after_seconds" in result
            assert "Too many failed authentication attempts" in result["detail"]
            assert result["retry_after_seconds"] > 0

    @pytest.mark.asyncio
    async def test_retry_after_calculation(self):
        """Retry-after should be based on oldest attempt in window."""
        # Oldest attempt was 10 minutes ago, so window elapses in ~5 minutes
        oldest_time = datetime.now(timezone.utc) - timedelta(minutes=10)

        with patch(
            "app.api.rate_limiter.is_rate_limited",
            new_callable=AsyncMock,
            return_value=True,
        ):
            session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = oldest_time
            session.execute = AsyncMock(return_value=mock_result)

            result = await check_rate_limit(session, "192.168.1.100")

            # Window elapses 15 min after oldest attempt (10 min ago)
            # So retry_after should be approximately 5 minutes (300 seconds)
            assert 280 <= result["retry_after_seconds"] <= 320

    @pytest.mark.asyncio
    async def test_retry_after_defaults_when_no_oldest(self):
        """Should default to full window when oldest attempt not found."""
        with patch(
            "app.api.rate_limiter.is_rate_limited",
            new_callable=AsyncMock,
            return_value=True,
        ):
            session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            session.execute = AsyncMock(return_value=mock_result)

            result = await check_rate_limit(session, "192.168.1.100")

            assert result["retry_after_seconds"] == WINDOW_MINUTES * 60
