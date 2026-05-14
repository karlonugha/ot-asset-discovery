"""Unit tests for the ScanScheduler class.

Tests cover:
- Cron schedule validation (reject < 5 minutes)
- Scan execution and result recording
- Manual trigger within 5 seconds
- Overlap detection and scan_skipped event
- scan_failed alert generation on execution failure

Requirements: 11.1, 11.2, 11.5, 11.6, 11.7
"""

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models.domain import Alert, ScanJobConfig
from app.scheduling.scheduler import (
    ScanScheduler,
    ScanJob,
    ScanResult,
    ScheduleValidationError,
    ScanJobNotFoundError,
)


# --- Cron Schedule Validation Tests (Requirement 11.1) ---


class TestCronScheduleValidation:
    """Tests for cron schedule interval validation."""

    def test_valid_every_5_minutes(self):
        """Cron expression '*/5 * * * *' (every 5 min) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("*/5 * * * *") is True

    def test_valid_every_10_minutes(self):
        """Cron expression '*/10 * * * *' (every 10 min) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("*/10 * * * *") is True

    def test_valid_every_hour(self):
        """Cron expression '0 * * * *' (every hour) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("0 * * * *") is True

    def test_valid_every_day(self):
        """Cron expression '0 0 * * *' (daily at midnight) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("0 0 * * *") is True

    def test_valid_every_30_minutes(self):
        """Cron expression '*/30 * * * *' (every 30 min) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("*/30 * * * *") is True

    def test_reject_every_1_minute(self):
        """Cron expression '* * * * *' (every minute) should be rejected."""
        with pytest.raises(ScheduleValidationError):
            ScanScheduler.validate_cron_schedule("* * * * *")

    def test_reject_every_2_minutes(self):
        """Cron expression '*/2 * * * *' (every 2 min) should be rejected."""
        with pytest.raises(ScheduleValidationError):
            ScanScheduler.validate_cron_schedule("*/2 * * * *")

    def test_reject_every_3_minutes(self):
        """Cron expression '*/3 * * * *' (every 3 min) should be rejected."""
        with pytest.raises(ScheduleValidationError):
            ScanScheduler.validate_cron_schedule("*/3 * * * *")

    def test_reject_every_4_minutes(self):
        """Cron expression '*/4 * * * *' (every 4 min) should be rejected."""
        with pytest.raises(ScheduleValidationError):
            ScanScheduler.validate_cron_schedule("*/4 * * * *")

    def test_invalid_cron_expression(self):
        """Invalid cron expression should raise ValueError."""
        with pytest.raises(ValueError):
            ScanScheduler.validate_cron_schedule("not a cron expression")

    def test_invalid_cron_too_many_fields(self):
        """Cron expression with too many fields should be rejected."""
        with pytest.raises((ValueError, ScheduleValidationError)):
            ScanScheduler.validate_cron_schedule("* * * * * * *")

    def test_valid_specific_minutes(self):
        """Cron expression '0,30 * * * *' (at :00 and :30) should be accepted."""
        assert ScanScheduler.validate_cron_schedule("0,30 * * * *") is True

    def test_reject_specific_minutes_too_close(self):
        """Cron expression '0,1,2,3,4 * * * *' (every minute for 5 min) should be rejected."""
        with pytest.raises(ScheduleValidationError):
            ScanScheduler.validate_cron_schedule("0,1,2,3,4 * * * *")


# --- Scan Job Creation Tests ---


class TestScanJobCreation:
    """Tests for creating scan jobs."""

    @pytest.mark.asyncio
    async def test_create_job_with_valid_schedule(self):
        """Creating a job with a valid cron schedule should succeed."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(
            name="Test Scan",
            schedule="*/10 * * * *",
            target_subnet="192.168.1.0/24",
            active_probing_enabled=True,
        )

        job = await scheduler.create_job(config)

        assert job.id is not None
        assert job.config.name == "Test Scan"
        assert job.config.schedule == "*/10 * * * *"
        assert job.status == "scheduled"

    @pytest.mark.asyncio
    async def test_create_job_with_invalid_schedule_rejected(self):
        """Creating a job with a too-frequent schedule should raise ScheduleValidationError."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(
            name="Too Frequent Scan",
            schedule="*/2 * * * *",
        )

        with pytest.raises(ScheduleValidationError):
            await scheduler.create_job(config)

    @pytest.mark.asyncio
    async def test_create_job_without_schedule(self):
        """Creating a job without a schedule (manual-only) should succeed."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(name="Manual Scan Only")

        job = await scheduler.create_job(config)

        assert job.id is not None
        assert job.config.schedule is None
        assert job.status == "scheduled"

    @pytest.mark.asyncio
    async def test_create_multiple_jobs(self):
        """Multiple jobs can be created and tracked."""
        scheduler = ScanScheduler()

        job1 = await scheduler.create_job(ScanJobConfig(name="Scan 1", schedule="*/5 * * * *"))
        job2 = await scheduler.create_job(ScanJobConfig(name="Scan 2", schedule="0 * * * *"))

        assert len(scheduler.list_jobs()) == 2
        assert job1.id != job2.id


# --- Scan Execution and Result Recording Tests (Requirement 11.2) ---


class TestScanExecution:
    """Tests for scan execution and result recording."""

    @pytest.mark.asyncio
    async def test_execute_scan_records_results(self):
        """Scan execution should record start time, end time, and metrics."""
        async def mock_executor(job: ScanJob) -> ScanResult:
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                devices_discovered=10,
                new_devices=3,
                alerts_generated=2,
                status="completed",
            )

        scheduler = ScanScheduler(scan_executor=mock_executor)
        config = ScanJobConfig(name="Test Scan")
        job = await scheduler.create_job(config)

        result = await scheduler.trigger_manual(job.id)

        assert result.status == "completed"
        assert result.devices_discovered == 10
        assert result.new_devices == 3
        assert result.alerts_generated == 2
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    @pytest.mark.asyncio
    async def test_execute_scan_updates_job_status(self):
        """After execution, job status should reflect the result."""
        async def mock_executor(job: ScanJob) -> ScanResult:
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
            )

        scheduler = ScanScheduler(scan_executor=mock_executor)
        config = ScanJobConfig(name="Test Scan")
        job = await scheduler.create_job(config)

        await scheduler.trigger_manual(job.id)

        assert job.status == "completed"
        assert job.last_result is not None
        assert job.last_result.status == "completed"

    @pytest.mark.asyncio
    async def test_execute_scan_emits_completion_event(self):
        """Scan completion should emit a scan_completed event."""
        events = []

        async def mock_executor(job: ScanJob) -> ScanResult:
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                devices_discovered=5,
                new_devices=1,
                alerts_generated=1,
                status="completed",
            )

        async def on_event(event: dict):
            events.append(event)

        scheduler = ScanScheduler(scan_executor=mock_executor, on_event=on_event)
        config = ScanJobConfig(name="Test Scan")
        job = await scheduler.create_job(config)

        await scheduler.trigger_manual(job.id)

        assert len(events) == 1
        assert events[0]["type"] == "scan_completed"
        assert events[0]["job_id"] == job.id
        assert events[0]["devices_discovered"] == 5
        assert events[0]["new_devices"] == 1
        assert events[0]["alerts_generated"] == 1


# --- Manual Trigger Tests (Requirement 11.5) ---


class TestManualTrigger:
    """Tests for manual scan triggering."""

    @pytest.mark.asyncio
    async def test_manual_trigger_executes_within_5_seconds(self):
        """Manual trigger should begin execution within 5 seconds."""
        execution_started = asyncio.Event()

        async def mock_executor(job: ScanJob) -> ScanResult:
            execution_started.set()
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
            )

        scheduler = ScanScheduler(scan_executor=mock_executor)
        config = ScanJobConfig(name="Manual Scan")
        job = await scheduler.create_job(config)

        start_time = datetime.now(timezone.utc)
        await scheduler.trigger_manual(job.id)
        end_time = datetime.now(timezone.utc)

        assert execution_started.is_set()
        elapsed = (end_time - start_time).total_seconds()
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_manual_trigger_nonexistent_job_raises(self):
        """Triggering a non-existent job should raise ScanJobNotFoundError."""
        scheduler = ScanScheduler()

        with pytest.raises(ScanJobNotFoundError):
            await scheduler.trigger_manual("nonexistent-id")


# --- Overlap Detection Tests (Requirement 11.7) ---


class TestOverlapDetection:
    """Tests for overlapping scan execution detection."""

    @pytest.mark.asyncio
    async def test_overlap_detected_when_job_running(self):
        """Triggering a job while it's running should detect overlap."""
        execution_barrier = asyncio.Event()

        async def slow_executor(job: ScanJob) -> ScanResult:
            await execution_barrier.wait()
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
            )

        scheduler = ScanScheduler(scan_executor=slow_executor)
        config = ScanJobConfig(name="Slow Scan")
        job = await scheduler.create_job(config)

        # Start first execution in background
        task = asyncio.create_task(scheduler.trigger_manual(job.id))
        await asyncio.sleep(0.01)  # Let it start

        # Second trigger should detect overlap
        assert scheduler.check_overlap(job.id) is True

        # Clean up
        execution_barrier.set()
        await task

    @pytest.mark.asyncio
    async def test_overlap_emits_scan_skipped_event(self):
        """Overlapping trigger should emit scan_skipped event."""
        events = []
        execution_barrier = asyncio.Event()

        async def slow_executor(job: ScanJob) -> ScanResult:
            await execution_barrier.wait()
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
            )

        async def on_event(event: dict):
            events.append(event)

        scheduler = ScanScheduler(scan_executor=slow_executor, on_event=on_event)
        config = ScanJobConfig(name="Overlap Test")
        job = await scheduler.create_job(config)

        # Start first execution
        task = asyncio.create_task(scheduler.trigger_manual(job.id))
        await asyncio.sleep(0.01)

        # Second trigger should be skipped
        result = await scheduler.trigger_manual(job.id)

        assert result.status == "skipped"
        assert result.failure_reason == "previous execution still in progress"

        # Check scan_skipped event was emitted
        skipped_events = [e for e in events if e["type"] == "scan_skipped"]
        assert len(skipped_events) == 1
        assert skipped_events[0]["reason"] == "previous execution still in progress"
        assert skipped_events[0]["job_id"] == job.id

        # Clean up
        execution_barrier.set()
        await task

    @pytest.mark.asyncio
    async def test_no_overlap_when_job_not_running(self):
        """check_overlap should return False when job is not running."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(name="Idle Scan")
        job = await scheduler.create_job(config)

        assert scheduler.check_overlap(job.id) is False

    @pytest.mark.asyncio
    async def test_no_overlap_for_nonexistent_job(self):
        """check_overlap should return False for non-existent job."""
        scheduler = ScanScheduler()
        assert scheduler.check_overlap("nonexistent") is False


# --- Scan Failure Alert Tests (Requirement 11.6) ---


class TestScanFailureAlert:
    """Tests for scan_failed alert generation."""

    @pytest.mark.asyncio
    async def test_scan_failure_generates_high_alert(self):
        """Scan execution failure should generate a scan_failed alert with severity HIGH."""
        alerts = []

        async def failing_executor(job: ScanJob) -> ScanResult:
            raise RuntimeError("Network interface unavailable")

        async def on_alert(alert: Alert):
            alerts.append(alert)

        scheduler = ScanScheduler(scan_executor=failing_executor, on_alert=on_alert)
        config = ScanJobConfig(name="Failing Scan", target_subnet="10.0.0.0/24")
        job = await scheduler.create_job(config)

        result = await scheduler.trigger_manual(job.id)

        assert result.status == "failed"
        assert result.failure_reason == "Network interface unavailable"

        # Verify alert was generated
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.alert_type == "scan_failed"
        assert alert.severity == "HIGH"
        assert alert.device_id is None
        assert alert.details["job_id"] == job.id
        assert alert.details["job_name"] == "Failing Scan"
        assert alert.details["failure_reason"] == "Network interface unavailable"
        assert alert.details["target_subnet"] == "10.0.0.0/24"

    @pytest.mark.asyncio
    async def test_scan_failure_updates_job_status(self):
        """Failed scan should update job status to 'failed'."""
        async def failing_executor(job: ScanJob) -> ScanResult:
            raise ValueError("Invalid subnet configuration")

        scheduler = ScanScheduler(scan_executor=failing_executor)
        config = ScanJobConfig(name="Failing Scan")
        job = await scheduler.create_job(config)

        await scheduler.trigger_manual(job.id)

        assert job.status == "failed"
        assert job.last_result is not None
        assert job.last_result.failure_reason == "Invalid subnet configuration"

    @pytest.mark.asyncio
    async def test_scan_failure_records_timestamps(self):
        """Failed scan should still record start and completion timestamps."""
        async def failing_executor(job: ScanJob) -> ScanResult:
            raise RuntimeError("Connection refused")

        scheduler = ScanScheduler(scan_executor=failing_executor)
        config = ScanJobConfig(name="Failing Scan")
        job = await scheduler.create_job(config)

        result = await scheduler.trigger_manual(job.id)

        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    @pytest.mark.asyncio
    async def test_scan_failure_job_not_stuck_running(self):
        """After failure, job should not remain in running state."""
        async def failing_executor(job: ScanJob) -> ScanResult:
            raise RuntimeError("Failure")

        scheduler = ScanScheduler(scan_executor=failing_executor)
        config = ScanJobConfig(name="Failing Scan")
        job = await scheduler.create_job(config)

        await scheduler.trigger_manual(job.id)

        assert not job.is_running


# --- Job Management Tests ---


class TestJobManagement:
    """Tests for job listing and deletion."""

    @pytest.mark.asyncio
    async def test_list_jobs_empty(self):
        """list_jobs should return empty list when no jobs exist."""
        scheduler = ScanScheduler()
        assert scheduler.list_jobs() == []

    @pytest.mark.asyncio
    async def test_get_job_by_id(self):
        """get_job should return the job with matching ID."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(name="Test")
        job = await scheduler.create_job(config)

        retrieved = await scheduler.get_job(job.id)
        assert retrieved is not None
        assert retrieved.id == job.id

    @pytest.mark.asyncio
    async def test_get_nonexistent_job_returns_none(self):
        """get_job should return None for non-existent ID."""
        scheduler = ScanScheduler()
        result = await scheduler.get_job("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_job(self):
        """delete_job should remove the job from the scheduler."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(name="To Delete")
        job = await scheduler.create_job(config)

        assert await scheduler.delete_job(job.id) is True
        assert await scheduler.get_job(job.id) is None
        assert len(scheduler.list_jobs()) == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_job_returns_false(self):
        """delete_job should return False for non-existent ID."""
        scheduler = ScanScheduler()
        assert await scheduler.delete_job("nonexistent") is False


# --- Scheduler Start/Stop Tests ---


class TestSchedulerLifecycle:
    """Tests for scheduler start and stop."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        """Scheduler should start and stop cleanly."""
        scheduler = ScanScheduler()
        config = ScanJobConfig(name="Scheduled", schedule="*/5 * * * *")
        await scheduler.create_job(config)

        await scheduler.start()
        assert scheduler._running is True

        await scheduler.stop()
        assert scheduler._running is False
        assert len(scheduler._scheduler_tasks) == 0
