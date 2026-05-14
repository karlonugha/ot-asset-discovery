"""Scan Scheduler for OT Asset Discovery.

Manages cron-based and on-demand scan execution with overlap detection,
result recording, and failure alerting.

The ScanScheduler:
- Validates cron schedule intervals (rejects < 5 minutes)
- Executes scans at scheduled intervals using croniter
- Records scan results: start time, end time, devices discovered, new devices, alerts generated
- Handles manual trigger within 5 seconds
- Detects and skips overlapping executions with "scan_skipped" event
- Generates "scan_failed" alert with severity HIGH on execution failure

Requirements: 11.1, 11.2, 11.5, 11.6, 11.7
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Callable, Awaitable, Optional

from croniter import croniter

from app.models.domain import Alert, ScanJobConfig

logger = logging.getLogger(__name__)


# Type alias for alert/event callbacks
AlertCallback = Callable[[Alert], Awaitable[None]]
EventCallback = Callable[[dict], Awaitable[None]]


class ScheduleValidationError(Exception):
    """Raised when a cron schedule interval is less than 5 minutes."""
    pass


class ScanJobNotFoundError(Exception):
    """Raised when a scan job is not found."""
    pass


class ScanResult:
    """Result of a scan execution.

    Attributes:
        started_at: When the scan started.
        completed_at: When the scan completed.
        devices_discovered: Total devices found during the scan.
        new_devices: Number of newly discovered devices.
        alerts_generated: Number of alerts generated during the scan.
        status: Final status ('completed' or 'failed').
        failure_reason: Reason for failure if status is 'failed'.
    """

    def __init__(
        self,
        started_at: datetime,
        completed_at: Optional[datetime] = None,
        devices_discovered: int = 0,
        new_devices: int = 0,
        alerts_generated: int = 0,
        status: str = "completed",
        failure_reason: Optional[str] = None,
    ):
        self.started_at = started_at
        self.completed_at = completed_at
        self.devices_discovered = devices_discovered
        self.new_devices = new_devices
        self.alerts_generated = alerts_generated
        self.status = status
        self.failure_reason = failure_reason


class ScanJob:
    """Represents a scan job with its configuration and state.

    Attributes:
        id: Unique identifier for the scan job.
        config: The scan job configuration.
        status: Current status (scheduled, running, completed, failed, skipped).
        last_result: The most recent scan result.
    """

    def __init__(self, job_id: str, config: ScanJobConfig):
        self.id = job_id
        self.config = config
        self.status: str = "scheduled"
        self.last_result: Optional[ScanResult] = None
        self._running: bool = False

    @property
    def is_running(self) -> bool:
        """Check if this job is currently executing."""
        return self._running


class ScanScheduler:
    """Manages cron-based and on-demand scan execution.

    Validates cron schedules, executes scans with overlap detection,
    records results, and generates alerts on failure.

    Attributes:
        MIN_INTERVAL_MINUTES: Minimum allowed interval between scan executions (5 minutes).
    """

    MIN_INTERVAL_MINUTES: int = 5

    def __init__(
        self,
        scan_executor: Optional[Callable[[ScanJob], Awaitable[ScanResult]]] = None,
        on_alert: Optional[AlertCallback] = None,
        on_event: Optional[EventCallback] = None,
    ):
        """Initialize the ScanScheduler.

        Args:
            scan_executor: Async callable that performs the actual scan.
                           Receives a ScanJob and returns a ScanResult.
            on_alert: Async callback for alert events (e.g., scan_failed).
            on_event: Async callback for scan events (e.g., scan_skipped, scan_completed).
        """
        self._jobs: dict[str, ScanJob] = {}
        self._scan_executor = scan_executor
        self._on_alert = on_alert
        self._on_event = on_event
        self._scheduler_tasks: dict[str, asyncio.Task] = {}
        self._running = False

    @staticmethod
    def validate_cron_schedule(schedule: str) -> bool:
        """Validate that a cron expression has intervals of at least 5 minutes.

        Uses croniter to compute the next two execution times and checks
        that the interval between them is >= 5 minutes.

        Args:
            schedule: A cron expression string.

        Returns:
            True if the schedule is valid (interval >= 5 minutes).

        Raises:
            ScheduleValidationError: If the interval is less than 5 minutes.
            ValueError: If the cron expression is invalid/unparseable.
        """
        if not croniter.is_valid(schedule):
            raise ValueError(f"Invalid cron expression: {schedule}")

        # Compute the interval between the next two executions
        base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        cron = croniter(schedule, base_time)

        first_execution = cron.get_next(datetime)
        second_execution = cron.get_next(datetime)

        interval_seconds = (second_execution - first_execution).total_seconds()
        min_interval_seconds = ScanScheduler.MIN_INTERVAL_MINUTES * 60

        if interval_seconds < min_interval_seconds:
            raise ScheduleValidationError(
                f"Cron schedule interval ({interval_seconds}s) is less than the "
                f"minimum allowed interval ({min_interval_seconds}s / "
                f"{ScanScheduler.MIN_INTERVAL_MINUTES} minutes). "
                f"Schedule: '{schedule}'"
            )

        return True

    async def create_job(self, config: ScanJobConfig) -> ScanJob:
        """Create a scheduled scan job.

        Validates the cron schedule minimum interval if a schedule is provided.

        Args:
            config: ScanJobConfig with name, schedule, target_subnet, etc.

        Returns:
            The created ScanJob.

        Raises:
            ScheduleValidationError: If the cron interval is < 5 minutes.
            ValueError: If the cron expression is invalid.
        """
        # Validate cron schedule if provided
        if config.schedule:
            self.validate_cron_schedule(config.schedule)

        job_id = str(uuid.uuid4())
        job = ScanJob(job_id=job_id, config=config)
        self._jobs[job_id] = job

        logger.info(f"Created scan job '{config.name}' (id={job_id})")

        # If scheduler is running and job has a schedule, start the cron loop
        if self._running and config.schedule:
            self._start_job_loop(job)

        return job

    async def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID.

        Args:
            job_id: The scan job UUID string.

        Returns:
            The ScanJob if found, None otherwise.
        """
        return self._jobs.get(job_id)

    async def delete_job(self, job_id: str) -> bool:
        """Delete a scan job and stop its scheduler loop.

        Args:
            job_id: The scan job UUID string.

        Returns:
            True if the job was deleted, False if not found.
        """
        if job_id not in self._jobs:
            return False

        # Cancel the scheduler task if running
        if job_id in self._scheduler_tasks:
            self._scheduler_tasks[job_id].cancel()
            del self._scheduler_tasks[job_id]

        del self._jobs[job_id]
        logger.info(f"Deleted scan job {job_id}")
        return True

    async def trigger_manual(self, job_id: str) -> ScanResult:
        """Trigger immediate execution of a scan job within 5 seconds.

        Checks for overlapping execution before starting. If the job is
        already running, records a "scan_skipped" event.

        Args:
            job_id: The scan job UUID string.

        Returns:
            ScanResult from the execution.

        Raises:
            ScanJobNotFoundError: If the job_id is not found.
        """
        job = self._jobs.get(job_id)
        if job is None:
            raise ScanJobNotFoundError(f"Scan job {job_id} not found.")

        # Check for overlap (Requirement 11.7)
        if self.check_overlap(job_id):
            await self._emit_scan_skipped(job)
            return ScanResult(
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="skipped",
                failure_reason="previous execution still in progress",
            )

        # Execute within 5 seconds (Requirement 11.5)
        return await self._execute_scan(job)

    def check_overlap(self, job_id: str) -> bool:
        """Check if a previous execution of the job is still running.

        Args:
            job_id: The scan job UUID string.

        Returns:
            True if the job is currently running (overlap detected).
        """
        job = self._jobs.get(job_id)
        if job is None:
            return False
        return job.is_running

    async def start(self) -> None:
        """Start the scheduler, beginning cron loops for all scheduled jobs."""
        self._running = True
        for job in self._jobs.values():
            if job.config.schedule:
                self._start_job_loop(job)
        logger.info("ScanScheduler started")

    async def stop(self) -> None:
        """Stop the scheduler, cancelling all cron loops."""
        self._running = False
        for task in self._scheduler_tasks.values():
            task.cancel()
        self._scheduler_tasks.clear()
        logger.info("ScanScheduler stopped")

    def _start_job_loop(self, job: ScanJob) -> None:
        """Start the cron-based execution loop for a job.

        Args:
            job: The ScanJob to schedule.
        """
        task = asyncio.create_task(self._cron_loop(job))
        self._scheduler_tasks[job.id] = task

    async def _cron_loop(self, job: ScanJob) -> None:
        """Run the cron-based execution loop for a scan job.

        Computes the next execution time from the cron schedule and sleeps
        until that time, then executes the scan. Handles overlap detection.

        Args:
            job: The ScanJob to execute on schedule.
        """
        try:
            while self._running:
                if not job.config.schedule:
                    break

                # Compute next execution time
                now = datetime.now(timezone.utc)
                cron = croniter(job.config.schedule, now)
                next_time = cron.get_next(datetime)

                # Sleep until next execution
                delay = (next_time - now).total_seconds()
                if delay > 0:
                    await asyncio.sleep(delay)

                if not self._running:
                    break

                # Check for overlap before executing (Requirement 11.7)
                if self.check_overlap(job.id):
                    await self._emit_scan_skipped(job)
                    continue

                # Execute the scan
                await self._execute_scan(job)

        except asyncio.CancelledError:
            logger.debug(f"Cron loop cancelled for job {job.id}")
        except Exception as e:
            logger.error(f"Unexpected error in cron loop for job {job.id}: {e}")

    async def _execute_scan(self, job: ScanJob) -> ScanResult:
        """Execute a scan job and record results.

        Sets the job to running state, invokes the scan executor,
        records results, and handles failures with alert generation.

        Args:
            job: The ScanJob to execute.

        Returns:
            ScanResult with execution details.

        Requirements: 11.2, 11.5, 11.6
        """
        started_at = datetime.now(timezone.utc)
        job._running = True
        job.status = "running"

        try:
            if self._scan_executor:
                result = await self._scan_executor(job)
            else:
                # No executor configured - return empty result
                result = ScanResult(
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    status="completed",
                )

            # Record results (Requirement 11.2)
            result.started_at = started_at
            if result.completed_at is None:
                result.completed_at = datetime.now(timezone.utc)

            job.status = result.status
            job.last_result = result

            # Emit completion event
            await self._emit_event({
                "type": "scan_completed",
                "job_id": job.id,
                "job_name": job.config.name,
                "started_at": result.started_at.isoformat(),
                "completed_at": result.completed_at.isoformat(),
                "devices_discovered": result.devices_discovered,
                "new_devices": result.new_devices,
                "alerts_generated": result.alerts_generated,
                "status": result.status,
            })

            return result

        except Exception as e:
            # Scan failed (Requirement 11.6)
            completed_at = datetime.now(timezone.utc)
            failure_reason = str(e)

            result = ScanResult(
                started_at=started_at,
                completed_at=completed_at,
                status="failed",
                failure_reason=failure_reason,
            )

            job.status = "failed"
            job.last_result = result

            logger.error(f"Scan job '{job.config.name}' failed: {failure_reason}")

            # Generate "scan_failed" alert with severity HIGH (Requirement 11.6)
            await self._emit_scan_failed_alert(job, failure_reason)

            return result

        finally:
            job._running = False

    async def _emit_scan_skipped(self, job: ScanJob) -> None:
        """Emit a scan_skipped event when overlap is detected.

        Requirement 11.7: Skip execution and record event with reason.

        Args:
            job: The ScanJob that was skipped.
        """
        event = {
            "type": "scan_skipped",
            "job_id": job.id,
            "job_name": job.config.name,
            "reason": "previous execution still in progress",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.warning(
            f"Scan job '{job.config.name}' skipped: previous execution still in progress"
        )

        await self._emit_event(event)

    async def _emit_scan_failed_alert(self, job: ScanJob, failure_reason: str) -> None:
        """Generate a scan_failed alert with severity HIGH.

        Requirement 11.6: Record failure reason and generate alert.

        Args:
            job: The failed ScanJob.
            failure_reason: Description of why the scan failed.
        """
        alert = Alert(
            id=uuid.uuid4(),
            alert_type="scan_failed",
            severity="HIGH",
            device_id=None,
            details={
                "job_id": job.id,
                "job_name": job.config.name,
                "failure_reason": failure_reason,
                "target_subnet": job.config.target_subnet,
            },
            generated_at=datetime.now(timezone.utc),
        )

        if self._on_alert:
            try:
                await self._on_alert(alert)
            except Exception as e:
                logger.error(f"Error emitting scan_failed alert: {e}")

    async def _emit_event(self, event: dict) -> None:
        """Emit a scan event to the registered callback.

        Args:
            event: Event dictionary with type and details.
        """
        if self._on_event:
            try:
                await self._on_event(event)
            except Exception as e:
                logger.error(f"Error emitting scan event: {e}")

    def list_jobs(self) -> list[ScanJob]:
        """List all registered scan jobs.

        Returns:
            List of all ScanJob objects.
        """
        return list(self._jobs.values())
