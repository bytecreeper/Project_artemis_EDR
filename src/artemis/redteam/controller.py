"""
Red Team Controller
Manages pentest jobs, triggers, and orchestration.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Any
import json

logger = logging.getLogger("artemis.redteam")


class JobStatus(str, Enum):
    """Pentest job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"


class ScanMode(str, Enum):
    """Scan mode determines depth and approach."""
    RECON = "recon"              # Quick reconnaissance only
    VULN_SCAN = "vuln_scan"      # Vulnerability analysis
    FULL_AUDIT = "full_audit"    # Complete pentest
    COUNTER_RECON = "counter_recon"    # Counter-attack recon only
    COUNTER_FULL = "counter_full"      # Full counter-attack (requires approval)


class TriggerType(str, Enum):
    """What triggered the scan."""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    NEW_SERVICE = "new_service"
    NEW_DEVICE = "new_device"
    THREAT_DETECTED = "threat"
    HONEYPOT = "honeypot"
    TRAFFIC_ANOMALY = "traffic_anomaly"


@dataclass
class PentestJob:
    """Represents a penetration testing job."""
    id: str
    target: str
    mode: ScanMode
    status: JobStatus
    trigger: TriggerType
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Paths
    report_path: Optional[str] = None
    workspace_path: Optional[str] = None
    
    # Config
    config: dict = field(default_factory=dict)
    error: Optional[str] = None
    
    # Approval tracking
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d['mode'] = self.mode.value
        d['status'] = self.status.value
        d['trigger'] = self.trigger.value
        # Convert datetimes to ISO strings
        for key in ['created_at', 'started_at', 'completed_at', 'approved_at']:
            if d[key]:
                d[key] = d[key].isoformat()
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> 'PentestJob':
        """Create from dictionary."""
        data = data.copy()
        data['mode'] = ScanMode(data['mode'])
        data['status'] = JobStatus(data['status'])
        data['trigger'] = TriggerType(data['trigger'])
        for key in ['created_at', 'started_at', 'completed_at', 'approved_at']:
            if data.get(key):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)


@dataclass
class ScanConstraints:
    """Safety constraints for scanning."""
    internal_networks: list = field(default_factory=lambda: [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
    ])
    max_concurrent_jobs: int = 2
    cooldown_minutes: int = 15  # Per-target cooldown
    modes_requiring_approval: list = field(default_factory=lambda: [
        ScanMode.COUNTER_FULL.value,
    ])


class RedTeamController:
    """
    Manages red team operations and Shannon integration.
    
    Autonomous operation with permission prompts for destructive actions only.
    """
    
    def __init__(
        self,
        data_dir: Path,
        constraints: Optional[ScanConstraints] = None,
        on_approval_needed: Optional[Callable] = None,
    ):
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "redteam" / "jobs"
        self.reports_dir = self.data_dir / "redteam" / "reports"
        self.constraints = constraints or ScanConstraints()
        self.on_approval_needed = on_approval_needed
        
        # In-memory job tracking
        self._jobs: dict[str, PentestJob] = {}
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._target_cooldowns: dict[str, datetime] = {}
        
        # Shannon engine (lazy loaded)
        self._shannon = None
        
        # Ensure directories exist
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Load persisted jobs
        self._load_jobs()
        
        logger.info(f"RedTeamController initialized - {len(self._jobs)} jobs loaded")
    
    def _load_jobs(self):
        """Load jobs from disk."""
        for job_file in self.jobs_dir.glob("*.json"):
            try:
                with open(job_file) as f:
                    data = json.load(f)
                job = PentestJob.from_dict(data)
                self._jobs[job.id] = job
            except Exception as e:
                logger.error(f"Failed to load job {job_file}: {e}")
    
    def _save_job(self, job: PentestJob):
        """Persist job to disk."""
        job_file = self.jobs_dir / f"{job.id}.json"
        with open(job_file, 'w') as f:
            json.dump(job.to_dict(), f, indent=2)
    
    def _check_cooldown(self, target: str) -> bool:
        """Check if target is in cooldown period."""
        if target in self._target_cooldowns:
            cooldown_until = self._target_cooldowns[target]
            if datetime.now(timezone.utc) < cooldown_until:
                return False
        return True
    
    def _set_cooldown(self, target: str):
        """Set cooldown for target."""
        from datetime import timedelta
        self._target_cooldowns[target] = (
            datetime.now(timezone.utc) + 
            timedelta(minutes=self.constraints.cooldown_minutes)
        )
    
    def _count_running(self) -> int:
        """Count currently running jobs."""
        return sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)
    
    def _requires_approval(self, mode: ScanMode) -> bool:
        """Check if mode requires human approval."""
        return mode.value in self.constraints.modes_requiring_approval
    
    async def create_job(
        self,
        target: str,
        mode: ScanMode,
        trigger: TriggerType = TriggerType.MANUAL,
        config: Optional[dict] = None,
        bypass_cooldown: bool = False,
    ) -> PentestJob:
        """
        Create a new pentest job.
        
        Returns the job (may be in AWAITING_APPROVAL status if approval needed).
        """
        # Check constraints
        if not bypass_cooldown and not self._check_cooldown(target):
            raise ValueError(f"Target {target} is in cooldown period")
        
        if self._count_running() >= self.constraints.max_concurrent_jobs:
            raise ValueError(f"Max concurrent jobs ({self.constraints.max_concurrent_jobs}) reached")
        
        # Create job
        job = PentestJob(
            id=f"job-{uuid.uuid4().hex[:12]}",
            target=target,
            mode=mode,
            status=JobStatus.PENDING,
            trigger=trigger,
            config=config or {},
            requires_approval=self._requires_approval(mode),
        )
        
        # If requires approval, set status and notify
        if job.requires_approval:
            job.status = JobStatus.AWAITING_APPROVAL
            logger.warning(f"Job {job.id} requires approval for {mode.value} on {target}")
            if self.on_approval_needed:
                await self.on_approval_needed(job)
        
        self._jobs[job.id] = job
        self._save_job(job)
        
        logger.info(f"Created job {job.id}: {mode.value} on {target} ({trigger.value})")
        
        # Auto-start if doesn't require approval
        if not job.requires_approval:
            asyncio.create_task(self.start_job(job.id))
        
        return job
    
    async def approve_job(self, job_id: str, approved_by: str = "user") -> PentestJob:
        """Approve a job that requires approval."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if job.status != JobStatus.AWAITING_APPROVAL:
            raise ValueError(f"Job {job_id} is not awaiting approval")
        
        job.approved_by = approved_by
        job.approved_at = datetime.now(timezone.utc)
        job.status = JobStatus.PENDING
        self._save_job(job)
        
        logger.info(f"Job {job_id} approved by {approved_by}")
        
        # Start the job
        asyncio.create_task(self.start_job(job_id))
        
        return job
    
    async def start_job(self, job_id: str) -> PentestJob:
        """Start a pending job."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if job.status not in [JobStatus.PENDING]:
            raise ValueError(f"Job {job_id} cannot be started (status: {job.status})")
        
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        self._save_job(job)
        
        # Set cooldown
        self._set_cooldown(job.target)
        
        # Create async task for execution
        task = asyncio.create_task(self._execute_job(job))
        self._running_tasks[job_id] = task
        
        logger.info(f"Started job {job_id}")
        return job
    
    async def _execute_job(self, job: PentestJob):
        """Execute a pentest job via Shannon."""
        try:
            # Lazy load Shannon engine
            if not self._shannon:
                from .shannon import ShannonEngine
                self._shannon = ShannonEngine(
                    shannon_dir=self.data_dir.parent / "shannon-integration",
                    output_dir=self.reports_dir,
                )
            
            # Run the scan
            result = await self._shannon.run_scan(
                target=job.target,
                mode=job.mode,
                config=job.config,
                job_id=job.id,
            )
            
            # Update job with results
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.findings_count = result.get('findings_count', 0)
            job.critical_count = result.get('critical', 0)
            job.high_count = result.get('high', 0)
            job.medium_count = result.get('medium', 0)
            job.low_count = result.get('low', 0)
            job.report_path = result.get('report_path')
            job.workspace_path = result.get('workspace_path')
            
            logger.info(f"Job {job.id} completed: {job.findings_count} findings")
            
        except asyncio.CancelledError:
            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.now(timezone.utc)
            logger.info(f"Job {job.id} cancelled")
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error = str(e)
            logger.error(f"Job {job.id} failed: {e}")
        
        finally:
            self._save_job(job)
            self._running_tasks.pop(job.id, None)
    
    async def cancel_job(self, job_id: str) -> PentestJob:
        """Cancel a running or pending job."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        if job.status == JobStatus.RUNNING:
            task = self._running_tasks.get(job_id)
            if task:
                task.cancel()
        
        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.now(timezone.utc)
        self._save_job(job)
        
        logger.info(f"Cancelled job {job_id}")
        return job
    
    def get_job(self, job_id: str) -> Optional[PentestJob]:
        """Get a job by ID."""
        return self._jobs.get(job_id)
    
    def list_jobs(
        self,
        status: Optional[JobStatus] = None,
        limit: int = 50,
    ) -> list[PentestJob]:
        """List jobs, optionally filtered by status."""
        jobs = list(self._jobs.values())
        
        if status:
            jobs = [j for j in jobs if j.status == status]
        
        # Sort by created_at descending
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        
        return jobs[:limit]
    
    def get_report(self, job_id: str) -> Optional[str]:
        """Get the report content for a completed job."""
        job = self._jobs.get(job_id)
        if not job or not job.report_path:
            return None
        
        report_file = Path(job.report_path)
        if report_file.exists():
            return report_file.read_text()
        return None
    
    async def quick_recon(self, target: str, trigger: TriggerType = TriggerType.MANUAL) -> PentestJob:
        """Convenience method for quick reconnaissance scan."""
        return await self.create_job(target, ScanMode.RECON, trigger)
    
    async def full_audit(self, target: str, trigger: TriggerType = TriggerType.MANUAL) -> PentestJob:
        """Convenience method for full audit scan."""
        return await self.create_job(target, ScanMode.FULL_AUDIT, trigger)
    
    async def counter_attack(self, target: str, full: bool = False) -> PentestJob:
        """
        Launch counter-attack against threat actor.
        
        Args:
            target: IP/hostname of threat actor
            full: If True, requires approval for full pentest. Default is recon-only.
        """
        mode = ScanMode.COUNTER_FULL if full else ScanMode.COUNTER_RECON
        return await self.create_job(
            target=target,
            mode=mode,
            trigger=TriggerType.THREAT_DETECTED,
            bypass_cooldown=True,  # Counter-attacks bypass cooldown
        )
    
    def get_stats(self) -> dict:
        """Get summary statistics."""
        jobs = list(self._jobs.values())
        return {
            "total_jobs": len(jobs),
            "running": sum(1 for j in jobs if j.status == JobStatus.RUNNING),
            "completed": sum(1 for j in jobs if j.status == JobStatus.COMPLETED),
            "failed": sum(1 for j in jobs if j.status == JobStatus.FAILED),
            "awaiting_approval": sum(1 for j in jobs if j.status == JobStatus.AWAITING_APPROVAL),
            "total_findings": sum(j.findings_count for j in jobs),
            "critical_findings": sum(j.critical_count for j in jobs),
        }
