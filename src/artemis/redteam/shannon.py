"""
Shannon Engine Interface
Wraps Shannon autonomous pentester for Artemis integration.
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from .controller import ScanMode

logger = logging.getLogger("artemis.redteam.shannon")


class ShannonEngine:
    """
    Interface to Shannon autonomous pentester.
    
    Shannon runs in Docker with Temporal orchestration.
    This class handles:
    - Starting/stopping Shannon containers
    - Launching scan jobs
    - Monitoring progress
    - Retrieving results
    """
    
    def __init__(
        self,
        shannon_dir: Path,
        output_dir: Path,
        docker_compose: str = "docker compose",
    ):
        self.shannon_dir = Path(shannon_dir)
        self.output_dir = Path(output_dir)
        self.docker_compose = docker_compose
        
        # Validate Shannon installation
        self._validate_installation()
        
        logger.info(f"ShannonEngine initialized: {self.shannon_dir}")
    
    def _validate_installation(self):
        """Validate Shannon is properly installed."""
        required_files = [
            "shannon",
            "docker-compose.yml",
            "src/temporal/workflows.ts",
        ]
        
        for f in required_files:
            if not (self.shannon_dir / f).exists():
                raise RuntimeError(f"Shannon installation incomplete: missing {f}")
        
        # Check Docker is available
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("Docker may not be running")
        except Exception as e:
            logger.warning(f"Docker check failed: {e}")
    
    def _mode_to_shannon_args(self, mode: ScanMode) -> dict:
        """Convert Artemis scan mode to Shannon arguments."""
        # Shannon doesn't have direct mode mapping, but we can configure via:
        # - CONFIG file for depth/scope
        # - Environment variables
        
        configs = {
            ScanMode.RECON: {
                "phases": ["pre-recon", "recon"],
                "skip_exploit": True,
            },
            ScanMode.VULN_SCAN: {
                "phases": ["pre-recon", "recon", "vuln"],
                "skip_exploit": True,
            },
            ScanMode.FULL_AUDIT: {
                "phases": ["all"],
                "skip_exploit": False,
            },
            ScanMode.COUNTER_RECON: {
                "phases": ["pre-recon", "recon"],
                "skip_exploit": True,
                "external": True,
            },
            ScanMode.COUNTER_FULL: {
                "phases": ["all"],
                "skip_exploit": False,
                "external": True,
            },
        }
        
        return configs.get(mode, configs[ScanMode.RECON])
    
    async def ensure_running(self) -> bool:
        """Ensure Shannon containers are running."""
        try:
            # Check if Temporal is healthy
            result = await asyncio.to_thread(
                subprocess.run,
                [*self.docker_compose.split(), "ps", "--format", "json"],
                cwd=self.shannon_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if "temporal" not in result.stdout.lower():
                # Start containers
                logger.info("Starting Shannon containers...")
                await self._start_containers()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to ensure Shannon running: {e}")
            return False
    
    async def _start_containers(self):
        """Start Shannon Docker containers."""
        result = await asyncio.to_thread(
            subprocess.run,
            [*self.docker_compose.split(), "up", "-d", "temporal"],
            cwd=self.shannon_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start Shannon: {result.stderr}")
        
        # Wait for Temporal to be healthy
        for _ in range(30):
            await asyncio.sleep(2)
            try:
                health = await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "exec", "shannon-temporal-1", "temporal", "operator", "cluster", "health"],
                    capture_output=True,
                    timeout=10,
                )
                if health.returncode == 0:
                    logger.info("Temporal is healthy")
                    return
            except:
                pass
        
        logger.warning("Temporal health check timed out, continuing anyway")
    
    async def run_scan(
        self,
        target: str,
        mode: ScanMode,
        config: Optional[dict] = None,
        job_id: Optional[str] = None,
    ) -> dict:
        """
        Run a Shannon scan.
        
        Args:
            target: URL or IP to scan
            mode: Scan mode (recon, vuln, full, etc.)
            config: Additional configuration
            job_id: Artemis job ID for tracking
            
        Returns:
            dict with findings_count, report_path, etc.
        """
        workspace = job_id or f"artemis-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Ensure containers are running
        if not await self.ensure_running():
            raise RuntimeError("Failed to start Shannon containers")
        
        # Build command
        mode_config = self._mode_to_shannon_args(mode)
        
        # For now, we'll run Shannon via its CLI script
        # In production, we'd use the Temporal API directly
        cmd = [
            "bash", "shannon", "start",
            f"URL={target}",
            f"WORKSPACE={workspace}",
        ]
        
        # Add output directory
        cmd.append(f"OUTPUT={self.output_dir}")
        
        logger.info(f"Starting Shannon scan: {' '.join(cmd)}")
        
        try:
            # Run Shannon (this is a long-running process)
            process = await asyncio.to_thread(
                subprocess.Popen,
                cmd,
                cwd=self.shannon_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env={
                    **os.environ,
                    "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY", ""),
                },
            )
            
            # Monitor progress
            workflow_id = None
            while True:
                line = await asyncio.to_thread(process.stdout.readline)
                if not line:
                    break
                    
                logger.debug(f"Shannon: {line.strip()}")
                
                # Extract workflow ID
                if "workflow ID:" in line.lower() or "started workflow" in line.lower():
                    # Parse workflow ID from output
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p.lower() in ["id:", "workflow"]:
                            if i + 1 < len(parts):
                                workflow_id = parts[i + 1].strip()
                                break
            
            # Wait for completion
            await asyncio.to_thread(process.wait)
            
            # Collect results
            return await self._collect_results(workspace, target)
            
        except asyncio.CancelledError:
            # Kill Shannon process
            if process:
                process.terminate()
            raise
    
    async def _collect_results(self, workspace: str, target: str) -> dict:
        """Collect results from Shannon output."""
        # Find the output directory
        # Shannon uses format: audit-logs/{hostname}_{sessionId}/
        
        results = {
            "findings_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "report_path": None,
            "workspace_path": None,
        }
        
        # Search for workspace directory
        for audit_dir in self.output_dir.glob(f"*{workspace}*"):
            if audit_dir.is_dir():
                results["workspace_path"] = str(audit_dir)
                
                # Find report
                report_path = audit_dir / "deliverables" / "comprehensive_security_assessment_report.md"
                if report_path.exists():
                    results["report_path"] = str(report_path)
                    
                    # Parse report for findings
                    report_content = report_path.read_text()
                    results.update(self._parse_findings(report_content))
                
                # Check session.json for metrics
                session_path = audit_dir / "session.json"
                if session_path.exists():
                    try:
                        session_data = json.loads(session_path.read_text())
                        # Extract any additional metrics
                    except:
                        pass
                
                break
        
        return results
    
    def _parse_findings(self, report_content: str) -> dict:
        """Parse findings from Shannon report."""
        findings = {
            "findings_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        
        content_lower = report_content.lower()
        
        # Count severity markers
        # Shannon reports typically have sections like "Critical Findings", "High Findings", etc.
        
        # Simple heuristic: count occurrence patterns
        import re
        
        # Look for severity headers
        critical_matches = re.findall(r'critical|severity:\s*critical', content_lower)
        high_matches = re.findall(r'(?<!non-)high|severity:\s*high', content_lower)
        medium_matches = re.findall(r'medium|severity:\s*medium', content_lower)
        low_matches = re.findall(r'(?<!be)low|severity:\s*low', content_lower)
        
        # Be conservative - count distinct finding sections
        findings["critical"] = min(len(critical_matches), 20)
        findings["high"] = min(len(high_matches), 20)
        findings["medium"] = min(len(medium_matches), 20)
        findings["low"] = min(len(low_matches), 20)
        
        findings["findings_count"] = (
            findings["critical"] + 
            findings["high"] + 
            findings["medium"] + 
            findings["low"]
        )
        
        return findings
    
    async def get_job_status(self, workflow_id: str) -> dict:
        """Query Temporal for job status."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    *self.docker_compose.split(), "exec", "temporal",
                    "temporal", "workflow", "describe",
                    "--workflow-id", workflow_id,
                    "--output", "json",
                ],
                cwd=self.shannon_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
                
        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
        
        return {}
    
    async def stop(self):
        """Stop Shannon containers."""
        try:
            await asyncio.to_thread(
                subprocess.run,
                [*self.docker_compose.split(), "stop"],
                cwd=self.shannon_dir,
                capture_output=True,
                timeout=60,
            )
            logger.info("Shannon containers stopped")
        except Exception as e:
            logger.error(f"Failed to stop Shannon: {e}")
    
    def is_available(self) -> bool:
        """Check if Shannon is available and configured."""
        try:
            # Check for API key
            if not os.getenv("ANTHROPIC_API_KEY"):
                return False
            
            # Check Docker
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
            
        except:
            return False
