"""
AI-Powered Remediation Engine
Interactive and automated threat response with integrity validation.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger("artemis.agent.remediation")


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ActionType(Enum):
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"
    KILL_PROCESS = "kill_process"
    BLOCK_IP = "block_ip"
    DISABLE_SERVICE = "disable_service"
    REGISTRY_RESTORE = "registry_restore"
    ROLLBACK_CHANGE = "rollback_change"
    SCAN_FULL = "scan_full"
    UPDATE_RULES = "update_rules"


@dataclass
class Threat:
    """Detected threat."""
    id: str
    timestamp: str
    severity: ThreatSeverity
    title: str
    description: str
    source: str  # file, process, network, registry
    indicators: list[str] = field(default_factory=list)
    affected_items: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0
    verified: bool = False  # Second scan confirmation
    remediation_options: list[dict] = field(default_factory=list)


@dataclass
class RemediationAction:
    """Remediation action to take."""
    id: str
    threat_id: str
    action_type: ActionType
    target: str
    parameters: dict = field(default_factory=dict)
    status: RemediationStatus = RemediationStatus.PENDING
    requires_approval: bool = True
    automated: bool = False
    rollback_data: dict = field(default_factory=dict)
    result: str = ""
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class IntegrityCheck:
    """Integrity validation result."""
    check_id: str
    timestamp: str
    target: str
    original_verdict: str
    verification_verdict: str
    confidence_original: float
    confidence_verification: float
    is_confirmed: bool
    discrepancy_notes: str = ""


class RemediationEngine:
    """
    AI-powered remediation with integrity validation.
    
    Features:
    - AI-assisted threat analysis
    - Interactive remediation walkthroughs
    - Automated remediation (with approval)
    - Double-scan integrity validation
    - Rollback capabilities
    """
    
    def __init__(
        self,
        model: str = "deepseek-r1:70b",
        provider: str = "ollama",
        quarantine_dir: Optional[Path] = None,
        auto_remediate_low: bool = False,
        require_approval_high: bool = True,
    ):
        self.model = model
        self.provider = provider
        self.quarantine_dir = quarantine_dir or Path.home() / ".artemis" / "quarantine"
        self.auto_remediate_low = auto_remediate_low
        self.require_approval_high = require_approval_high
        
        # Ensure quarantine dir exists
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # State
        self.threats: dict[str, Threat] = {}
        self.actions: dict[str, RemediationAction] = {}
        self.integrity_checks: list[IntegrityCheck] = []
        
        # Pending approvals
        self.pending_approvals: list[str] = []
        
        # Callbacks
        self._on_threat: list[callable] = []
        self._on_action: list[callable] = []
        self._on_approval_needed: list[callable] = []
    
    # =========================================================================
    # THREAT ANALYSIS
    # =========================================================================
    
    async def analyze_threat(
        self,
        source: str,
        data: dict,
        context: str = "",
    ) -> Optional[Threat]:
        """
        Analyze potential threat with AI.
        Performs double-verification for integrity.
        """
        # First analysis
        first_result = await self._ai_analyze(source, data, context)
        
        if not first_result or first_result.get("is_threat") is False:
            return None
        
        # Second analysis for verification (anti-hallucination)
        second_result = await self._ai_analyze(
            source, data, 
            context + "\n[VERIFICATION PASS - Confirm or deny the threat assessment]"
        )
        
        # Create integrity check
        check = IntegrityCheck(
            check_id=self._generate_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=str(data),
            original_verdict=first_result.get("verdict", "unknown"),
            verification_verdict=second_result.get("verdict", "unknown") if second_result else "failed",
            confidence_original=first_result.get("confidence", 0),
            confidence_verification=second_result.get("confidence", 0) if second_result else 0,
            is_confirmed=self._verdicts_match(first_result, second_result),
        )
        
        self.integrity_checks.append(check)
        
        # Only proceed if verified
        if not check.is_confirmed:
            logger.warning(f"Threat not verified - discrepancy detected")
            check.discrepancy_notes = "AI verdicts did not match - potential hallucination"
            return None
        
        # Create threat
        threat = Threat(
            id=self._generate_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=ThreatSeverity(first_result.get("severity", "medium")),
            title=first_result.get("title", "Potential Threat"),
            description=first_result.get("description", ""),
            source=source,
            indicators=first_result.get("indicators", []),
            affected_items=[data],
            mitre_techniques=first_result.get("mitre", []),
            confidence=first_result.get("confidence", 0),
            verified=True,
            remediation_options=await self._get_remediation_options(first_result, source, data),
        )
        
        self.threats[threat.id] = threat
        
        # Notify
        for cb in self._on_threat:
            try:
                await cb(threat)
            except Exception:
                pass
        
        return threat
    
    async def _ai_analyze(self, source: str, data: dict, context: str) -> Optional[dict]:
        """Run AI analysis."""
        try:
            import httpx
            
            prompt = f"""Analyze this {source} for security threats:

Data: {json.dumps(data, default=str)}

Context: {context}

Respond with JSON only:
{{
    "is_threat": true/false,
    "verdict": "clean|suspicious|malicious",
    "severity": "low|medium|high|critical",
    "confidence": 0.0-1.0,
    "title": "Brief threat title",
    "description": "Detailed explanation",
    "indicators": ["list", "of", "IOCs"],
    "mitre": ["T1059", "technique IDs"],
    "recommended_actions": ["action1", "action2"]
}}"""
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                    timeout=90.0,
                )
                
                if response.status_code == 200:
                    result = response.json()
                    text = result.get("response", "")
                    
                    # Extract JSON
                    import re
                    match = re.search(r'\{[\s\S]*\}', text)
                    if match:
                        return json.loads(match.group())
                        
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
        
        return None
    
    def _verdicts_match(self, first: dict, second: Optional[dict]) -> bool:
        """Check if two AI verdicts match (anti-hallucination)."""
        if not second:
            return False
        
        v1 = first.get("verdict", "").lower()
        v2 = second.get("verdict", "").lower()
        
        # Exact match
        if v1 == v2:
            return True
        
        # Close enough (both indicate threat or both clean)
        threat_verdicts = {"suspicious", "malicious", "threat"}
        clean_verdicts = {"clean", "safe", "benign"}
        
        if v1 in threat_verdicts and v2 in threat_verdicts:
            return True
        if v1 in clean_verdicts and v2 in clean_verdicts:
            return True
        
        return False
    
    async def _get_remediation_options(
        self,
        analysis: dict,
        source: str,
        data: dict,
    ) -> list[dict]:
        """Generate remediation options based on threat."""
        options = []
        
        if source == "file":
            options.extend([
                {
                    "action": ActionType.QUARANTINE_FILE.value,
                    "label": "Quarantine File",
                    "description": "Move file to quarantine folder (recoverable)",
                    "risk": "low",
                    "automated": True,
                },
                {
                    "action": ActionType.DELETE_FILE.value,
                    "label": "Delete File",
                    "description": "Permanently delete the file",
                    "risk": "medium",
                    "automated": False,
                },
            ])
        
        elif source == "process":
            options.extend([
                {
                    "action": ActionType.KILL_PROCESS.value,
                    "label": "Terminate Process",
                    "description": "Kill the malicious process",
                    "risk": "low",
                    "automated": True,
                },
            ])
            
            # If process has associated file
            if data.get("exe"):
                options.append({
                    "action": ActionType.QUARANTINE_FILE.value,
                    "label": "Quarantine Executable",
                    "description": "Quarantine the process executable",
                    "risk": "medium",
                    "automated": False,
                })
        
        elif source == "network":
            options.extend([
                {
                    "action": ActionType.BLOCK_IP.value,
                    "label": "Block IP Address",
                    "description": "Add firewall rule to block this IP",
                    "risk": "low",
                    "automated": True,
                },
                {
                    "action": ActionType.KILL_PROCESS.value,
                    "label": "Terminate Connection",
                    "description": "Kill the process making this connection",
                    "risk": "medium",
                    "automated": False,
                },
            ])
        
        elif source == "service":
            options.extend([
                {
                    "action": ActionType.DISABLE_SERVICE.value,
                    "label": "Disable Service",
                    "description": "Stop and disable the malicious service",
                    "risk": "medium",
                    "automated": False,
                },
            ])
        
        # Always add scan option
        options.append({
            "action": ActionType.SCAN_FULL.value,
            "label": "Full System Scan",
            "description": "Run comprehensive system scan",
            "risk": "low",
            "automated": True,
        })
        
        return options
    
    # =========================================================================
    # REMEDIATION EXECUTION
    # =========================================================================
    
    async def create_remediation(
        self,
        threat_id: str,
        action_type: ActionType,
        target: str,
        parameters: dict = None,
        auto_execute: bool = False,
    ) -> RemediationAction:
        """Create a remediation action."""
        threat = self.threats.get(threat_id)
        
        action = RemediationAction(
            id=self._generate_id(),
            threat_id=threat_id,
            action_type=action_type,
            target=target,
            parameters=parameters or {},
            requires_approval=not auto_execute and (
                threat.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)
                if threat else True
            ),
        )
        
        self.actions[action.id] = action
        
        if action.requires_approval:
            self.pending_approvals.append(action.id)
            action.status = RemediationStatus.AWAITING_APPROVAL
            
            for cb in self._on_approval_needed:
                try:
                    await cb(action)
                except Exception:
                    pass
        elif auto_execute:
            await self.execute_remediation(action.id)
        
        return action
    
    async def execute_remediation(
        self,
        action_id: str,
        approved_by: str = "system",
    ) -> bool:
        """Execute a remediation action."""
        action = self.actions.get(action_id)
        if not action:
            return False
        
        action.status = RemediationStatus.IN_PROGRESS
        action.executed_at = datetime.now(timezone.utc).isoformat()
        
        try:
            # Execute based on action type
            if action.action_type == ActionType.QUARANTINE_FILE:
                success = await self._quarantine_file(action)
            elif action.action_type == ActionType.DELETE_FILE:
                success = await self._delete_file(action)
            elif action.action_type == ActionType.KILL_PROCESS:
                success = await self._kill_process(action)
            elif action.action_type == ActionType.BLOCK_IP:
                success = await self._block_ip(action)
            elif action.action_type == ActionType.DISABLE_SERVICE:
                success = await self._disable_service(action)
            else:
                action.result = f"Unknown action type: {action.action_type}"
                success = False
            
            action.status = RemediationStatus.COMPLETED if success else RemediationStatus.FAILED
            action.completed_at = datetime.now(timezone.utc).isoformat()
            
            # Remove from pending
            if action_id in self.pending_approvals:
                self.pending_approvals.remove(action_id)
            
            # Notify
            for cb in self._on_action:
                try:
                    await cb(action)
                except Exception:
                    pass
            
            return success
            
        except Exception as e:
            action.status = RemediationStatus.FAILED
            action.result = str(e)
            logger.error(f"Remediation failed: {e}")
            return False
    
    async def _quarantine_file(self, action: RemediationAction) -> bool:
        """Move file to quarantine."""
        try:
            src = Path(action.target)
            if not src.exists():
                action.result = "File not found"
                return False
            
            # Save rollback data
            action.rollback_data = {
                "original_path": str(src),
                "hash_md5": hashlib.md5(src.read_bytes()).hexdigest(),
            }
            
            # Move to quarantine
            dst = self.quarantine_dir / f"{action.id}_{src.name}"
            shutil.move(str(src), str(dst))
            
            action.result = f"File quarantined to {dst}"
            logger.info(f"Quarantined: {src} -> {dst}")
            return True
            
        except Exception as e:
            action.result = str(e)
            return False
    
    async def _delete_file(self, action: RemediationAction) -> bool:
        """Delete file (with backup to quarantine first)."""
        try:
            src = Path(action.target)
            if not src.exists():
                action.result = "File not found"
                return False
            
            # Backup first
            action.rollback_data = {
                "original_path": str(src),
                "backup_path": str(self.quarantine_dir / f"deleted_{action.id}_{src.name}"),
            }
            shutil.copy2(str(src), action.rollback_data["backup_path"])
            
            # Delete
            src.unlink()
            
            action.result = f"File deleted (backup in quarantine)"
            return True
            
        except Exception as e:
            action.result = str(e)
            return False
    
    async def _kill_process(self, action: RemediationAction) -> bool:
        """Terminate a process."""
        try:
            pid = action.parameters.get("pid") or int(action.target)
            
            proc = psutil.Process(pid)
            action.rollback_data = {
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
            }
            
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
            
            action.result = f"Process {pid} terminated"
            return True
            
        except psutil.NoSuchProcess:
            action.result = "Process not found"
            return False
        except Exception as e:
            action.result = str(e)
            return False
    
    async def _block_ip(self, action: RemediationAction) -> bool:
        """Add firewall rule to block IP."""
        try:
            import platform
            ip = action.target
            
            if platform.system() == "Windows":
                # Windows Firewall
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Artemis_Block_{ip}",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip}",
                ]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    action.result = f"Blocked outbound to {ip}"
                    action.rollback_data = {"rule_name": f"Artemis_Block_{ip}"}
                    return True
                else:
                    action.result = result.stderr
                    return False
            else:
                # Linux iptables
                cmd = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    action.result = f"Blocked {ip} via iptables"
                    return True
                else:
                    action.result = result.stderr
                    return False
                    
        except Exception as e:
            action.result = str(e)
            return False
    
    async def _disable_service(self, action: RemediationAction) -> bool:
        """Disable a Windows service."""
        try:
            import platform
            if platform.system() != "Windows":
                action.result = "Service management only on Windows"
                return False
            
            service_name = action.target
            
            # Stop service
            subprocess.run(
                ["sc", "stop", service_name],
                capture_output=True
            )
            
            # Disable service
            result = subprocess.run(
                ["sc", "config", service_name, "start=", "disabled"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                action.result = f"Service {service_name} disabled"
                action.rollback_data = {"service_name": service_name}
                return True
            else:
                action.result = result.stderr
                return False
                
        except Exception as e:
            action.result = str(e)
            return False
    
    # =========================================================================
    # ROLLBACK
    # =========================================================================
    
    async def rollback_action(self, action_id: str) -> bool:
        """Rollback a remediation action."""
        action = self.actions.get(action_id)
        if not action or not action.rollback_data:
            return False
        
        try:
            if action.action_type == ActionType.QUARANTINE_FILE:
                # Restore from quarantine
                original = action.rollback_data.get("original_path")
                quarantined = self.quarantine_dir / f"{action.id}_{Path(original).name}"
                if quarantined.exists():
                    shutil.move(str(quarantined), original)
                    action.status = RemediationStatus.ROLLED_BACK
                    return True
            
            elif action.action_type == ActionType.DELETE_FILE:
                # Restore from backup
                backup = action.rollback_data.get("backup_path")
                original = action.rollback_data.get("original_path")
                if backup and Path(backup).exists():
                    shutil.copy2(backup, original)
                    action.status = RemediationStatus.ROLLED_BACK
                    return True
            
            elif action.action_type == ActionType.BLOCK_IP:
                # Remove firewall rule
                rule_name = action.rollback_data.get("rule_name")
                if rule_name:
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        capture_output=True
                    )
                    action.status = RemediationStatus.ROLLED_BACK
                    return True
            
            elif action.action_type == ActionType.DISABLE_SERVICE:
                # Re-enable service
                service_name = action.rollback_data.get("service_name")
                if service_name:
                    subprocess.run(
                        ["sc", "config", service_name, "start=", "auto"],
                        capture_output=True
                    )
                    subprocess.run(
                        ["sc", "start", service_name],
                        capture_output=True
                    )
                    action.status = RemediationStatus.ROLLED_BACK
                    return True
                    
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
        
        return False
    
    # =========================================================================
    # INTERACTIVE WALKTHROUGH
    # =========================================================================
    
    async def get_remediation_walkthrough(
        self,
        threat_id: str,
        action_type: ActionType,
    ) -> list[dict]:
        """Get step-by-step remediation walkthrough from AI."""
        threat = self.threats.get(threat_id)
        if not threat:
            return []
        
        try:
            import httpx
            
            prompt = f"""Provide a step-by-step remediation walkthrough for this threat:

Threat: {threat.title}
Description: {threat.description}
Action: {action_type.value}
Severity: {threat.severity.value}

Provide JSON with detailed steps:
{{
    "steps": [
        {{
            "step": 1,
            "title": "Step title",
            "description": "Detailed description",
            "command": "optional command to run",
            "warning": "optional warning",
            "verification": "how to verify step completed"
        }}
    ],
    "estimated_time": "5 minutes",
    "risk_level": "low|medium|high",
    "rollback_available": true/false
}}"""
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                    timeout=60.0,
                )
                
                if response.status_code == 200:
                    result = response.json()
                    text = result.get("response", "")
                    
                    import re
                    match = re.search(r'\{[\s\S]*\}', text)
                    if match:
                        data = json.loads(match.group())
                        return data.get("steps", [])
                        
        except Exception as e:
            logger.error(f"Walkthrough generation failed: {e}")
        
        return []
    
    # =========================================================================
    # UTILITIES
    # =========================================================================
    
    def _generate_id(self) -> str:
        """Generate unique ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def on_threat(self, callback):
        self._on_threat.append(callback)
    
    def on_action(self, callback):
        self._on_action.append(callback)
    
    def on_approval_needed(self, callback):
        self._on_approval_needed.append(callback)
    
    def get_pending_approvals(self) -> list[dict]:
        """Get actions pending approval."""
        return [
            {
                "id": self.actions[aid].id,
                "threat_id": self.actions[aid].threat_id,
                "action": self.actions[aid].action_type.value,
                "target": self.actions[aid].target,
                "threat_title": self.threats.get(self.actions[aid].threat_id, {}).title
                    if self.actions[aid].threat_id in self.threats else "Unknown",
            }
            for aid in self.pending_approvals
            if aid in self.actions
        ]
    
    def get_integrity_report(self) -> list[dict]:
        """Get integrity check report."""
        return [
            {
                "check_id": c.check_id,
                "timestamp": c.timestamp,
                "target": c.target[:100],
                "original": c.original_verdict,
                "verification": c.verification_verdict,
                "confirmed": c.is_confirmed,
                "notes": c.discrepancy_notes,
            }
            for c in self.integrity_checks[-50:]
        ]
