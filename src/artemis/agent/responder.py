# Artemis Agent - Action Responder
"""
Takes defensive actions based on threat assessments.
Supports alerts, rule generation, blocking, and more.
"""

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .events import EventSeverity, ThreatAssessment

logger = logging.getLogger("artemis.agent.responder")


class ActionType(Enum):
    """Types of defensive actions."""
    LOG = "log"
    ALERT = "alert"
    NOTIFY = "notify"  # Desktop notification
    GENERATE_RULE = "generate_rule"
    BLOCK_IP = "block_ip"
    BLOCK_PROCESS = "block_process"
    KILL_PROCESS = "kill_process"
    ISOLATE_NETWORK = "isolate_network"
    QUARANTINE_FILE = "quarantine_file"
    CUSTOM = "custom"


class ActionStatus(Enum):
    """Status of an action."""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"


@dataclass
class DefensiveAction:
    """A defensive action to be taken."""
    action_id: str
    action_type: ActionType
    assessment_id: str
    
    # Action details
    description: str
    target: str  # IP, process name, file path, etc.
    parameters: dict[str, Any] = field(default_factory=dict)
    
    # Status tracking
    status: ActionStatus = ActionStatus.PENDING
    requires_approval: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    executed_at: datetime | None = None
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "assessment_id": self.assessment_id,
            "description": self.description,
            "target": self.target,
            "parameters": self.parameters,
            "status": self.status.value,
            "requires_approval": self.requires_approval,
            "created_at": self.created_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "error": self.error,
        }


class ActionResponder:
    """
    Executes defensive actions based on threat assessments.
    Some actions require approval, others can be auto-executed.
    """
    
    def __init__(
        self,
        log_dir: Path | None = None,
        rules_dir: Path | None = None,
        auto_actions: bool = False,
        notify_enabled: bool = True,
    ):
        """
        Initialize the action responder.
        
        Args:
            log_dir: Directory for threat logs
            rules_dir: Directory for generated rules
            auto_actions: Allow automatic execution without approval
            notify_enabled: Enable desktop notifications
        """
        self.log_dir = log_dir or Path.home() / ".artemis" / "logs"
        self.rules_dir = rules_dir or Path.home() / ".artemis" / "rules"
        self.auto_actions = auto_actions
        self.notify_enabled = notify_enabled
        
        # Ensure directories exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Action queue (for approval workflow)
        self._pending_actions: dict[str, DefensiveAction] = {}
        self._action_history: list[DefensiveAction] = []
        
        # Action handlers
        self._handlers = {
            ActionType.LOG: self._handle_log,
            ActionType.ALERT: self._handle_alert,
            ActionType.NOTIFY: self._handle_notify,
            ActionType.GENERATE_RULE: self._handle_generate_rule,
            ActionType.BLOCK_IP: self._handle_block_ip,
            ActionType.KILL_PROCESS: self._handle_kill_process,
        }
        
    async def respond(self, assessment: ThreatAssessment) -> list[DefensiveAction]:
        """
        Determine and queue appropriate actions for a threat assessment.
        
        Args:
            assessment: The threat assessment to respond to
            
        Returns:
            List of actions (pending or executed)
        """
        actions: list[DefensiveAction] = []
        
        # Always log threats
        if assessment.is_threat:
            actions.append(await self._create_action(
                ActionType.LOG,
                assessment,
                description=f"Log threat: {assessment.threat_type}",
                target="threat_log",
                requires_approval=False,
            ))
            
        # Determine response based on severity
        if assessment.severity == EventSeverity.CRITICAL:
            actions.extend(await self._respond_critical(assessment))
        elif assessment.severity == EventSeverity.HIGH:
            actions.extend(await self._respond_high(assessment))
        elif assessment.severity == EventSeverity.MEDIUM:
            actions.extend(await self._respond_medium(assessment))
        elif assessment.severity == EventSeverity.LOW:
            actions.extend(await self._respond_low(assessment))
            
        # Execute auto-approved actions
        for action in actions:
            if not action.requires_approval or (self.auto_actions and assessment.auto_action_eligible):
                await self.execute_action(action)
            else:
                self._pending_actions[action.action_id] = action
                
        return actions
        
    async def _respond_critical(self, assessment: ThreatAssessment) -> list[DefensiveAction]:
        """Response actions for CRITICAL threats."""
        actions = []
        
        # Desktop notification (urgent)
        if self.notify_enabled:
            actions.append(await self._create_action(
                ActionType.NOTIFY,
                assessment,
                description=f"CRITICAL THREAT: {assessment.threat_type}",
                target="desktop",
                requires_approval=False,
                parameters={"urgent": True},
            ))
            
        # Generate detection rule
        actions.append(await self._create_action(
            ActionType.GENERATE_RULE,
            assessment,
            description=f"Generate detection rule for {assessment.threat_type}",
            target=assessment.threat_type,
            requires_approval=False,
        ))
        
        # Recommend process kill if applicable
        for action in assessment.recommended_actions:
            if "kill" in action.lower() or "terminate" in action.lower():
                actions.append(await self._create_action(
                    ActionType.KILL_PROCESS,
                    assessment,
                    description=f"Kill suspicious process",
                    target=self._extract_process_target(assessment),
                    requires_approval=True,  # Always require approval for kills
                ))
                break
                
        return actions
        
    async def _respond_high(self, assessment: ThreatAssessment) -> list[DefensiveAction]:
        """Response actions for HIGH severity threats."""
        actions = []
        
        # Desktop notification
        if self.notify_enabled:
            actions.append(await self._create_action(
                ActionType.NOTIFY,
                assessment,
                description=f"HIGH THREAT: {assessment.threat_type}",
                target="desktop",
                requires_approval=False,
            ))
            
        # Generate detection rule
        actions.append(await self._create_action(
            ActionType.GENERATE_RULE,
            assessment,
            description=f"Generate detection rule for {assessment.threat_type}",
            target=assessment.threat_type,
            requires_approval=False,
        ))
        
        # Block IP if network-related
        if any(t in assessment.mitre_tactics for t in ["Command and Control", "Exfiltration"]):
            actions.append(await self._create_action(
                ActionType.BLOCK_IP,
                assessment,
                description=f"Block suspicious IP address",
                target=self._extract_ip_target(assessment),
                requires_approval=True,
            ))
            
        return actions
        
    async def _respond_medium(self, assessment: ThreatAssessment) -> list[DefensiveAction]:
        """Response actions for MEDIUM severity threats."""
        actions = []
        
        # Alert (logged prominently)
        actions.append(await self._create_action(
            ActionType.ALERT,
            assessment,
            description=f"Alert: {assessment.threat_type}",
            target="alert_log",
            requires_approval=False,
        ))
        
        # Optional notification
        if self.notify_enabled:
            actions.append(await self._create_action(
                ActionType.NOTIFY,
                assessment,
                description=f"Suspicious activity: {assessment.threat_type}",
                target="desktop",
                requires_approval=False,
                parameters={"urgent": False},
            ))
            
        return actions
        
    async def _respond_low(self, assessment: ThreatAssessment) -> list[DefensiveAction]:
        """Response actions for LOW severity threats."""
        # Just log, no active response
        return []
        
    async def _create_action(
        self,
        action_type: ActionType,
        assessment: ThreatAssessment,
        description: str,
        target: str,
        requires_approval: bool = True,
        parameters: dict | None = None,
    ) -> DefensiveAction:
        """Create a defensive action."""
        import uuid
        
        return DefensiveAction(
            action_id=str(uuid.uuid4()),
            action_type=action_type,
            assessment_id=assessment.assessment_id,
            description=description,
            target=target,
            parameters=parameters or {},
            requires_approval=requires_approval,
        )
        
    async def execute_action(self, action: DefensiveAction) -> bool:
        """
        Execute a defensive action.
        
        Args:
            action: The action to execute
            
        Returns:
            True if successful, False otherwise
        """
        handler = self._handlers.get(action.action_type)
        if not handler:
            logger.warning(f"No handler for action type: {action.action_type}")
            action.status = ActionStatus.FAILED
            action.error = "No handler available"
            return False
            
        try:
            await handler(action)
            action.status = ActionStatus.EXECUTED
            action.executed_at = datetime.now(timezone.utc)
            self._action_history.append(action)
            
            # Remove from pending
            self._pending_actions.pop(action.action_id, None)
            
            logger.info(f"Executed action: {action.action_type.value} -> {action.target}")
            return True
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
            logger.error(f"Action failed: {action.action_type.value} - {e}")
            return False
            
    async def approve_action(self, action_id: str) -> bool:
        """Approve and execute a pending action."""
        action = self._pending_actions.get(action_id)
        if not action:
            return False
            
        action.status = ActionStatus.APPROVED
        return await self.execute_action(action)
        
    async def reject_action(self, action_id: str) -> bool:
        """Reject a pending action."""
        action = self._pending_actions.pop(action_id, None)
        if action:
            action.status = ActionStatus.REJECTED
            self._action_history.append(action)
            return True
        return False
        
    # Action handlers
    
    async def _handle_log(self, action: DefensiveAction) -> None:
        """Log threat to file."""
        log_file = self.log_dir / f"threats_{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assessment_id": action.assessment_id,
            "action": action.to_dict(),
        }
        
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
            
    async def _handle_alert(self, action: DefensiveAction) -> None:
        """Log alert prominently."""
        alert_file = self.log_dir / "alerts.jsonl"
        
        alert_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assessment_id": action.assessment_id,
            "description": action.description,
            "severity": action.parameters.get("severity", "MEDIUM"),
        }
        
        with open(alert_file, "a") as f:
            f.write(json.dumps(alert_entry) + "\n")
            
    async def _handle_notify(self, action: DefensiveAction) -> None:
        """Send desktop notification."""
        try:
            # Try Windows toast notification
            if self._is_windows():
                await self._windows_notify(
                    title="Artemis Security Alert",
                    message=action.description,
                    urgent=action.parameters.get("urgent", False),
                )
            else:
                # Fallback to terminal bell
                print(f"\a[ARTEMIS ALERT] {action.description}")
                
        except Exception as e:
            logger.debug(f"Notification failed: {e}")
            
    async def _handle_generate_rule(self, action: DefensiveAction) -> None:
        """Generate a detection rule for this threat."""
        # This integrates with the existing Artemis rule generators
        from ..core import Artemis
        
        rule_file = self.rules_dir / f"{action.target.replace(' ', '_')}_{action.action_id[:8]}.yml"
        
        # For now, log the rule generation request
        # Full integration will call the Artemis rule generators
        rule_request = {
            "threat_type": action.target,
            "assessment_id": action.assessment_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending_generation",
        }
        
        with open(rule_file, "w") as f:
            json.dump(rule_request, f, indent=2)
            
        logger.info(f"Rule generation queued: {rule_file}")
        
    async def _handle_block_ip(self, action: DefensiveAction) -> None:
        """Block an IP address using Windows Firewall."""
        ip = action.target
        if not ip or ip == "unknown":
            raise ValueError("No valid IP to block")
            
        if self._is_windows():
            # Use Windows Firewall
            rule_name = f"Artemis_Block_{ip.replace('.', '_')}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Firewall rule failed: {result.stderr}")
                
            logger.warning(f"Blocked IP: {ip}")
        else:
            raise NotImplementedError("IP blocking only implemented for Windows")
            
    async def _handle_kill_process(self, action: DefensiveAction) -> None:
        """Kill a process by name or PID."""
        target = action.target
        if not target or target == "unknown":
            raise ValueError("No valid process target")
            
        if self._is_windows():
            # Try as PID first
            try:
                pid = int(target)
                cmd = ["taskkill", "/F", "/PID", str(pid)]
            except ValueError:
                # Treat as process name
                cmd = ["taskkill", "/F", "/IM", target]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Process kill failed: {result.stderr}")
                
            logger.warning(f"Killed process: {target}")
        else:
            raise NotImplementedError("Process kill only implemented for Windows")
            
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        import platform
        return platform.system() == "Windows"
        
    async def _windows_notify(self, title: str, message: str, urgent: bool = False) -> None:
        """Send Windows toast notification."""
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message,
                duration=10 if urgent else 5,
                threaded=True,
            )
        except ImportError:
            # Fallback: use PowerShell
            ps_script = f'''
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
            $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
            $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
            $xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("{title}")) | Out-Null
            $xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{message}")) | Out-Null
            $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Artemis").Show($toast)
            '''
            subprocess.run(["powershell", "-Command", ps_script], capture_output=True)
            
    def _extract_process_target(self, assessment: ThreatAssessment) -> str:
        """Extract process target from assessment."""
        # Look in description for process names
        desc = assessment.description.lower()
        common_threats = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32"]
        for proc in common_threats:
            if proc in desc:
                return proc
        return "unknown"
        
    def _extract_ip_target(self, assessment: ThreatAssessment) -> str:
        """Extract IP target from assessment."""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, assessment.description)
        return matches[0] if matches else "unknown"
        
    @property
    def pending_actions(self) -> list[DefensiveAction]:
        """Get all pending actions."""
        return list(self._pending_actions.values())
        
    @property
    def action_history(self) -> list[DefensiveAction]:
        """Get action history."""
        return self._action_history.copy()
        
    @property
    def stats(self) -> dict:
        """Get responder statistics."""
        return {
            "pending_count": len(self._pending_actions),
            "total_executed": len([a for a in self._action_history if a.status == ActionStatus.EXECUTED]),
            "total_failed": len([a for a in self._action_history if a.status == ActionStatus.FAILED]),
            "total_rejected": len([a for a in self._action_history if a.status == ActionStatus.REJECTED]),
        }
