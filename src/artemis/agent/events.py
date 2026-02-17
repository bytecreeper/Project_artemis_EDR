# Artemis Agent - Event Models
"""Normalized event structures for cross-source compatibility."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class EventSource(Enum):
    """Supported event sources."""
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSTEM = "windows_system"
    WINDOWS_POWERSHELL = "windows_powershell"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_DEFENDER = "windows_defender"
    SYSLOG = "syslog"
    CUSTOM = "custom"


class EventSeverity(Enum):
    """Event severity levels."""
    DEBUG = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class NormalizedEvent:
    """
    Normalized event structure that works across all sources.
    This is what gets sent to the AI for analysis.
    """
    # Core identification
    event_id: str
    timestamp: datetime
    source: EventSource
    
    # Event details
    event_code: int | str
    event_type: str
    message: str
    
    # Context
    hostname: str = ""
    username: str = ""
    process_name: str = ""
    process_id: int | None = None
    parent_process: str = ""
    command_line: str = ""
    
    # Network context
    source_ip: str = ""
    dest_ip: str = ""
    source_port: int | None = None
    dest_port: int | None = None
    
    # File context
    file_path: str = ""
    file_hash: str = ""
    
    # Raw data for reference
    raw_data: dict[str, Any] = field(default_factory=dict)
    
    # Analysis metadata (filled by analyzer)
    severity: EventSeverity = EventSeverity.INFO
    tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source.value,
            "event_code": self.event_code,
            "event_type": self.event_type,
            "message": self.message,
            "hostname": self.hostname,
            "username": self.username,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process": self.parent_process,
            "command_line": self.command_line,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "severity": self.severity.name,
            "tags": self.tags,
        }
    
    def summary(self) -> str:
        """One-line summary for logging."""
        parts = [f"[{self.source.value}]", f"EventID:{self.event_code}"]
        if self.username:
            parts.append(f"User:{self.username}")
        if self.process_name:
            parts.append(f"Process:{self.process_name}")
        if self.command_line:
            cmd_preview = self.command_line[:50] + "..." if len(self.command_line) > 50 else self.command_line
            parts.append(f"Cmd:{cmd_preview}")
        return " ".join(parts)


@dataclass
class ThreatAssessment:
    """
    AI-generated threat assessment for an event or event batch.
    """
    # Identification
    assessment_id: str
    timestamp: datetime
    
    # Events that triggered this assessment
    event_ids: list[str]
    
    # Threat classification
    is_threat: bool
    confidence: float  # 0.0 to 1.0
    severity: EventSeverity
    
    # Details
    threat_type: str  # e.g., "credential_theft", "lateral_movement", "c2_beacon"
    description: str
    
    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    # Recommended actions
    recommended_actions: list[str] = field(default_factory=list)
    
    # Auto-action eligibility
    auto_action_eligible: bool = False
    requires_approval: bool = True
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp.isoformat(),
            "event_ids": self.event_ids,
            "is_threat": self.is_threat,
            "confidence": self.confidence,
            "severity": self.severity.name,
            "threat_type": self.threat_type,
            "description": self.description,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "auto_action_eligible": self.auto_action_eligible,
            "requires_approval": self.requires_approval,
        }
