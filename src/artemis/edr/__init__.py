"""EDR (Endpoint Detection & Response) module for Project Artemis.

This module provides:
- Sysmon log ingestion and parsing
- Real-time process monitoring
- Threat intelligence feed integration
- Behavioral analysis and anomaly detection
- Risk scoring and security posture
- Response actions (kill, quarantine, block)
- Timeline and threat hunting
"""

from .sysmon import SysmonParser, SysmonEvent, EventType
from .process_monitor import ProcessMonitor, ProcessEvent
from .threat_intel import ThreatIntelFeed, IoC, IoCType
from .risk_score import RiskScorer, SecurityPosture, get_mitre_coverage, MITRE_TECHNIQUES, MITRE_TACTICS
from .response import ResponseEngine, ResponseAction, ActionType, ActionStatus
from .timeline import TimelineEngine, TimelineEvent, ProcessNode

__all__ = [
    # Sysmon
    "SysmonParser",
    "SysmonEvent", 
    "EventType",
    # Process Monitor
    "ProcessMonitor",
    "ProcessEvent",
    # Threat Intel
    "ThreatIntelFeed",
    "IoC",
    "IoCType",
    # Risk Score
    "RiskScorer",
    "SecurityPosture",
    "get_mitre_coverage",
    "MITRE_TECHNIQUES",
    "MITRE_TACTICS",
    # Response
    "ResponseEngine",
    "ResponseAction",
    "ActionType",
    "ActionStatus",
    # Timeline
    "TimelineEngine",
    "TimelineEvent",
    "ProcessNode",
]
