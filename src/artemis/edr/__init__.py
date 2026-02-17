"""EDR (Endpoint Detection & Response) module for Project Artemis.

This module provides:
- Sysmon log ingestion and parsing
- Real-time process monitoring
- Threat intelligence feed integration
- Behavioral analysis and anomaly detection
"""

from .sysmon import SysmonParser, SysmonEvent, EventType
from .process_monitor import ProcessMonitor, ProcessEvent
from .threat_intel import ThreatIntelFeed, IoC, IoCType

__all__ = [
    "SysmonParser",
    "SysmonEvent", 
    "EventType",
    "ProcessMonitor",
    "ProcessEvent",
    "ThreatIntelFeed",
    "IoC",
    "IoCType",
]
