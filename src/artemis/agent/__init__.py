# Artemis Agent - Autonomous Detection & Response
"""
The Artemis Agent continuously monitors system events,
analyzes them with AI, and takes defensive actions.
"""

from .events import EventSource, EventSeverity, NormalizedEvent, ThreatAssessment
from .monitor import EventMonitor
from .analyzer import ThreatAnalyzer
from .responder import ActionResponder, ActionType, ActionStatus, DefensiveAction
from .daemon import ArtemisDaemon
from .network import (
    NetworkScanner,
    NetworkDevice,
    DeviceCategory,
    DeviceStatus,
)
from .discovery import (
    EnhancedNetworkDiscovery,
    DiscoveredDevice,
    DeviceType,
)
from .traffic import (
    TrafficMonitor,
    NetworkFlow,
    DeviceTraffic,
    is_admin,
    require_admin,
)
from .endpoint import (
    EndpointMonitor,
    EndpointEvent,
    ProcessInfo,
    EventType,
)

__all__ = [
    # Events
    "EventSource",
    "EventSeverity", 
    "NormalizedEvent",
    "ThreatAssessment",
    # Monitor
    "EventMonitor",
    # Analyzer
    "ThreatAnalyzer",
    # Responder
    "ActionResponder",
    "ActionType",
    "ActionStatus",
    "DefensiveAction",
    # Daemon
    "ArtemisDaemon",
    # Network (basic)
    "NetworkScanner",
    "NetworkDevice",
    "DeviceCategory",
    "DeviceStatus",
    # Discovery (enhanced)
    "EnhancedNetworkDiscovery",
    "DiscoveredDevice",
    "DeviceType",
    # Traffic
    "TrafficMonitor",
    "NetworkFlow",
    "DeviceTraffic",
    "is_admin",
    "require_admin",
    # Endpoint
    "EndpointMonitor",
    "EndpointEvent",
    "ProcessInfo",
    "EventType",
]
