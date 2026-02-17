"""Timeline and event correlation for Project Artemis.

Provides:
- Unified event timeline across all sources
- Process tree reconstruction
- Threat hunting queries
- Event correlation
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from collections import defaultdict

logger = logging.getLogger("artemis.edr.timeline")


@dataclass
class TimelineEvent:
    """A unified timeline event."""
    timestamp: datetime
    event_type: str  # process, network, file, registry, alert
    source: str  # sysmon, process_monitor, threat_intel, etc.
    action: str  # create, terminate, connect, modify, etc.
    
    # Entity info
    subject: str  # What did it (e.g., process name)
    subject_id: Optional[str] = None  # PID, connection ID, etc.
    target: Optional[str] = None  # What was affected
    target_id: Optional[str] = None
    
    # Details
    details: dict = field(default_factory=dict)
    severity: str = "info"
    mitre_techniques: list[str] = field(default_factory=list)
    
    # Correlation
    parent_event_id: Optional[str] = None
    related_events: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source": self.source,
            "action": self.action,
            "subject": self.subject,
            "subject_id": self.subject_id,
            "target": self.target,
            "target_id": self.target_id,
            "details": self.details,
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class ProcessNode:
    """A node in the process tree."""
    pid: int
    name: str
    cmdline: Optional[str] = None
    exe: Optional[str] = None
    username: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    parent_pid: Optional[int] = None
    children: list["ProcessNode"] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    network_connections: list[dict] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "cmdline": self.cmdline,
            "exe": self.exe,
            "username": self.username,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "parent_pid": self.parent_pid,
            "children": [c.to_dict() for c in self.children],
            "alerts": self.alerts,
            "network_connections": self.network_connections,
            "files_created": self.files_created,
            "is_suspicious": len(self.alerts) > 0,
        }


class TimelineEngine:
    """Unified timeline and correlation engine."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("data/timeline")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.events_file = self.data_dir / "events.jsonl"
        
        # In-memory index for recent events
        self._events: list[TimelineEvent] = []
        self._max_memory_events = 10000
        
        # Process tree cache
        self._process_cache: dict[int, ProcessNode] = {}
    
    def add_event(self, event: TimelineEvent):
        """Add an event to the timeline."""
        self._events.append(event)
        
        # Trim if too many in memory
        if len(self._events) > self._max_memory_events:
            self._events = self._events[-self._max_memory_events:]
        
        # Persist
        try:
            with open(self.events_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to persist event: {e}")
    
    def add_sysmon_event(self, sysmon_event: dict):
        """Convert and add a Sysmon event to timeline."""
        event_id = sysmon_event.get("event_id", 0)
        data = sysmon_event.get("data", {})
        
        timestamp = datetime.fromisoformat(
            sysmon_event.get("timestamp", datetime.now().isoformat())
        )
        
        # Map Sysmon event types
        if event_id == 1:  # Process Create
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="process",
                source="sysmon",
                action="create",
                subject=data.get("ParentImage", "").split("\\")[-1],
                subject_id=data.get("ParentProcessId"),
                target=data.get("Image", "").split("\\")[-1],
                target_id=data.get("ProcessId"),
                details={
                    "commandline": data.get("CommandLine"),
                    "user": data.get("User"),
                    "integrity": data.get("IntegrityLevel"),
                    "hashes": data.get("Hashes"),
                },
                severity=sysmon_event.get("severity", "info"),
                mitre_techniques=sysmon_event.get("mitre_techniques", []),
            )
        elif event_id == 3:  # Network Connect
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="network",
                source="sysmon",
                action="connect",
                subject=data.get("Image", "").split("\\")[-1],
                subject_id=data.get("ProcessId"),
                target=f"{data.get('DestinationIp')}:{data.get('DestinationPort')}",
                details={
                    "source_ip": data.get("SourceIp"),
                    "source_port": data.get("SourcePort"),
                    "dest_ip": data.get("DestinationIp"),
                    "dest_port": data.get("DestinationPort"),
                    "protocol": data.get("Protocol"),
                },
                severity=sysmon_event.get("severity", "info"),
                mitre_techniques=sysmon_event.get("mitre_techniques", []),
            )
        elif event_id == 5:  # Process Terminate
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="process",
                source="sysmon",
                action="terminate",
                subject=data.get("Image", "").split("\\")[-1],
                subject_id=data.get("ProcessId"),
            )
        elif event_id == 11:  # File Create
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="file",
                source="sysmon",
                action="create",
                subject=data.get("Image", "").split("\\")[-1],
                subject_id=data.get("ProcessId"),
                target=data.get("TargetFilename"),
                severity=sysmon_event.get("severity", "info"),
                mitre_techniques=sysmon_event.get("mitre_techniques", []),
            )
        elif event_id == 22:  # DNS Query
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="network",
                source="sysmon",
                action="dns_query",
                subject=data.get("Image", "").split("\\")[-1],
                subject_id=data.get("ProcessId"),
                target=data.get("QueryName"),
                details={"query_status": data.get("QueryStatus")},
                severity=sysmon_event.get("severity", "info"),
                mitre_techniques=sysmon_event.get("mitre_techniques", []),
            )
        else:
            event = TimelineEvent(
                timestamp=timestamp,
                event_type="other",
                source="sysmon",
                action=f"event_{event_id}",
                subject=data.get("Image", "unknown").split("\\")[-1],
                details=data,
            )
        
        self.add_event(event)
        return event
    
    def add_process_event(self, proc_event: dict):
        """Convert and add a process monitor event to timeline."""
        timestamp = datetime.fromisoformat(
            proc_event.get("timestamp", datetime.now().isoformat())
        )
        
        event = TimelineEvent(
            timestamp=timestamp,
            event_type="process",
            source="process_monitor",
            action=proc_event.get("event_type", "unknown"),
            subject=proc_event.get("parent_name", "unknown"),
            subject_id=str(proc_event.get("parent_pid")),
            target=proc_event.get("name"),
            target_id=str(proc_event.get("pid")),
            details={
                "cmdline": proc_event.get("cmdline"),
                "exe": proc_event.get("exe"),
                "username": proc_event.get("username"),
            },
            severity=proc_event.get("severity", "info"),
            mitre_techniques=proc_event.get("mitre_techniques", []),
        )
        
        self.add_event(event)
        return event
    
    def get_timeline(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[list[str]] = None,
        severity: Optional[str] = None,
        subject: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query the timeline with filters.
        
        Args:
            start_time: Start of time window
            end_time: End of time window
            event_types: Filter by event types
            severity: Filter by severity
            subject: Filter by subject name (partial match)
            limit: Maximum events to return
            
        Returns:
            List of matching events
        """
        events = self._events.copy()
        
        # Apply filters
        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]
        if event_types:
            events = [e for e in events if e.event_type in event_types]
        if severity:
            events = [e for e in events if e.severity == severity]
        if subject:
            subject_lower = subject.lower()
            events = [e for e in events if subject_lower in e.subject.lower()]
        
        # Sort by timestamp descending
        events.sort(key=lambda e: e.timestamp, reverse=True)
        
        return [e.to_dict() for e in events[:limit]]
    
    def build_process_tree(
        self,
        root_pid: Optional[int] = None,
        time_window_minutes: int = 60,
    ) -> list[ProcessNode]:
        """Build process tree from events.
        
        Args:
            root_pid: Start from this PID (None = all roots)
            time_window_minutes: How far back to look
            
        Returns:
            List of root process nodes
        """
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        
        # Gather process events
        process_events = [
            e for e in self._events
            if e.event_type == "process" and e.timestamp >= cutoff
        ]
        
        # Build nodes
        nodes: dict[int, ProcessNode] = {}
        parent_map: dict[int, int] = {}  # child -> parent
        
        for event in process_events:
            if event.action == "create":
                pid = int(event.target_id) if event.target_id else 0
                parent_pid = int(event.subject_id) if event.subject_id else None
                
                if pid not in nodes:
                    nodes[pid] = ProcessNode(
                        pid=pid,
                        name=event.target or "unknown",
                        cmdline=event.details.get("cmdline"),
                        exe=event.details.get("exe"),
                        username=event.details.get("username") or event.details.get("user"),
                        start_time=event.timestamp,
                        parent_pid=parent_pid,
                    )
                
                if parent_pid:
                    parent_map[pid] = parent_pid
                
                # Add alerts
                if event.severity in ("high", "critical"):
                    nodes[pid].alerts.extend(event.mitre_techniques)
            
            elif event.action == "terminate":
                pid = int(event.subject_id) if event.subject_id else 0
                if pid in nodes:
                    nodes[pid].end_time = event.timestamp
        
        # Add network connections
        for event in self._events:
            if event.event_type == "network" and event.timestamp >= cutoff:
                pid = int(event.subject_id) if event.subject_id else 0
                if pid in nodes:
                    nodes[pid].network_connections.append({
                        "target": event.target,
                        "time": event.timestamp.isoformat(),
                    })
        
        # Build tree structure
        for pid, parent_pid in parent_map.items():
            if parent_pid in nodes and pid in nodes:
                nodes[parent_pid].children.append(nodes[pid])
        
        # Find roots
        roots = []
        for pid, node in nodes.items():
            if node.parent_pid is None or node.parent_pid not in nodes:
                if root_pid is None or pid == root_pid:
                    roots.append(node)
        
        return roots
    
    def hunt(self, query: str, limit: int = 100) -> list[dict]:
        """Execute a threat hunting query.
        
        Supports simple query syntax:
        - field:value - exact match
        - field:*value* - contains
        - field:>value - greater than (for numbers)
        - AND, OR for combining
        
        Examples:
        - "subject:powershell"
        - "action:connect AND target:*445*"
        - "severity:high OR severity:critical"
        
        Args:
            query: Hunt query string
            limit: Maximum results
            
        Returns:
            Matching events
        """
        # Parse query
        conditions = self._parse_hunt_query(query)
        
        if not conditions:
            return []
        
        # Execute
        results = []
        for event in self._events:
            if self._matches_conditions(event, conditions):
                results.append(event.to_dict())
                if len(results) >= limit:
                    break
        
        return results
    
    def _parse_hunt_query(self, query: str) -> list[tuple]:
        """Parse hunt query into conditions."""
        conditions = []
        
        # Split by AND/OR (simplified)
        parts = re.split(r'\s+(?:AND|OR)\s+', query, flags=re.IGNORECASE)
        
        for part in parts:
            part = part.strip()
            if ":" not in part:
                continue
            
            field, value = part.split(":", 1)
            field = field.strip().lower()
            value = value.strip()
            
            # Determine match type
            if value.startswith("*") and value.endswith("*"):
                conditions.append((field, "contains", value[1:-1]))
            elif value.startswith(">"):
                conditions.append((field, "gt", value[1:]))
            elif value.startswith("<"):
                conditions.append((field, "lt", value[1:]))
            else:
                conditions.append((field, "eq", value))
        
        return conditions
    
    def _matches_conditions(self, event: TimelineEvent, conditions: list[tuple]) -> bool:
        """Check if event matches all conditions."""
        for field, op, value in conditions:
            event_value = None
            
            # Get field value
            if hasattr(event, field):
                event_value = getattr(event, field)
            elif field in event.details:
                event_value = event.details[field]
            
            if event_value is None:
                return False
            
            event_value = str(event_value).lower()
            value = value.lower()
            
            # Apply operator
            if op == "eq" and event_value != value:
                return False
            elif op == "contains" and value not in event_value:
                return False
            elif op == "gt":
                try:
                    if float(event_value) <= float(value):
                        return False
                except ValueError:
                    return False
            elif op == "lt":
                try:
                    if float(event_value) >= float(value):
                        return False
                except ValueError:
                    return False
        
        return True
    
    def get_statistics(self, hours: int = 24) -> dict:
        """Get timeline statistics.
        
        Args:
            hours: Time window in hours
            
        Returns:
            Statistics dict
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = [e for e in self._events if e.timestamp >= cutoff]
        
        # Count by type
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_hour = defaultdict(int)
        mitre_hits = defaultdict(int)
        
        for event in recent:
            by_type[event.event_type] += 1
            by_severity[event.severity] += 1
            by_hour[event.timestamp.strftime("%Y-%m-%d %H:00")] += 1
            for tech in event.mitre_techniques:
                mitre_hits[tech] += 1
        
        return {
            "total_events": len(recent),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "by_hour": dict(sorted(by_hour.items())),
            "mitre_techniques": dict(sorted(mitre_hits.items(), key=lambda x: -x[1])[:10]),
            "time_range": {
                "start": cutoff.isoformat(),
                "end": datetime.now().isoformat(),
            },
        }
    
    def clear_old_events(self, days: int = 7):
        """Clear events older than specified days."""
        cutoff = datetime.now() - timedelta(days=days)
        self._events = [e for e in self._events if e.timestamp >= cutoff]
        logger.info(f"Cleared events older than {days} days, {len(self._events)} remaining")
