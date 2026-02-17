"""Sysmon log ingestion and parsing for Project Artemis.

Sysmon Event IDs:
- 1: Process Create
- 2: File creation time changed
- 3: Network connection
- 4: Sysmon service state changed
- 5: Process terminated
- 6: Driver loaded
- 7: Image loaded (DLL)
- 8: CreateRemoteThread
- 9: RawAccessRead
- 10: ProcessAccess
- 11: FileCreate
- 12: RegistryEvent (Object create/delete)
- 13: RegistryEvent (Value Set)
- 14: RegistryEvent (Key/Value Rename)
- 15: FileCreateStreamHash
- 16: Sysmon config state changed
- 17: PipeEvent (Pipe Created)
- 18: PipeEvent (Pipe Connected)
- 19: WmiEvent (WmiEventFilter)
- 20: WmiEvent (WmiEventConsumer)
- 21: WmiEvent (WmiEventConsumerToFilter)
- 22: DNSEvent (DNS query)
- 23: FileDelete (archived)
- 24: ClipboardChange
- 25: ProcessTampering
- 26: FileDeleteDetected
- 27: FileBlockExecutable
- 28: FileBlockShredding
- 29: FileExecutableDetected
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Optional
import asyncio

logger = logging.getLogger("artemis.edr.sysmon")


class EventType(IntEnum):
    """Sysmon event type IDs."""
    PROCESS_CREATE = 1
    FILE_TIME_CHANGE = 2
    NETWORK_CONNECT = 3
    SERVICE_STATE = 4
    PROCESS_TERMINATE = 5
    DRIVER_LOAD = 6
    IMAGE_LOAD = 7
    CREATE_REMOTE_THREAD = 8
    RAW_ACCESS_READ = 9
    PROCESS_ACCESS = 10
    FILE_CREATE = 11
    REGISTRY_CREATE_DELETE = 12
    REGISTRY_VALUE_SET = 13
    REGISTRY_RENAME = 14
    FILE_STREAM_HASH = 15
    CONFIG_CHANGE = 16
    PIPE_CREATE = 17
    PIPE_CONNECT = 18
    WMI_FILTER = 19
    WMI_CONSUMER = 20
    WMI_BINDING = 21
    DNS_QUERY = 22
    FILE_DELETE_ARCHIVED = 23
    CLIPBOARD_CHANGE = 24
    PROCESS_TAMPERING = 25
    FILE_DELETE_DETECTED = 26
    FILE_BLOCK_EXECUTABLE = 27
    FILE_BLOCK_SHREDDING = 28
    FILE_EXECUTABLE_DETECTED = 29


# Suspicious patterns for detection
SUSPICIOUS_PROCESSES = {
    # LOLBAS (Living Off The Land Binaries)
    "certutil.exe": "LOLBAS - Certificate utility abuse",
    "mshta.exe": "LOLBAS - HTML Application Host",
    "regsvr32.exe": "LOLBAS - COM registration abuse",
    "rundll32.exe": "LOLBAS - DLL execution",
    "wscript.exe": "LOLBAS - Windows Script Host",
    "cscript.exe": "LOLBAS - Windows Script Host",
    "msiexec.exe": "LOLBAS - MSI installer abuse",
    "wmic.exe": "LOLBAS - WMI command line",
    "powershell.exe": "PowerShell execution",
    "pwsh.exe": "PowerShell Core execution",
    "cmd.exe": "Command prompt",
    "bitsadmin.exe": "LOLBAS - BITS abuse",
    "curl.exe": "File download utility",
    "wget.exe": "File download utility",
    "net.exe": "Network utility",
    "net1.exe": "Network utility",
    "netsh.exe": "Network configuration",
    "schtasks.exe": "Scheduled task creation",
    "at.exe": "Task scheduling",
    "reg.exe": "Registry manipulation",
    "sc.exe": "Service control",
    "taskkill.exe": "Process termination",
    "vssadmin.exe": "Volume shadow copy (ransomware indicator)",
    "bcdedit.exe": "Boot configuration (ransomware indicator)",
    "wbadmin.exe": "Backup deletion (ransomware indicator)",
}

SUSPICIOUS_PARENT_CHILD = {
    # Parent -> Child patterns that are suspicious
    ("winword.exe", "powershell.exe"): "Office spawning PowerShell",
    ("winword.exe", "cmd.exe"): "Office spawning cmd",
    ("winword.exe", "wscript.exe"): "Office spawning script",
    ("excel.exe", "powershell.exe"): "Excel spawning PowerShell",
    ("excel.exe", "cmd.exe"): "Excel spawning cmd",
    ("outlook.exe", "powershell.exe"): "Outlook spawning PowerShell",
    ("outlook.exe", "cmd.exe"): "Outlook spawning cmd",
    ("explorer.exe", "mshta.exe"): "Explorer spawning HTA",
    ("services.exe", "cmd.exe"): "Services spawning cmd (persistence)",
    ("wmiprvse.exe", "powershell.exe"): "WMI spawning PowerShell",
    ("wmiprvse.exe", "cmd.exe"): "WMI spawning cmd",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    (r"-enc\s+[A-Za-z0-9+/=]+", "Base64 encoded PowerShell"),
    (r"-e\s+[A-Za-z0-9+/=]+", "Base64 encoded PowerShell"),
    (r"downloadstring\s*\(", "PowerShell download cradle"),
    (r"invoke-expression", "PowerShell IEX"),
    (r"iex\s*\(", "PowerShell IEX shorthand"),
    (r"bypass\s+executionpolicy", "Execution policy bypass"),
    (r"-nop\s+-w\s+hidden", "Hidden PowerShell"),
    (r"hidden\s+-ep\s+bypass", "Hidden bypass PowerShell"),
    (r"net\s+user\s+\S+\s+\S+\s+/add", "User creation"),
    (r"net\s+localgroup\s+administrators", "Admin group modification"),
    (r"mimikatz", "Mimikatz execution"),
    (r"sekurlsa", "Credential dumping"),
    (r"lsass", "LSASS access"),
    (r"procdump.*lsass", "LSASS dump via procdump"),
    (r"vssadmin.*delete.*shadows", "Shadow copy deletion"),
    (r"wmic.*shadowcopy.*delete", "Shadow copy deletion via WMIC"),
    (r"bcdedit.*/set.*recoveryenabled.*no", "Recovery disabled"),
]


@dataclass
class SysmonEvent:
    """Parsed Sysmon event."""
    event_id: int
    timestamp: datetime
    computer: str
    data: dict[str, Any]
    raw_xml: Optional[str] = None
    
    # Computed fields
    severity: str = "info"
    alerts: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "event_type": EventType(self.event_id).name if self.event_id in EventType._value2member_map_ else "UNKNOWN",
            "timestamp": self.timestamp.isoformat(),
            "computer": self.computer,
            "data": self.data,
            "severity": self.severity,
            "alerts": self.alerts,
            "mitre_techniques": self.mitre_techniques,
        }


class SysmonParser:
    """Parser for Sysmon Windows Event Logs."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the parser.
        
        Args:
            data_dir: Directory to store parsed events and state
        """
        self.data_dir = data_dir or Path("data/sysmon")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.events_file = self.data_dir / "events.jsonl"
        self.alerts_file = self.data_dir / "alerts.jsonl"
        self.state_file = self.data_dir / "state.json"
        
        # Callbacks for real-time alerting
        self._alert_callbacks: list[Callable[[SysmonEvent], None]] = []
        
        # Statistics
        self.stats = {
            "total_events": 0,
            "events_by_type": {},
            "alerts_generated": 0,
            "last_event_time": None,
        }
        
        self._load_state()
    
    def _load_state(self):
        """Load parser state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    self.stats = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
    
    def _save_state(self):
        """Save parser state to disk."""
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.stats, f)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
    
    def on_alert(self, callback: Callable[[SysmonEvent], None]):
        """Register a callback for alerts."""
        self._alert_callbacks.append(callback)
    
    def parse_xml(self, xml_string: str) -> Optional[SysmonEvent]:
        """Parse a Sysmon event from XML.
        
        Args:
            xml_string: Raw XML event from Windows Event Log
            
        Returns:
            Parsed SysmonEvent or None if parsing fails
        """
        try:
            # Handle namespace
            xml_string = re.sub(r'\sxmlns="[^"]+"', '', xml_string)
            root = ET.fromstring(xml_string)
            
            # Extract system info
            system = root.find(".//System")
            if system is None:
                return None
            
            event_id = int(system.find("EventID").text)
            time_created = system.find("TimeCreated")
            timestamp_str = time_created.get("SystemTime") if time_created is not None else None
            computer = system.find("Computer")
            computer_name = computer.text if computer is not None else "unknown"
            
            # Parse timestamp
            if timestamp_str:
                # Handle ISO format with varying precision
                timestamp_str = re.sub(r'(\.\d{6})\d*', r'\1', timestamp_str)
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now()
            
            # Extract event data
            data = {}
            event_data = root.find(".//EventData")
            if event_data is not None:
                for elem in event_data:
                    name = elem.get("Name", "")
                    data[name] = elem.text or ""
            
            # Create event
            event = SysmonEvent(
                event_id=event_id,
                timestamp=timestamp,
                computer=computer_name,
                data=data,
                raw_xml=xml_string,
            )
            
            # Analyze for threats
            self._analyze_event(event)
            
            # Update stats
            self.stats["total_events"] += 1
            event_type = str(event_id)
            self.stats["events_by_type"][event_type] = self.stats["events_by_type"].get(event_type, 0) + 1
            self.stats["last_event_time"] = timestamp.isoformat()
            
            # Store event
            self._store_event(event)
            
            # Trigger alerts if needed
            if event.alerts:
                self.stats["alerts_generated"] += 1
                self._store_alert(event)
                for callback in self._alert_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Alert callback failed: {e}")
            
            return event
            
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            return None
        except Exception as e:
            logger.error(f"Event parse error: {e}")
            return None
    
    def parse_json(self, json_data: dict) -> Optional[SysmonEvent]:
        """Parse a Sysmon event from JSON format.
        
        Args:
            json_data: Event data as dictionary
            
        Returns:
            Parsed SysmonEvent or None if parsing fails
        """
        try:
            event_id = json_data.get("EventID") or json_data.get("event_id")
            timestamp_str = json_data.get("TimeCreated") or json_data.get("timestamp")
            computer = json_data.get("Computer") or json_data.get("computer", "unknown")
            
            if not event_id:
                return None
            
            # Parse timestamp
            if isinstance(timestamp_str, str):
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now()
            
            # Get event data
            data = json_data.get("EventData") or json_data.get("data", {})
            
            event = SysmonEvent(
                event_id=int(event_id),
                timestamp=timestamp,
                computer=computer,
                data=data,
            )
            
            self._analyze_event(event)
            
            # Update stats
            self.stats["total_events"] += 1
            event_type = str(event_id)
            self.stats["events_by_type"][event_type] = self.stats["events_by_type"].get(event_type, 0) + 1
            self.stats["last_event_time"] = timestamp.isoformat()
            
            self._store_event(event)
            
            if event.alerts:
                self.stats["alerts_generated"] += 1
                self._store_alert(event)
                for callback in self._alert_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Alert callback failed: {e}")
            
            return event
            
        except Exception as e:
            logger.error(f"JSON parse error: {e}")
            return None
    
    def _analyze_event(self, event: SysmonEvent):
        """Analyze an event for suspicious activity."""
        
        if event.event_id == EventType.PROCESS_CREATE:
            self._analyze_process_create(event)
        elif event.event_id == EventType.NETWORK_CONNECT:
            self._analyze_network_connect(event)
        elif event.event_id == EventType.CREATE_REMOTE_THREAD:
            self._analyze_remote_thread(event)
        elif event.event_id == EventType.PROCESS_ACCESS:
            self._analyze_process_access(event)
        elif event.event_id == EventType.DNS_QUERY:
            self._analyze_dns_query(event)
        elif event.event_id == EventType.FILE_CREATE:
            self._analyze_file_create(event)
        elif event.event_id in (EventType.REGISTRY_CREATE_DELETE, EventType.REGISTRY_VALUE_SET):
            self._analyze_registry(event)
    
    def _analyze_process_create(self, event: SysmonEvent):
        """Analyze process creation events."""
        image = event.data.get("Image", "").lower()
        parent_image = event.data.get("ParentImage", "").lower()
        command_line = event.data.get("CommandLine", "").lower()
        
        # Extract just filenames
        image_name = Path(image).name if image else ""
        parent_name = Path(parent_image).name if parent_image else ""
        
        # Check for suspicious processes
        if image_name in SUSPICIOUS_PROCESSES:
            event.alerts.append(SUSPICIOUS_PROCESSES[image_name])
            event.severity = "medium"
        
        # Check parent-child relationships
        parent_child = (parent_name, image_name)
        if parent_child in SUSPICIOUS_PARENT_CHILD:
            event.alerts.append(SUSPICIOUS_PARENT_CHILD[parent_child])
            event.severity = "high"
            event.mitre_techniques.append("T1059")  # Command and Scripting Interpreter
        
        # Check command line patterns
        for pattern, description in SUSPICIOUS_COMMAND_PATTERNS:
            if re.search(pattern, command_line, re.IGNORECASE):
                event.alerts.append(description)
                event.severity = "high"
        
        # Specific high-severity checks
        if "mimikatz" in command_line or "sekurlsa" in command_line:
            event.severity = "critical"
            event.mitre_techniques.append("T1003")  # Credential Dumping
        
        if "vssadmin" in image_name and "delete" in command_line and "shadows" in command_line:
            event.severity = "critical"
            event.mitre_techniques.append("T1490")  # Inhibit System Recovery
    
    def _analyze_network_connect(self, event: SysmonEvent):
        """Analyze network connection events."""
        dest_ip = event.data.get("DestinationIp", "")
        dest_port = event.data.get("DestinationPort", "")
        image = event.data.get("Image", "").lower()
        
        # Suspicious ports
        suspicious_ports = {"4444", "5555", "1234", "31337", "6666", "6667", "8080", "9001"}
        if dest_port in suspicious_ports:
            event.alerts.append(f"Connection to suspicious port {dest_port}")
            event.severity = "medium"
            event.mitre_techniques.append("T1571")  # Non-Standard Port
        
        # PowerShell/cmd making outbound connections
        if "powershell" in image or "cmd.exe" in image:
            event.alerts.append("Shell process making network connection")
            event.severity = "medium"
            event.mitre_techniques.append("T1059")
        
        # Office apps making connections
        office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
        if any(app in image for app in office_apps):
            # This could be legitimate, but worth logging
            event.alerts.append("Office application network activity")
            event.severity = "low"
    
    def _analyze_remote_thread(self, event: SysmonEvent):
        """Analyze CreateRemoteThread events - often indicates injection."""
        source = event.data.get("SourceImage", "")
        target = event.data.get("TargetImage", "")
        
        event.alerts.append(f"Remote thread created: {Path(source).name} -> {Path(target).name}")
        event.severity = "high"
        event.mitre_techniques.append("T1055")  # Process Injection
    
    def _analyze_process_access(self, event: SysmonEvent):
        """Analyze process access events."""
        target = event.data.get("TargetImage", "").lower()
        source = event.data.get("SourceImage", "").lower()
        access = event.data.get("GrantedAccess", "")
        
        # LSASS access is always suspicious
        if "lsass.exe" in target:
            event.alerts.append(f"LSASS access from {Path(source).name}")
            event.severity = "critical"
            event.mitre_techniques.append("T1003")  # Credential Dumping
        
        # Check for memory read access to sensitive processes
        sensitive = ["lsass.exe", "winlogon.exe", "csrss.exe"]
        if any(proc in target for proc in sensitive):
            if "0x1010" in access or "0x1410" in access:  # Read memory access
                event.alerts.append(f"Memory read access to {Path(target).name}")
                event.severity = "high"
    
    def _analyze_dns_query(self, event: SysmonEvent):
        """Analyze DNS query events."""
        query = event.data.get("QueryName", "").lower()
        
        # Check for DGA-like patterns (high entropy, long random-looking domains)
        parts = query.split(".")
        if len(parts) >= 2:
            domain = parts[-2]
            # Simple entropy check - lots of numbers and consonants
            if len(domain) > 15 and sum(c.isdigit() for c in domain) > 3:
                event.alerts.append(f"Possible DGA domain: {query}")
                event.severity = "medium"
                event.mitre_techniques.append("T1568.002")  # DGA
        
        # Known suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"]
        if any(query.endswith(tld) for tld in suspicious_tlds):
            event.alerts.append(f"Query to suspicious TLD: {query}")
            event.severity = "low"
    
    def _analyze_file_create(self, event: SysmonEvent):
        """Analyze file creation events."""
        target = event.data.get("TargetFilename", "").lower()
        
        # Suspicious locations
        suspicious_paths = [
            r"\appdata\local\temp",
            r"\windows\temp",
            r"\programdata",
            r"\users\public",
        ]
        
        suspicious_extensions = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"]
        
        for path in suspicious_paths:
            if path in target:
                ext = Path(target).suffix.lower()
                if ext in suspicious_extensions:
                    event.alerts.append(f"Executable created in suspicious location: {target}")
                    event.severity = "medium"
                    event.mitre_techniques.append("T1105")  # Ingress Tool Transfer
                    break
    
    def _analyze_registry(self, event: SysmonEvent):
        """Analyze registry events for persistence."""
        target = event.data.get("TargetObject", "").lower()
        
        # Common persistence locations
        persistence_keys = [
            r"software\microsoft\windows\currentversion\run",
            r"software\microsoft\windows\currentversion\runonce",
            r"software\microsoft\windows nt\currentversion\winlogon",
            r"software\microsoft\windows\currentversion\policies\explorer\run",
            r"system\currentcontrolset\services",
        ]
        
        for key in persistence_keys:
            if key in target:
                event.alerts.append(f"Registry persistence: {target}")
                event.severity = "high"
                event.mitre_techniques.append("T1547")  # Boot/Logon Autostart Execution
                break
    
    def _store_event(self, event: SysmonEvent):
        """Store event to JSONL file."""
        try:
            with open(self.events_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
    
    def _store_alert(self, event: SysmonEvent):
        """Store alert to separate file."""
        try:
            with open(self.alerts_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to store alert: {e}")
    
    def get_recent_events(self, limit: int = 100, event_type: Optional[int] = None) -> list[dict]:
        """Get recent events from storage."""
        events = []
        try:
            if self.events_file.exists():
                with open(self.events_file) as f:
                    lines = f.readlines()
                    for line in reversed(lines[-limit * 2:]):  # Read extra in case of filtering
                        try:
                            event = json.loads(line)
                            if event_type is None or event["event_id"] == event_type:
                                events.append(event)
                                if len(events) >= limit:
                                    break
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Failed to read events: {e}")
        return events
    
    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent alerts from storage."""
        alerts = []
        try:
            if self.alerts_file.exists():
                with open(self.alerts_file) as f:
                    lines = f.readlines()
                    for line in reversed(lines[-limit:]):
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Failed to read alerts: {e}")
        return alerts
    
    def get_stats(self) -> dict:
        """Get parser statistics."""
        return self.stats.copy()
    
    def clear_data(self):
        """Clear all stored events and alerts."""
        if self.events_file.exists():
            self.events_file.unlink()
        if self.alerts_file.exists():
            self.alerts_file.unlink()
        self.stats = {
            "total_events": 0,
            "events_by_type": {},
            "alerts_generated": 0,
            "last_event_time": None,
        }
        self._save_state()
