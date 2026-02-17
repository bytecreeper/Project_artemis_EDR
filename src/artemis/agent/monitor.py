# Artemis Agent - Windows Event Monitor
"""
Real-time Windows Event Log monitoring.
Watches Security, PowerShell, Sysmon, and other critical logs.
"""

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timezone, timedelta
from typing import Any

from .events import EventSource, NormalizedEvent

logger = logging.getLogger("artemis.agent.monitor")

# Windows Event Log channel mappings
MONITORED_CHANNELS = {
    "Security": EventSource.WINDOWS_SECURITY,
    "Microsoft-Windows-PowerShell/Operational": EventSource.WINDOWS_POWERSHELL,
    "Windows PowerShell": EventSource.WINDOWS_POWERSHELL,
    "Microsoft-Windows-Sysmon/Operational": EventSource.WINDOWS_SYSMON,
    "System": EventSource.WINDOWS_SYSTEM,
    "Microsoft-Windows-Windows Defender/Operational": EventSource.WINDOWS_DEFENDER,
}

# High-value event IDs to prioritize
PRIORITY_EVENTS = {
    # Security - Authentication
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Explicit Credential Logon",
    4672: "Special Privileges Assigned",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4756: "Member Added to Universal Group",
    
    # Security - Process/Object
    4688: "Process Creation",
    4689: "Process Termination",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4702: "Scheduled Task Updated",
    
    # Security - Network
    5140: "Network Share Accessed",
    5145: "Network Share Object Accessed",
    5156: "Windows Filtering Platform Connection",
    
    # PowerShell
    4103: "Module Logging",
    4104: "Script Block Logging",
    
    # Sysmon (if installed)
    1: "Process Creation",
    3: "Network Connection",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "Registry Event (Object create/delete)",
    13: "Registry Event (Value Set)",
    22: "DNS Query",
    23: "FileDelete",
}


class EventMonitor:
    """
    Monitors Windows Event Logs in real-time and yields normalized events.
    Uses win32evtlog for efficient Windows API access.
    """
    
    def __init__(
        self,
        channels: list[str] | None = None,
        batch_size: int = 50,
        batch_timeout: float = 5.0,
        priority_only: bool = False,
    ):
        """
        Initialize the event monitor.
        
        Args:
            channels: Event log channels to monitor (default: all supported)
            batch_size: Number of events to batch before yielding
            batch_timeout: Max seconds to wait before yielding partial batch
            priority_only: Only capture high-value event IDs
        """
        self.channels = channels or list(MONITORED_CHANNELS.keys())
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.priority_only = priority_only
        
        self._running = False
        self._event_queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue()
        self._tasks: list[asyncio.Task] = []
        
    async def start(self) -> None:
        """Start monitoring all configured channels."""
        if self._running:
            return
            
        self._running = True
        logger.info(f"Starting event monitor for channels: {self.channels}")
        
        # Start a monitor task for each channel
        for channel in self.channels:
            task = asyncio.create_task(
                self._monitor_channel(channel),
                name=f"monitor_{channel}"
            )
            self._tasks.append(task)
            
    async def stop(self) -> None:
        """Stop all monitoring tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Event monitor stopped")
        
    async def events(self) -> AsyncIterator[list[NormalizedEvent]]:
        """
        Yield batches of normalized events.
        Batches when batch_size is reached or batch_timeout expires.
        """
        batch: list[NormalizedEvent] = []
        last_yield = asyncio.get_event_loop().time()
        
        while self._running:
            try:
                # Wait for event with timeout
                timeout = max(0.1, self.batch_timeout - (asyncio.get_event_loop().time() - last_yield))
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=timeout
                )
                batch.append(event)
                
                # Yield if batch is full
                if len(batch) >= self.batch_size:
                    yield batch
                    batch = []
                    last_yield = asyncio.get_event_loop().time()
                    
            except asyncio.TimeoutError:
                # Yield partial batch on timeout
                if batch:
                    yield batch
                    batch = []
                last_yield = asyncio.get_event_loop().time()
                
    async def _monitor_channel(self, channel: str) -> None:
        """
        Monitor a single event log channel.
        Uses Windows Event Log API via win32evtlog.
        """
        try:
            import win32evtlog
            import win32evtlogutil
        except ImportError:
            logger.error("pywin32 not installed. Run: pip install pywin32")
            return
            
        source = MONITORED_CHANNELS.get(channel, EventSource.CUSTOM)
        logger.info(f"Monitoring channel: {channel}")
        
        # Open the event log
        try:
            # Use EvtSubscribe for real-time monitoring
            # Fall back to polling if subscription fails
            await self._poll_channel(channel, source)
        except Exception as e:
            logger.error(f"Error monitoring {channel}: {e}")
            
    async def _poll_channel(self, channel: str, source: EventSource) -> None:
        """
        Poll event log using PowerShell (most compatible approach).
        """
        # Use PowerShell for all channels - more compatible
        await self._poll_with_powershell(channel, source)
        
    async def _poll_with_powershell(self, channel: str, source: EventSource) -> None:
        """
        Poll event log using PowerShell Get-WinEvent.
        Works across Windows versions without needing specific pywin32 APIs.
        """
        import subprocess
        import json
        
        logger.info(f"Starting PowerShell polling for {channel}")
        
        # Track last event time - use naive local time since PowerShell returns local
        # Strip timezone from comparisons to avoid mixing aware/naive
        last_time = datetime.now() - timedelta(seconds=30)
        
        while self._running:
            try:
                # PowerShell command to get recent events as JSON
                ps_script = f'''
$startTime = [DateTime]::Parse("{last_time.strftime('%Y-%m-%dT%H:%M:%S')}")
try {{
    Get-WinEvent -LogName "{channel}" -MaxEvents 50 -ErrorAction SilentlyContinue | 
    Where-Object {{ $_.TimeCreated -gt $startTime }} |
    ForEach-Object {{
        @{{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id = $_.Id
            LevelDisplayName = $_.LevelDisplayName
            Message = if ($_.Message.Length -gt 500) {{ $_.Message.Substring(0, 500) }} else {{ $_.Message }}
            ProviderName = $_.ProviderName
            MachineName = $_.MachineName
            UserId = if ($_.UserId) {{ $_.UserId.Value }} else {{ $null }}
            ProcessId = $_.ProcessId
            Properties = ($_.Properties | ForEach-Object {{ $_.Value }}) -join "|"
        }}
    }} | ConvertTo-Json -Compress
}} catch {{}}
'''
                
                # Run synchronously in thread pool
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        # Handle single event (not array)
                        if isinstance(data, dict):
                            data = [data]
                        
                        logger.info(f"[{channel}] Got {len(data)} events from PowerShell")
                        
                        for event_data in data:
                            normalized = self._normalize_ps_event(event_data, source)
                            if normalized:
                                # Filter priority events
                                if self.priority_only:
                                    try:
                                        event_id = int(normalized.event_code)
                                        if event_id not in PRIORITY_EVENTS:
                                            continue
                                    except (ValueError, TypeError):
                                        pass
                                
                                await self._event_queue.put(normalized)
                                logger.debug(f"Queued event: {normalized.event_code}")
                                # Update last time (strip timezone for comparison)
                                event_time = normalized.timestamp.replace(tzinfo=None) if normalized.timestamp.tzinfo else normalized.timestamp
                                if event_time > last_time:
                                    last_time = event_time
                                    
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON decode error: {e}")
                        
            except subprocess.TimeoutExpired:
                logger.debug(f"PowerShell timeout for {channel}")
            except Exception as e:
                logger.debug(f"Error polling {channel} via PowerShell: {e}")
                
            await asyncio.sleep(2.0)  # Poll every 2 seconds
            
    def _normalize_ps_event(self, data: dict, source: EventSource) -> NormalizedEvent | None:
        """Normalize a PowerShell Get-WinEvent result."""
        try:
            timestamp_str = data.get("TimeCreated", "")
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now(timezone.utc)
            
            # Parse properties (pipe-separated)
            props = data.get("Properties", "").split("|") if data.get("Properties") else []
            
            # Try to extract common fields from properties
            username = ""
            process_name = ""
            command_line = ""
            
            for prop in props:
                prop_lower = prop.lower() if prop else ""
                if "\\" in prop and not username:
                    username = prop
                elif prop_lower.endswith(".exe") and not process_name:
                    process_name = prop.split("\\")[-1]
                elif len(prop) > 30 and (" " in prop or "-" in prop):
                    if not command_line:
                        command_line = prop
            
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=timestamp,
                source=source,
                event_code=data.get("Id", 0),
                event_type=data.get("LevelDisplayName", "Information"),
                message=data.get("Message", "")[:1000],
                hostname=data.get("MachineName", ""),
                username=username or (data.get("UserId") or ""),
                process_name=process_name,
                process_id=data.get("ProcessId"),
                command_line=command_line,
                raw_data=data,
            )
        except Exception as e:
            logger.debug(f"Error normalizing PS event: {e}")
            return None
            
    async def _poll_modern_channel(self, channel: str, source: EventSource) -> None:
        """
        Poll modern event log channels (like Microsoft-Windows-*).
        Uses EvtQuery API.
        """
        try:
            import win32evtlog
        except ImportError:
            return
            
        # Track last event time
        last_time = datetime.now(timezone.utc)
        
        while self._running:
            try:
                # Query for events since last check
                query = f"*[System[TimeCreated[@SystemTime>='{last_time.isoformat()}']]]"
                
                handle = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                    query,
                    None
                )
                
                try:
                    while True:
                        events = win32evtlog.EvtNext(handle, 100, -1, 0)
                        if not events:
                            break
                            
                        for event in events:
                            # Render event to XML
                            xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                            
                            # Parse and normalize
                            normalized = self._normalize_xml_event(xml, source)
                            if normalized:
                                # Filter to priority events if configured
                                if self.priority_only:
                                    try:
                                        event_id = int(normalized.event_code)
                                        if event_id not in PRIORITY_EVENTS:
                                            continue
                                    except (ValueError, TypeError):
                                        pass
                                        
                                await self._event_queue.put(normalized)
                                last_time = max(last_time, normalized.timestamp)
                                
                finally:
                    win32evtlog.EvtClose(handle)
                    
            except Exception as e:
                logger.debug(f"Error polling modern channel {channel}: {e}")
                
            await asyncio.sleep(1.0)
            
    def _normalize_classic_event(self, event: Any, source: EventSource) -> NormalizedEvent | None:
        """Normalize a classic Windows event log entry."""
        try:
            import win32evtlogutil
            
            # Extract basic fields
            event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
            timestamp = datetime.fromtimestamp(
                event.TimeGenerated.timestamp(),
                tz=timezone.utc
            )
            
            # Get message
            try:
                message = win32evtlogutil.SafeFormatMessage(event, None)
            except Exception:
                message = str(event.StringInserts) if event.StringInserts else ""
                
            # Build normalized event
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=timestamp,
                source=source,
                event_code=event_id,
                event_type=self._get_event_type(event.EventType),
                message=message[:2000] if message else "",
                hostname=event.ComputerName or "",
                username=self._extract_username(event.StringInserts),
                process_name=self._extract_process(event.StringInserts),
                process_id=self._extract_pid(event.StringInserts),
                command_line=self._extract_cmdline(event.StringInserts),
                raw_data={
                    "record_number": event.RecordNumber,
                    "event_category": event.EventCategory,
                    "string_inserts": list(event.StringInserts) if event.StringInserts else [],
                }
            )
        except Exception as e:
            logger.debug(f"Error normalizing event: {e}")
            return None
            
    def _normalize_xml_event(self, xml: str, source: EventSource) -> NormalizedEvent | None:
        """Normalize a modern Windows event from XML."""
        try:
            import xml.etree.ElementTree as ET
            
            root = ET.fromstring(xml)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            # Extract System data
            system = root.find("e:System", ns)
            if system is None:
                return None
                
            event_id_elem = system.find("e:EventID", ns)
            event_id = event_id_elem.text if event_id_elem is not None else "0"
            
            time_elem = system.find("e:TimeCreated", ns)
            timestamp_str = time_elem.get("SystemTime") if time_elem is not None else None
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                timestamp = datetime.now(timezone.utc)
                
            computer_elem = system.find("e:Computer", ns)
            hostname = computer_elem.text if computer_elem is not None else ""
            
            # Extract EventData
            event_data = root.find("e:EventData", ns)
            data_dict: dict[str, str] = {}
            
            if event_data is not None:
                for data in event_data.findall("e:Data", ns):
                    name = data.get("Name", "")
                    value = data.text or ""
                    if name:
                        data_dict[name] = value
                        
            # Build normalized event
            return NormalizedEvent(
                event_id=str(uuid.uuid4()),
                timestamp=timestamp,
                source=source,
                event_code=event_id,
                event_type="Information",
                message=self._build_message(data_dict),
                hostname=hostname,
                username=data_dict.get("SubjectUserName", data_dict.get("User", "")),
                process_name=data_dict.get("Image", data_dict.get("ProcessName", "")).split("\\")[-1],
                process_id=int(data_dict["ProcessId"]) if "ProcessId" in data_dict else None,
                parent_process=data_dict.get("ParentImage", "").split("\\")[-1],
                command_line=data_dict.get("CommandLine", ""),
                source_ip=data_dict.get("SourceIp", data_dict.get("IpAddress", "")),
                dest_ip=data_dict.get("DestinationIp", ""),
                source_port=int(data_dict["SourcePort"]) if "SourcePort" in data_dict else None,
                dest_port=int(data_dict["DestinationPort"]) if "DestinationPort" in data_dict else None,
                file_path=data_dict.get("TargetFilename", data_dict.get("ObjectName", "")),
                file_hash=data_dict.get("Hashes", ""),
                raw_data=data_dict,
            )
        except Exception as e:
            logger.debug(f"Error parsing XML event: {e}")
            return None
            
    def _get_event_type(self, event_type: int) -> str:
        """Convert Windows event type to string."""
        types = {
            0: "Success",
            1: "Error",
            2: "Warning",
            4: "Information",
            8: "Audit Success",
            16: "Audit Failure",
        }
        return types.get(event_type, "Unknown")
        
    def _extract_username(self, inserts: tuple | None) -> str:
        """Try to extract username from event string inserts."""
        if not inserts:
            return ""
        # Common positions for username in various events
        for insert in inserts:
            if insert and "\\" in str(insert):
                return str(insert)
        return ""
        
    def _extract_process(self, inserts: tuple | None) -> str:
        """Try to extract process name from event string inserts."""
        if not inserts:
            return ""
        for insert in inserts:
            s = str(insert)
            if s.endswith(".exe"):
                return s.split("\\")[-1]
        return ""
        
    def _extract_pid(self, inserts: tuple | None) -> int | None:
        """Try to extract process ID from event string inserts."""
        if not inserts:
            return None
        for insert in inserts:
            try:
                val = int(insert)
                if 0 < val < 100000:  # Reasonable PID range
                    return val
            except (ValueError, TypeError):
                continue
        return None
        
    def _extract_cmdline(self, inserts: tuple | None) -> str:
        """Try to extract command line from event string inserts."""
        if not inserts:
            return ""
        for insert in inserts:
            s = str(insert)
            if len(s) > 20 and (" " in s or "/" in s or "-" in s):
                if ".exe" in s.lower() or "powershell" in s.lower() or "cmd" in s.lower():
                    return s
        return ""
        
    def _build_message(self, data: dict[str, str]) -> str:
        """Build a readable message from event data."""
        parts = []
        for key, value in list(data.items())[:10]:
            if value and len(value) < 200:
                parts.append(f"{key}: {value}")
        return " | ".join(parts)[:2000]
