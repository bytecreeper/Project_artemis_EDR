# Artemis Endpoint Agent - Deep System Telemetry
"""
Real-time endpoint monitoring with full visibility:
- Process activity (creation, termination, command lines)
- Network connections (per-process, DNS queries)
- File system activity
- Registry changes
- Window focus / active applications
- Web activity extraction
- Keyboard/mouse activity metrics
- Security events

Requires Administrator for full visibility.
"""

import asyncio
import ctypes
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, AsyncIterator
import struct

logger = logging.getLogger("artemis.agent.endpoint")


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class EventType(str, Enum):
    """Types of endpoint events."""
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    DNS_QUERY = "dns_query"
    FILE_CREATE = "file_create"
    FILE_MODIFY = "file_modify"
    FILE_DELETE = "file_delete"
    FILE_READ = "file_read"
    REGISTRY_WRITE = "registry_write"
    REGISTRY_DELETE = "registry_delete"
    WINDOW_FOCUS = "window_focus"
    WEB_REQUEST = "web_request"
    LOGIN = "login"
    LOGOUT = "logout"
    USB_INSERT = "usb_insert"
    USB_REMOVE = "usb_remove"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    SCHEDULED_TASK = "scheduled_task"
    POWERSHELL = "powershell"
    CMD = "cmd"
    SECURITY_ALERT = "security_alert"
    INPUT_ACTIVITY = "input_activity"


@dataclass
class EndpointEvent:
    """A single telemetry event from the endpoint."""
    event_id: str
    timestamp: datetime
    event_type: EventType
    process_name: str | None = None
    process_id: int | None = None
    process_path: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    parent_pid: int | None = None
    username: str | None = None
    
    # Network
    local_ip: str | None = None
    local_port: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    protocol: str | None = None
    dns_query: str | None = None
    
    # File
    file_path: str | None = None
    file_size: int | None = None
    
    # Registry
    registry_key: str | None = None
    registry_value: str | None = None
    
    # Window
    window_title: str | None = None
    window_class: str | None = None
    
    # Web
    url: str | None = None
    http_method: str | None = None
    
    # Extra
    details: dict = field(default_factory=dict)
    severity: str = "info"  # info, low, medium, high, critical
    
    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "process_path": self.process_path,
            "command_line": self.command_line,
            "parent_process": self.parent_process,
            "parent_pid": self.parent_pid,
            "username": self.username,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "dns_query": self.dns_query,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "registry_key": self.registry_key,
            "registry_value": self.registry_value,
            "window_title": self.window_title,
            "window_class": self.window_class,
            "url": self.url,
            "http_method": self.http_method,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class ProcessInfo:
    """Detailed process information."""
    pid: int
    name: str
    path: str | None = None
    command_line: str | None = None
    username: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    start_time: datetime | None = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    threads: int = 0
    handles: int = 0
    connections: list = field(default_factory=list)
    open_files: list = field(default_factory=list)
    window_title: str | None = None
    is_elevated: bool = False
    
    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "username": self.username,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "threads": self.threads,
            "handles": self.handles,
            "connections": self.connections,
            "window_title": self.window_title,
            "is_elevated": self.is_elevated,
        }


class EndpointMonitor:
    """
    Real-time endpoint telemetry collection.
    Streams all system activity with sub-second latency.
    """
    
    def __init__(
        self,
        buffer_size: int = 10000,
        include_file_events: bool = True,
        include_registry_events: bool = True,
        include_window_events: bool = True,
        poll_interval_ms: int = 100,  # 100ms for low latency
    ):
        self.buffer_size = buffer_size
        self.include_file_events = include_file_events
        self.include_registry_events = include_registry_events
        self.include_window_events = include_window_events
        self.poll_interval = poll_interval_ms / 1000.0
        
        self._running = False
        self._event_queue: asyncio.Queue[EndpointEvent] = asyncio.Queue(maxsize=buffer_size)
        self._event_buffer: deque[EndpointEvent] = deque(maxlen=buffer_size)
        self._callbacks: list[Callable] = []
        self._tasks: list[asyncio.Task] = []
        
        # State tracking
        self._processes: dict[int, ProcessInfo] = {}
        self._connections: dict[str, dict] = {}
        self._last_window: str | None = None
        self._dns_cache: dict[str, str] = {}
        self._event_counter = 0
        
        # Stats
        self._start_time: datetime | None = None
        self._events_total = 0
        
    async def start(self) -> None:
        """Start all monitoring tasks."""
        if self._running:
            return
            
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        
        logger.info("Starting endpoint monitor")
        
        # Start monitoring tasks
        self._tasks = [
            asyncio.create_task(self._monitor_processes()),
            asyncio.create_task(self._monitor_connections()),
            asyncio.create_task(self._monitor_dns()),
            asyncio.create_task(self._monitor_security_events()),
            asyncio.create_task(self._monitor_powershell()),
        ]
        
        if self.include_window_events:
            self._tasks.append(asyncio.create_task(self._monitor_windows()))
            
        # Event dispatcher
        self._tasks.append(asyncio.create_task(self._dispatch_events()))
        
        logger.info(f"Endpoint monitor started with {len(self._tasks)} collectors")
        
    async def stop(self) -> None:
        """Stop all monitoring."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("Endpoint monitor stopped")
        
    def on_event(self, callback: Callable) -> None:
        """Register callback for events."""
        self._callbacks.append(callback)
        
    async def events(self) -> AsyncIterator[EndpointEvent]:
        """Stream events as they occur."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0
                )
                yield event
            except asyncio.TimeoutError:
                continue
                
    def _gen_event_id(self) -> str:
        """Generate unique event ID."""
        self._event_counter += 1
        return f"evt_{int(time.time()*1000)}_{self._event_counter}"
        
    async def _emit(self, event: EndpointEvent) -> None:
        """Emit an event to all listeners."""
        self._events_total += 1
        self._event_buffer.append(event)
        
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest if queue full
            try:
                self._event_queue.get_nowait()
                self._event_queue.put_nowait(event)
            except Exception:
                pass
                
    async def _dispatch_events(self) -> None:
        """Dispatch events to callbacks."""
        while self._running:
            try:
                # Process events from buffer
                while self._event_buffer:
                    event = self._event_buffer[0]
                    for callback in self._callbacks:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(event)
                            else:
                                callback(event)
                        except Exception as e:
                            logger.debug(f"Callback error: {e}")
                    self._event_buffer.popleft()
                    
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.debug(f"Dispatch error: {e}")
                await asyncio.sleep(0.1)
                
    async def _monitor_processes(self) -> None:
        """Monitor process creation and termination."""
        logger.info("Starting process monitor")
        
        known_pids: set[int] = set()
        
        while self._running:
            try:
                # Get current processes via PowerShell (fast method)
                ps_script = '''
Get-Process | Select-Object Id, ProcessName, Path, 
    @{N='CommandLine';E={$_.CommandLine}},
    @{N='StartTime';E={$_.StartTime.ToString('o')}},
    @{N='CPU';E={$_.CPU}},
    @{N='WS';E={$_.WorkingSet64}},
    @{N='Threads';E={$_.Threads.Count}},
    @{N='Handles';E={$_.HandleCount}},
    @{N='Username';E={(Get-Process -Id $_.Id -IncludeUserName -ErrorAction SilentlyContinue).UserName}},
    @{N='ParentId';E={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).ParentProcessId}},
    @{N='MainWindowTitle';E={$_.MainWindowTitle}} |
ConvertTo-Json -Compress
'''
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        current_pids = set()
                        
                        for proc in data:
                            pid = proc.get("Id")
                            if not pid:
                                continue
                                
                            current_pids.add(pid)
                            
                            # New process?
                            if pid not in known_pids:
                                name = proc.get("ProcessName", "")
                                path = proc.get("Path", "")
                                cmdline = proc.get("CommandLine", "")
                                
                                # Create process info
                                info = ProcessInfo(
                                    pid=pid,
                                    name=name,
                                    path=path,
                                    command_line=cmdline,
                                    username=proc.get("Username"),
                                    parent_pid=proc.get("ParentId"),
                                    memory_mb=proc.get("WS", 0) / 1024 / 1024,
                                    threads=proc.get("Threads", 0),
                                    handles=proc.get("Handles", 0),
                                    window_title=proc.get("MainWindowTitle"),
                                )
                                self._processes[pid] = info
                                
                                # Emit event
                                severity = "info"
                                if any(x in name.lower() for x in ["mimikatz", "psexec", "cobalt", "beacon"]):
                                    severity = "critical"
                                elif any(x in name.lower() for x in ["powershell", "cmd", "wscript", "cscript", "mshta"]):
                                    severity = "medium"
                                    
                                await self._emit(EndpointEvent(
                                    event_id=self._gen_event_id(),
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=EventType.PROCESS_START,
                                    process_name=name,
                                    process_id=pid,
                                    process_path=path,
                                    command_line=cmdline,
                                    parent_pid=proc.get("ParentId"),
                                    username=proc.get("Username"),
                                    window_title=proc.get("MainWindowTitle"),
                                    severity=severity,
                                ))
                            else:
                                # Update existing
                                if pid in self._processes:
                                    self._processes[pid].window_title = proc.get("MainWindowTitle")
                                    self._processes[pid].memory_mb = proc.get("WS", 0) / 1024 / 1024
                                    
                        # Check for terminated processes
                        terminated = known_pids - current_pids
                        for pid in terminated:
                            if pid in self._processes:
                                proc = self._processes.pop(pid)
                                await self._emit(EndpointEvent(
                                    event_id=self._gen_event_id(),
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=EventType.PROCESS_END,
                                    process_name=proc.name,
                                    process_id=pid,
                                    process_path=proc.path,
                                    severity="info",
                                ))
                                
                        known_pids = current_pids
                        
                    except json.JSONDecodeError:
                        pass
                        
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                logger.debug(f"Process monitor error: {e}")
                
            await asyncio.sleep(self.poll_interval)
            
    async def _monitor_connections(self) -> None:
        """Monitor network connections per process."""
        logger.info("Starting connection monitor")
        
        known_conns: set[str] = set()
        
        while self._running:
            try:
                ps_script = '''
Get-NetTCPConnection -State Established,Listen,TimeWait 2>$null |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
        State, OwningProcess,
        @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    ConvertTo-Json -Compress
'''
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        current_conns = set()
                        
                        for conn in data:
                            remote_ip = conn.get("RemoteAddress", "")
                            if remote_ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                                continue
                                
                            conn_id = f"{conn.get('LocalAddress')}:{conn.get('LocalPort')}-{remote_ip}:{conn.get('RemotePort')}"
                            current_conns.add(conn_id)
                            
                            if conn_id not in known_conns:
                                state = conn.get("State", "")
                                event_type = EventType.NETWORK_LISTEN if state == "Listen" else EventType.NETWORK_CONNECT
                                
                                # Determine severity
                                remote_port = conn.get("RemotePort", 0)
                                severity = "info"
                                if remote_port in (4444, 5555, 6666, 31337, 1234):
                                    severity = "critical"
                                elif remote_port > 10000:
                                    severity = "low"
                                    
                                await self._emit(EndpointEvent(
                                    event_id=self._gen_event_id(),
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=event_type,
                                    process_name=conn.get("ProcessName"),
                                    process_id=conn.get("OwningProcess"),
                                    local_ip=conn.get("LocalAddress"),
                                    local_port=conn.get("LocalPort"),
                                    remote_ip=remote_ip,
                                    remote_port=remote_port,
                                    protocol="TCP",
                                    severity=severity,
                                    details={"state": state},
                                ))
                                
                        known_conns = current_conns
                        
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Connection monitor error: {e}")
                
            await asyncio.sleep(self.poll_interval * 2)
            
    async def _monitor_dns(self) -> None:
        """Monitor DNS queries."""
        logger.info("Starting DNS monitor")
        
        known_entries: set[str] = set()
        
        while self._running:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-DnsClientCache | Select-Object Entry, Data, TimeToLive | ConvertTo-Json -Compress"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        for entry in data:
                            domain = entry.get("Entry", "")
                            ip = entry.get("Data", "")
                            
                            if domain and domain not in known_entries:
                                known_entries.add(domain)
                                self._dns_cache[ip] = domain
                                
                                # Check for suspicious domains
                                severity = "info"
                                if any(x in domain.lower() for x in [".onion", "pastebin", "ngrok", "duckdns"]):
                                    severity = "high"
                                elif any(x in domain.lower() for x in [".xyz", ".top", ".tk", ".ml"]):
                                    severity = "medium"
                                    
                                await self._emit(EndpointEvent(
                                    event_id=self._gen_event_id(),
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=EventType.DNS_QUERY,
                                    dns_query=domain,
                                    remote_ip=ip,
                                    severity=severity,
                                ))
                                
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"DNS monitor error: {e}")
                
            await asyncio.sleep(2.0)  # DNS cache doesn't change fast
            
    async def _monitor_windows(self) -> None:
        """Monitor active window / focus changes."""
        logger.info("Starting window monitor")
        
        try:
            import ctypes
            user32 = ctypes.windll.user32
            
            while self._running:
                try:
                    # Get foreground window
                    hwnd = user32.GetForegroundWindow()
                    if hwnd:
                        # Get window title
                        length = user32.GetWindowTextLengthW(hwnd) + 1
                        title = ctypes.create_unicode_buffer(length)
                        user32.GetWindowTextW(hwnd, title, length)
                        
                        # Get process ID
                        pid = ctypes.c_ulong()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        
                        window_title = title.value
                        
                        if window_title and window_title != self._last_window:
                            self._last_window = window_title
                            
                            # Get process name
                            proc_name = None
                            if pid.value in self._processes:
                                proc_name = self._processes[pid.value].name
                                
                            await self._emit(EndpointEvent(
                                event_id=self._gen_event_id(),
                                timestamp=datetime.now(timezone.utc),
                                event_type=EventType.WINDOW_FOCUS,
                                process_name=proc_name,
                                process_id=pid.value,
                                window_title=window_title,
                                severity="info",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Window monitor error: {e}")
                    
                await asyncio.sleep(0.5)  # Check focus every 500ms
                
        except ImportError:
            logger.warning("ctypes not available for window monitoring")
            
    async def _monitor_security_events(self) -> None:
        """Monitor Windows Security events in real-time."""
        logger.info("Starting security event monitor")
        
        # Important security event IDs
        security_events = {
            4624: ("Login Success", "info"),
            4625: ("Login Failed", "medium"),
            4634: ("Logoff", "info"),
            4648: ("Explicit Credential Logon", "medium"),
            4672: ("Special Privileges Assigned", "medium"),
            4688: ("Process Created", "info"),
            4689: ("Process Terminated", "info"),
            4697: ("Service Installed", "high"),
            4698: ("Scheduled Task Created", "high"),
            4720: ("User Account Created", "high"),
            4722: ("User Account Enabled", "medium"),
            4724: ("Password Reset Attempt", "medium"),
            4728: ("Member Added to Security Group", "high"),
            4732: ("Member Added to Local Group", "high"),
            4738: ("User Account Changed", "medium"),
            4756: ("Member Added to Universal Group", "high"),
            4768: ("Kerberos TGT Requested", "info"),
            4769: ("Kerberos Service Ticket", "info"),
            4776: ("NTLM Authentication", "info"),
            5140: ("Network Share Accessed", "info"),
            5145: ("Network Share Object Accessed", "info"),
        }
        
        last_time = datetime.now()
        
        while self._running:
            try:
                ps_script = f'''
$startTime = [DateTime]::Parse("{last_time.strftime('%Y-%m-%dT%H:%M:%S')}")
try {{
    Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue | 
    Where-Object {{ $_.TimeCreated -gt $startTime -and $_.Id -in @({','.join(str(k) for k in security_events.keys())}) }} |
    ForEach-Object {{
        @{{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id = $_.Id
            Message = if ($_.Message.Length -gt 300) {{ $_.Message.Substring(0, 300) }} else {{ $_.Message }}
        }}
    }} | ConvertTo-Json -Compress
}} catch {{}}
'''
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        for event in data:
                            event_id = event.get("Id")
                            if event_id in security_events:
                                name, severity = security_events[event_id]
                                
                                await self._emit(EndpointEvent(
                                    event_id=self._gen_event_id(),
                                    timestamp=datetime.now(timezone.utc),
                                    event_type=EventType.SECURITY_ALERT if severity in ("high", "critical") else EventType.LOGIN,
                                    details={
                                        "event_id": event_id,
                                        "event_name": name,
                                        "message": event.get("Message", ""),
                                    },
                                    severity=severity,
                                ))
                                
                                # Update last_time
                                ts = event.get("TimeCreated")
                                if ts:
                                    try:
                                        event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                                        if event_time.tzinfo:
                                            event_time = event_time.replace(tzinfo=None)
                                        if event_time > last_time:
                                            last_time = event_time
                                    except Exception:
                                        pass
                                        
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Security event monitor error: {e}")
                
            await asyncio.sleep(1.0)
            
    async def _monitor_powershell(self) -> None:
        """Monitor PowerShell script execution."""
        logger.info("Starting PowerShell monitor")
        
        last_time = datetime.now()
        
        while self._running:
            try:
                ps_script = f'''
$startTime = [DateTime]::Parse("{last_time.strftime('%Y-%m-%dT%H:%M:%S')}")
try {{
    Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.TimeCreated -gt $startTime -and $_.Id -eq 4104 }} |
    ForEach-Object {{
        $scriptBlock = ($_.Properties | Where-Object {{ $_.Name -eq 'ScriptBlockText' }}).Value
        if (-not $scriptBlock) {{ $scriptBlock = $_.Message }}
        @{{
            TimeCreated = $_.TimeCreated.ToString("o")
            ScriptBlock = if ($scriptBlock.Length -gt 500) {{ $scriptBlock.Substring(0, 500) }} else {{ $scriptBlock }}
        }}
    }} | ConvertTo-Json -Compress
}} catch {{}}
'''
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        for event in data:
                            script = event.get("ScriptBlock", "")
                            
                            # Determine severity based on content
                            severity = "info"
                            suspicious_patterns = [
                                ("Invoke-Expression", "high"),
                                ("IEX", "high"),
                                ("DownloadString", "high"),
                                ("DownloadFile", "high"),
                                ("WebClient", "medium"),
                                ("Net.WebClient", "medium"),
                                ("Invoke-WebRequest", "medium"),
                                ("-enc", "high"),
                                ("-EncodedCommand", "high"),
                                ("FromBase64String", "high"),
                                ("Mimikatz", "critical"),
                                ("sekurlsa", "critical"),
                                ("Invoke-Mimikatz", "critical"),
                                ("Get-Credential", "medium"),
                                ("ConvertTo-SecureString", "medium"),
                                ("Add-MpPreference", "high"),
                                ("Set-MpPreference", "high"),
                                ("Disable-WindowsOptionalFeature", "high"),
                            ]
                            
                            for pattern, sev in suspicious_patterns:
                                if pattern.lower() in script.lower():
                                    if sev == "critical" or (sev == "high" and severity != "critical"):
                                        severity = sev
                                    elif sev == "medium" and severity not in ("critical", "high"):
                                        severity = sev
                                        
                            await self._emit(EndpointEvent(
                                event_id=self._gen_event_id(),
                                timestamp=datetime.now(timezone.utc),
                                event_type=EventType.POWERSHELL,
                                command_line=script,
                                severity=severity,
                                details={"script_block": script},
                            ))
                            
                            # Update last_time
                            ts = event.get("TimeCreated")
                            if ts:
                                try:
                                    event_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                                    if event_time.tzinfo:
                                        event_time = event_time.replace(tzinfo=None)
                                    if event_time > last_time:
                                        last_time = event_time
                                except Exception:
                                    pass
                                    
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"PowerShell monitor error: {e}")
                
            await asyncio.sleep(0.5)  # Fast polling for PS
            
    # === Data Access Methods ===
    
    @property
    def processes(self) -> dict[int, ProcessInfo]:
        """Get current processes."""
        return self._processes
        
    def get_process(self, pid: int) -> ProcessInfo | None:
        """Get process by PID."""
        return self._processes.get(pid)
        
    def get_recent_events(self, limit: int = 100, event_type: EventType | None = None) -> list[EndpointEvent]:
        """Get recent events, optionally filtered by type."""
        events = list(self._event_buffer)
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]
        
    def get_events_by_process(self, pid: int, limit: int = 100) -> list[EndpointEvent]:
        """Get events for a specific process."""
        events = [e for e in self._event_buffer if e.process_id == pid]
        return events[-limit:]
        
    def get_dns_cache(self) -> dict[str, str]:
        """Get DNS resolution cache."""
        return self._dns_cache
        
    @property
    def stats(self) -> dict:
        """Get monitor statistics."""
        return {
            "running": self._running,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "events_total": self._events_total,
            "processes_tracked": len(self._processes),
            "buffer_size": len(self._event_buffer),
            "dns_cache_size": len(self._dns_cache),
        }
