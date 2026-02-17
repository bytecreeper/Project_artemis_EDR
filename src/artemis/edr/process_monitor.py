"""Real-time process monitoring for Project Artemis.

Monitors process creation, termination, and suspicious behavior using psutil and WMI.
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, Set

import psutil

logger = logging.getLogger("artemis.edr.process_monitor")

# Try to import WMI for Windows process events
try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False
    logger.warning("WMI not available - process event monitoring limited")


# Suspicious process patterns (shared with sysmon module)
SUSPICIOUS_PROCESSES = {
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "wmic.exe",
    "powershell.exe", "pwsh.exe", "bitsadmin.exe", "curl.exe",
    "net.exe", "net1.exe", "netsh.exe", "schtasks.exe", "at.exe",
    "reg.exe", "sc.exe", "vssadmin.exe", "bcdedit.exe", "wbadmin.exe",
}

SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("explorer.exe", "mshta.exe"),
    ("services.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("wmiprvse.exe", "cmd.exe"),
}


@dataclass
class ProcessEvent:
    """A process event (creation or termination)."""
    event_type: str  # "create" or "terminate"
    pid: int
    name: str
    exe: Optional[str]
    cmdline: Optional[str]
    parent_pid: Optional[int]
    parent_name: Optional[str]
    username: Optional[str]
    timestamp: datetime
    
    # Analysis results
    severity: str = "info"
    alerts: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline": self.cmdline,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "username": self.username,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "alerts": self.alerts,
            "mitre_techniques": self.mitre_techniques,
        }


class ProcessMonitor:
    """Real-time process monitor using psutil and optionally WMI."""
    
    def __init__(self, data_dir: Optional[Path] = None, use_wmi: bool = True):
        """Initialize the process monitor.
        
        Args:
            data_dir: Directory to store process events
            use_wmi: Whether to use WMI for real-time events (Windows only)
        """
        self.data_dir = data_dir or Path("data/process_monitor")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.events_file = self.data_dir / "events.jsonl"
        self.alerts_file = self.data_dir / "alerts.jsonl"
        
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._wmi_thread: Optional[threading.Thread] = None
        self._known_pids: Set[int] = set()
        self._callbacks: list[Callable[[ProcessEvent], None]] = []
        self._alert_callbacks: list[Callable[[ProcessEvent], None]] = []
        
        # Statistics
        self.stats = {
            "processes_seen": 0,
            "alerts_generated": 0,
            "start_time": None,
        }
        
        self.use_wmi = use_wmi and HAS_WMI and os.name == "nt"
    
    def on_event(self, callback: Callable[[ProcessEvent], None]):
        """Register callback for all process events."""
        self._callbacks.append(callback)
    
    def on_alert(self, callback: Callable[[ProcessEvent], None]):
        """Register callback for alerts only."""
        self._alert_callbacks.append(callback)
    
    def start(self):
        """Start the process monitor."""
        if self._running:
            return
        
        self._running = True
        self.stats["start_time"] = datetime.now().isoformat()
        
        # Initialize known PIDs
        self._known_pids = set(p.pid for p in psutil.process_iter())
        
        # Start polling thread (always runs as fallback)
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        
        # Start WMI thread if available
        if self.use_wmi:
            self._wmi_thread = threading.Thread(target=self._wmi_loop, daemon=True)
            self._wmi_thread.start()
            logger.info("Process monitor started with WMI events")
        else:
            logger.info("Process monitor started with polling")
    
    def stop(self):
        """Stop the process monitor."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=2)
        if self._wmi_thread:
            self._wmi_thread.join(timeout=2)
        logger.info("Process monitor stopped")
    
    def _poll_loop(self):
        """Poll for process changes."""
        while self._running:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'username']):
                    try:
                        pid = proc.pid
                        current_pids.add(pid)
                        
                        # Check for new processes
                        if pid not in self._known_pids:
                            info = proc.info
                            event = self._create_event(
                                "create",
                                pid,
                                info.get("name"),
                                info.get("exe"),
                                info.get("cmdline"),
                                info.get("ppid"),
                                info.get("username"),
                            )
                            self._process_event(event)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check for terminated processes
                terminated = self._known_pids - current_pids
                for pid in terminated:
                    event = ProcessEvent(
                        event_type="terminate",
                        pid=pid,
                        name="unknown",
                        exe=None,
                        cmdline=None,
                        parent_pid=None,
                        parent_name=None,
                        username=None,
                        timestamp=datetime.now(),
                    )
                    self._process_event(event)
                
                self._known_pids = current_pids
                
            except Exception as e:
                logger.error(f"Poll loop error: {e}")
            
            time.sleep(1)  # Poll every second
    
    def _wmi_loop(self):
        """Watch for process events via WMI."""
        try:
            c = wmi.WMI()
            
            # Watch for process creation
            process_watcher = c.Win32_Process.watch_for("creation")
            
            while self._running:
                try:
                    new_process = process_watcher(timeout_ms=1000)
                    if new_process:
                        # Get parent process name
                        parent_name = None
                        try:
                            parent = psutil.Process(new_process.ParentProcessId)
                            parent_name = parent.name()
                        except:
                            pass
                        
                        cmdline = None
                        if new_process.CommandLine:
                            cmdline = new_process.CommandLine.split()
                        
                        event = self._create_event(
                            "create",
                            new_process.ProcessId,
                            new_process.Name,
                            new_process.ExecutablePath,
                            cmdline,
                            new_process.ParentProcessId,
                            None,  # WMI doesn't easily give us username
                            parent_name,
                        )
                        self._process_event(event)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    logger.debug(f"WMI event error: {e}")
                    
        except Exception as e:
            logger.error(f"WMI loop failed: {e}")
    
    def _create_event(
        self,
        event_type: str,
        pid: int,
        name: Optional[str],
        exe: Optional[str],
        cmdline: Optional[list],
        parent_pid: Optional[int],
        username: Optional[str],
        parent_name: Optional[str] = None,
    ) -> ProcessEvent:
        """Create a process event and analyze it."""
        
        # Try to get parent name if not provided
        if parent_name is None and parent_pid:
            try:
                parent = psutil.Process(parent_pid)
                parent_name = parent.name()
            except:
                pass
        
        event = ProcessEvent(
            event_type=event_type,
            pid=pid,
            name=name or "unknown",
            exe=exe,
            cmdline=" ".join(cmdline) if cmdline else None,
            parent_pid=parent_pid,
            parent_name=parent_name,
            username=username,
            timestamp=datetime.now(),
        )
        
        # Analyze for threats
        self._analyze_event(event)
        
        return event
    
    def _analyze_event(self, event: ProcessEvent):
        """Analyze a process event for suspicious activity."""
        if event.event_type != "create":
            return
        
        name_lower = event.name.lower() if event.name else ""
        parent_lower = event.parent_name.lower() if event.parent_name else ""
        cmdline_lower = event.cmdline.lower() if event.cmdline else ""
        
        # Check for suspicious processes
        if name_lower in SUSPICIOUS_PROCESSES:
            event.alerts.append(f"Suspicious process: {event.name}")
            event.severity = "medium"
        
        # Check parent-child relationships
        if (parent_lower, name_lower) in SUSPICIOUS_PARENT_CHILD:
            event.alerts.append(f"Suspicious spawn: {event.parent_name} -> {event.name}")
            event.severity = "high"
            event.mitre_techniques.append("T1059")
        
        # Check for encoded PowerShell
        if "powershell" in name_lower or "pwsh" in name_lower:
            if cmdline_lower:
                if re.search(r"-enc\w*\s+[A-Za-z0-9+/=]{20,}", cmdline_lower):
                    event.alerts.append("Encoded PowerShell command")
                    event.severity = "high"
                    event.mitre_techniques.append("T1059.001")
                
                if "bypass" in cmdline_lower and "executionpolicy" in cmdline_lower:
                    event.alerts.append("PowerShell execution policy bypass")
                    event.severity = "medium"
                
                if "-w hidden" in cmdline_lower or "-windowstyle hidden" in cmdline_lower:
                    event.alerts.append("Hidden PowerShell window")
                    event.severity = "medium"
        
        # Check for credential access
        if "mimikatz" in cmdline_lower or "sekurlsa" in cmdline_lower:
            event.alerts.append("Potential credential dumping tool")
            event.severity = "critical"
            event.mitre_techniques.append("T1003")
        
        # Check for defense evasion
        if "vssadmin" in name_lower and "delete" in cmdline_lower:
            event.alerts.append("Shadow copy deletion")
            event.severity = "critical"
            event.mitre_techniques.append("T1490")
    
    def _process_event(self, event: ProcessEvent):
        """Process an event - store and notify callbacks."""
        self.stats["processes_seen"] += 1
        
        # Store event
        try:
            with open(self.events_file, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
        
        # Store alert if needed
        if event.alerts:
            self.stats["alerts_generated"] += 1
            try:
                with open(self.alerts_file, "a") as f:
                    f.write(json.dumps(event.to_dict()) + "\n")
            except Exception as e:
                logger.error(f"Failed to store alert: {e}")
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback failed: {e}")
        
        if event.alerts:
            for callback in self._alert_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")
    
    def get_current_processes(self) -> list[dict]:
        """Get list of currently running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'username', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                
                # Get parent name
                parent_name = None
                if info.get('ppid'):
                    try:
                        parent = psutil.Process(info['ppid'])
                        parent_name = parent.name()
                    except:
                        pass
                
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "exe": info['exe'],
                    "cmdline": " ".join(info['cmdline']) if info['cmdline'] else None,
                    "parent_pid": info['ppid'],
                    "parent_name": parent_name,
                    "username": info['username'],
                    "cpu_percent": info['cpu_percent'],
                    "memory_percent": info['memory_percent'],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def get_recent_events(self, limit: int = 100, event_type: Optional[str] = None) -> list[dict]:
        """Get recent process events."""
        events = []
        try:
            if self.events_file.exists():
                with open(self.events_file) as f:
                    lines = f.readlines()
                    for line in reversed(lines[-limit * 2:]):
                        try:
                            event = json.loads(line)
                            if event_type is None or event["event_type"] == event_type:
                                events.append(event)
                                if len(events) >= limit:
                                    break
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Failed to read events: {e}")
        return events
    
    def get_recent_alerts(self, limit: int = 50) -> list[dict]:
        """Get recent alerts."""
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
        """Get monitor statistics."""
        return {
            **self.stats,
            "running": self._running,
            "wmi_enabled": self.use_wmi,
        }
    
    def analyze_process(self, pid: int) -> Optional[dict]:
        """Get detailed analysis of a specific process."""
        try:
            proc = psutil.Process(pid)
            
            # Get process info
            with proc.oneshot():
                info = {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "exe": proc.exe(),
                    "cmdline": proc.cmdline(),
                    "cwd": proc.cwd(),
                    "username": proc.username(),
                    "status": proc.status(),
                    "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                    "parent_pid": proc.ppid(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_info": proc.memory_info()._asdict(),
                    "num_threads": proc.num_threads(),
                    "connections": [],
                    "open_files": [],
                }
            
            # Get network connections
            try:
                for conn in proc.connections():
                    info["connections"].append({
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Get open files
            try:
                for f in proc.open_files():
                    info["open_files"].append(f.path)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Analyze for threats
            alerts = []
            name_lower = info["name"].lower()
            cmdline_str = " ".join(info["cmdline"]).lower() if info["cmdline"] else ""
            
            if name_lower in SUSPICIOUS_PROCESSES:
                alerts.append(f"Process is on suspicious list: {info['name']}")
            
            if "powershell" in name_lower and "-enc" in cmdline_str:
                alerts.append("Encoded PowerShell detected")
            
            info["alerts"] = alerts
            info["is_suspicious"] = len(alerts) > 0
            
            return info
            
        except psutil.NoSuchProcess:
            return None
        except psutil.AccessDenied:
            return {"error": "Access denied", "pid": pid}
