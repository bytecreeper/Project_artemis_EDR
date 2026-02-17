"""EDR Response Actions for Project Artemis.

Provides automated and manual response capabilities:
- Kill process
- Quarantine file
- Block IP (firewall)
- Isolate endpoint (network)
- Collect forensic data
"""

import json
import logging
import os
import shutil
import subprocess
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Callable
import psutil

logger = logging.getLogger("artemis.edr.response")


class ActionType(Enum):
    """Types of response actions."""
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    UNISOLATE_ENDPOINT = "unisolate_endpoint"
    COLLECT_FORENSICS = "collect_forensics"
    RUN_SCAN = "run_scan"


class ActionStatus(Enum):
    """Status of a response action."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ResponseAction:
    """A response action record."""
    id: str
    action_type: ActionType
    target: str  # PID, file path, IP, etc.
    status: ActionStatus = ActionStatus.PENDING
    triggered_by: str = "manual"  # manual, auto, alert_id
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action_type": self.action_type.value,
            "target": self.target,
            "status": self.status.value,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "metadata": self.metadata,
        }


class ResponseEngine:
    """Execute and manage response actions."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("data/response")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.quarantine_dir = self.data_dir / "quarantine"
        self.quarantine_dir.mkdir(exist_ok=True)
        
        self.forensics_dir = self.data_dir / "forensics"
        self.forensics_dir.mkdir(exist_ok=True)
        
        self.actions_file = self.data_dir / "actions.jsonl"
        self.blocked_ips_file = self.data_dir / "blocked_ips.json"
        
        # Load blocked IPs
        self._blocked_ips = self._load_blocked_ips()
        
        # Callbacks for action events
        self._callbacks: list[Callable[[ResponseAction], None]] = []
        
        # Action counter for IDs
        self._action_counter = 0
    
    def _load_blocked_ips(self) -> set:
        """Load list of blocked IPs."""
        if self.blocked_ips_file.exists():
            try:
                with open(self.blocked_ips_file) as f:
                    return set(json.load(f))
            except:
                pass
        return set()
    
    def _save_blocked_ips(self):
        """Save blocked IPs to disk."""
        try:
            with open(self.blocked_ips_file, "w") as f:
                json.dump(list(self._blocked_ips), f)
        except Exception as e:
            logger.error(f"Failed to save blocked IPs: {e}")
    
    def on_action(self, callback: Callable[[ResponseAction], None]):
        """Register callback for action events."""
        self._callbacks.append(callback)
    
    def _notify(self, action: ResponseAction):
        """Notify callbacks of action."""
        for cb in self._callbacks:
            try:
                cb(action)
            except Exception as e:
                logger.error(f"Action callback failed: {e}")
    
    def _save_action(self, action: ResponseAction):
        """Save action to history."""
        try:
            with open(self.actions_file, "a") as f:
                f.write(json.dumps(action.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to save action: {e}")
    
    def _generate_id(self) -> str:
        """Generate unique action ID."""
        self._action_counter += 1
        return f"act-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._action_counter:04d}"
    
    def kill_process(
        self,
        pid: int,
        triggered_by: str = "manual",
        force: bool = False,
    ) -> ResponseAction:
        """Kill a process by PID.
        
        Args:
            pid: Process ID to kill
            triggered_by: What triggered this action
            force: Use SIGKILL instead of SIGTERM
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.KILL_PROCESS,
            target=str(pid),
            triggered_by=triggered_by,
            metadata={"force": force},
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            proc = psutil.Process(pid)
            proc_info = {
                "name": proc.name(),
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                "exe": proc.exe() if proc.exe() else "",
                "username": proc.username() if proc.username() else "",
            }
            action.metadata["process_info"] = proc_info
            
            if force:
                proc.kill()
            else:
                proc.terminate()
            
            # Wait briefly for termination
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                if not force:
                    proc.kill()
            
            action.status = ActionStatus.COMPLETED
            action.result = f"Process {pid} ({proc_info['name']}) terminated"
            
        except psutil.NoSuchProcess:
            action.status = ActionStatus.FAILED
            action.error = f"Process {pid} not found"
        except psutil.AccessDenied:
            action.status = ActionStatus.FAILED
            action.error = f"Access denied to kill process {pid}"
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
    
    def quarantine_file(
        self,
        file_path: str,
        triggered_by: str = "manual",
        delete_original: bool = True,
    ) -> ResponseAction:
        """Quarantine a file by moving it to secure storage.
        
        Args:
            file_path: Path to file to quarantine
            triggered_by: What triggered this action
            delete_original: Whether to delete original after copying
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.QUARANTINE_FILE,
            target=file_path,
            triggered_by=triggered_by,
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            src_path = Path(file_path)
            if not src_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Calculate hash
            sha256 = hashlib.sha256()
            with open(src_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()
            
            # Create quarantine entry
            quarantine_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file_hash[:16]}_{src_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Copy to quarantine
            shutil.copy2(src_path, quarantine_path)
            
            # Save metadata
            meta_path = self.quarantine_dir / f"{quarantine_name}.meta.json"
            with open(meta_path, "w") as f:
                json.dump({
                    "original_path": str(src_path.absolute()),
                    "sha256": file_hash,
                    "size": src_path.stat().st_size,
                    "quarantined_at": datetime.now().isoformat(),
                    "triggered_by": triggered_by,
                }, f, indent=2)
            
            # Delete original if requested
            if delete_original:
                src_path.unlink()
            
            action.status = ActionStatus.COMPLETED
            action.result = f"File quarantined: {quarantine_path}"
            action.metadata = {
                "sha256": file_hash,
                "quarantine_path": str(quarantine_path),
                "original_deleted": delete_original,
            }
            
        except FileNotFoundError as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        except PermissionError:
            action.status = ActionStatus.FAILED
            action.error = f"Permission denied: {file_path}"
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
    
    def block_ip(
        self,
        ip: str,
        triggered_by: str = "manual",
        direction: str = "both",  # inbound, outbound, both
    ) -> ResponseAction:
        """Block an IP address using Windows Firewall.
        
        Args:
            ip: IP address to block
            triggered_by: What triggered this action
            direction: Traffic direction to block
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.BLOCK_IP,
            target=ip,
            triggered_by=triggered_by,
            metadata={"direction": direction},
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            rule_name = f"Artemis_Block_{ip.replace('.', '_')}"
            
            # Create firewall rules using netsh
            commands = []
            
            if direction in ("inbound", "both"):
                commands.append([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_IN",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ])
            
            if direction in ("outbound", "both"):
                commands.append([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_OUT",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes"
                ])
            
            for cmd in commands:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    raise RuntimeError(f"Firewall command failed: {result.stderr}")
            
            self._blocked_ips.add(ip)
            self._save_blocked_ips()
            
            action.status = ActionStatus.COMPLETED
            action.result = f"IP {ip} blocked ({direction})"
            
        except subprocess.TimeoutExpired:
            action.status = ActionStatus.FAILED
            action.error = "Firewall command timed out"
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
    
    def unblock_ip(self, ip: str, triggered_by: str = "manual") -> ResponseAction:
        """Remove IP block from firewall.
        
        Args:
            ip: IP address to unblock
            triggered_by: What triggered this action
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.UNBLOCK_IP,
            target=ip,
            triggered_by=triggered_by,
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            rule_name = f"Artemis_Block_{ip.replace('.', '_')}"
            
            # Remove firewall rules
            for suffix in ("_IN", "_OUT"):
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}{suffix}"
                    ],
                    capture_output=True,
                    timeout=30
                )
            
            self._blocked_ips.discard(ip)
            self._save_blocked_ips()
            
            action.status = ActionStatus.COMPLETED
            action.result = f"IP {ip} unblocked"
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
    
    def collect_forensics(
        self,
        target: str = "system",
        triggered_by: str = "manual",
    ) -> ResponseAction:
        """Collect forensic data from the system.
        
        Args:
            target: What to collect (system, process:{pid}, memory)
            triggered_by: What triggered this action
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.COLLECT_FORENSICS,
            target=target,
            triggered_by=triggered_by,
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            collection_dir = self.forensics_dir / f"collection_{timestamp}"
            collection_dir.mkdir(exist_ok=True)
            
            collected = []
            
            # System info
            if target in ("system", "all"):
                # Running processes
                procs = []
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                    try:
                        info = proc.info
                        info['cmdline'] = ' '.join(info['cmdline']) if info['cmdline'] else ''
                        procs.append(info)
                    except:
                        continue
                
                with open(collection_dir / "processes.json", "w") as f:
                    json.dump(procs, f, indent=2, default=str)
                collected.append("processes.json")
                
                # Network connections
                conns = []
                for conn in psutil.net_connections():
                    conns.append({
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid,
                    })
                
                with open(collection_dir / "connections.json", "w") as f:
                    json.dump(conns, f, indent=2)
                collected.append("connections.json")
                
                # System info
                sys_info = {
                    "hostname": os.environ.get("COMPUTERNAME", "unknown"),
                    "username": os.environ.get("USERNAME", "unknown"),
                    "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                    "cpu_count": psutil.cpu_count(),
                    "memory_total": psutil.virtual_memory().total,
                    "disk_partitions": [p._asdict() for p in psutil.disk_partitions()],
                }
                
                with open(collection_dir / "system_info.json", "w") as f:
                    json.dump(sys_info, f, indent=2)
                collected.append("system_info.json")
            
            # Specific process
            if target.startswith("process:"):
                pid = int(target.split(":")[1])
                try:
                    proc = psutil.Process(pid)
                    proc_info = {
                        "pid": proc.pid,
                        "name": proc.name(),
                        "exe": proc.exe(),
                        "cmdline": proc.cmdline(),
                        "cwd": proc.cwd(),
                        "username": proc.username(),
                        "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                        "connections": [],
                        "open_files": [],
                        "children": [],
                    }
                    
                    for conn in proc.connections():
                        proc_info["connections"].append({
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status,
                        })
                    
                    for f in proc.open_files():
                        proc_info["open_files"].append(f.path)
                    
                    for child in proc.children(recursive=True):
                        proc_info["children"].append({
                            "pid": child.pid,
                            "name": child.name(),
                        })
                    
                    with open(collection_dir / f"process_{pid}.json", "w") as f:
                        json.dump(proc_info, f, indent=2)
                    collected.append(f"process_{pid}.json")
                    
                except psutil.NoSuchProcess:
                    raise ValueError(f"Process {pid} not found")
            
            action.status = ActionStatus.COMPLETED
            action.result = f"Collected: {', '.join(collected)}"
            action.metadata = {
                "collection_path": str(collection_dir),
                "files": collected,
            }
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
    
    def get_blocked_ips(self) -> list[str]:
        """Get list of currently blocked IPs."""
        return list(self._blocked_ips)
    
    def get_quarantined_files(self) -> list[dict]:
        """Get list of quarantined files."""
        files = []
        for meta_file in self.quarantine_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                    meta["quarantine_file"] = meta_file.stem.replace(".meta", "")
                    files.append(meta)
            except:
                continue
        return files
    
    def get_action_history(self, limit: int = 100) -> list[dict]:
        """Get recent action history."""
        actions = []
        try:
            if self.actions_file.exists():
                with open(self.actions_file) as f:
                    lines = f.readlines()
                    for line in reversed(lines[-limit:]):
                        try:
                            actions.append(json.loads(line))
                        except:
                            continue
        except Exception as e:
            logger.error(f"Failed to read action history: {e}")
        return actions
    
    def restore_quarantined_file(self, quarantine_name: str) -> ResponseAction:
        """Restore a quarantined file to its original location.
        
        Args:
            quarantine_name: Name of quarantined file
            
        Returns:
            ResponseAction record
        """
        action = ResponseAction(
            id=self._generate_id(),
            action_type=ActionType.QUARANTINE_FILE,
            target=quarantine_name,
            metadata={"operation": "restore"},
        )
        
        try:
            action.status = ActionStatus.RUNNING
            
            quarantine_path = self.quarantine_dir / quarantine_name
            meta_path = self.quarantine_dir / f"{quarantine_name}.meta.json"
            
            if not quarantine_path.exists():
                raise FileNotFoundError(f"Quarantined file not found: {quarantine_name}")
            
            if not meta_path.exists():
                raise FileNotFoundError(f"Metadata not found for: {quarantine_name}")
            
            with open(meta_path) as f:
                meta = json.load(f)
            
            original_path = Path(meta["original_path"])
            
            # Restore file
            shutil.copy2(quarantine_path, original_path)
            
            # Clean up quarantine
            quarantine_path.unlink()
            meta_path.unlink()
            
            action.status = ActionStatus.COMPLETED
            action.result = f"File restored to: {original_path}"
            action.metadata["restored_to"] = str(original_path)
            
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
        
        action.completed_at = datetime.now()
        self._save_action(action)
        self._notify(action)
        
        return action
