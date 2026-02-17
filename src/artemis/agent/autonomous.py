"""
Artemis Autonomous Security Agent
The All-Seeing Eye - Continuous monitoring, AI analysis, and threat response.

Features:
- Network device discovery and mapping
- Real-time connection monitoring
- Traffic analysis per device
- AI-powered threat detection
- Keyboard/mouse/process telemetry
- File scanning and threat hunting
- Automated remediation with integrity validation
"""

import asyncio
import json
import logging
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Optional
from collections import defaultdict

import psutil

logger = logging.getLogger("artemis.agent.autonomous")


class AutonomousAgent:
    """
    The autonomous security agent that provides complete visibility.
    
    Features:
    - Network device discovery and mapping
    - Real-time connection monitoring
    - Traffic analysis per device
    - AI-powered threat detection with integrity validation
    - Full endpoint telemetry (keyboard, mouse, processes)
    - Continuous file scanning
    - Automated remediation
    """
    
    def __init__(
        self,
        model: str = "deepseek-r1:70b",
        provider: str = "ollama",
        scan_interval: float = 30.0,
        connection_interval: float = 2.0,
        analysis_interval: float = 10.0,
        enable_telemetry: bool = True,
        enable_file_scanning: bool = True,
    ):
        self.model = model
        self.provider = provider
        self.scan_interval = scan_interval
        self.connection_interval = connection_interval
        self.analysis_interval = analysis_interval
        self.enable_telemetry = enable_telemetry
        self.enable_file_scanning = enable_file_scanning
        
        self._running = False
        self._start_time: Optional[datetime] = None
        
        # State
        self.devices: dict[str, dict] = {}
        self.connections: list[dict] = []
        self.threats: list[dict] = []
        self.traffic_stats: dict = defaultdict(lambda: {"bytes_in": 0, "bytes_out": 0})
        
        # Callbacks for UI integration
        self._on_device_update: list[callable] = []
        self._on_connection: list[callable] = []
        self._on_threat: list[callable] = []
        self._on_ai_analysis: list[callable] = []
        self._on_traffic: list[callable] = []
        
        # AI analysis queue
        self._analysis_queue: asyncio.Queue = asyncio.Queue()
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "threats_detected": 0,
            "scans_completed": 0,
            "ai_analyses": 0,
            "files_scanned": 0,
            "integrity_checks": 0,
        }
        
        # Sub-components (initialized on start)
        self.telemetry = None
        self.scanner = None
        self.remediation = None
    
    @property
    def uptime(self) -> float:
        if not self._start_time:
            return 0
        return (datetime.now(timezone.utc) - self._start_time).total_seconds()
    
    async def start(self):
        """Start the autonomous agent."""
        if self._running:
            return
        
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        
        logger.info("=" * 60)
        logger.info("ARTEMIS AUTONOMOUS AGENT STARTING")
        logger.info(f"Model: {self.provider}/{self.model}")
        logger.info(f"Hostname: {socket.gethostname()}")
        logger.info(f"Telemetry: {'enabled' if self.enable_telemetry else 'disabled'}")
        logger.info(f"File Scanning: {'enabled' if self.enable_file_scanning else 'disabled'}")
        logger.info("=" * 60)
        
        # Initialize sub-components
        try:
            if self.enable_telemetry:
                from .telemetry import EndpointTelemetry
                self.telemetry = EndpointTelemetry(
                    enable_keyboard=True,
                    enable_mouse=True,
                    enable_processes=True,
                    enable_services=True,
                )
                await self.telemetry.start()
                logger.info("Endpoint telemetry started")
        except ImportError:
            logger.warning("Telemetry module not available")
        except Exception as e:
            logger.error(f"Failed to start telemetry: {e}")
        
        try:
            if self.enable_file_scanning:
                from .scanner import FileScanner
                self.scanner = FileScanner(
                    model=self.model,
                    provider=self.provider,
                    enable_ai_analysis=True,
                )
                # Register scanner callbacks
                self.scanner.on_malicious(self._on_malicious_file)
                self.scanner.on_suspicious(self._on_suspicious_file)
                logger.info("File scanner initialized")
        except ImportError:
            logger.warning("Scanner module not available")
        except Exception as e:
            logger.error(f"Failed to initialize scanner: {e}")
        
        try:
            from .remediation import RemediationEngine
            self.remediation = RemediationEngine(
                model=self.model,
                provider=self.provider,
            )
            logger.info("Remediation engine initialized")
        except ImportError:
            logger.warning("Remediation module not available")
        except Exception as e:
            logger.error(f"Failed to initialize remediation: {e}")
        
        # Start monitoring tasks
        asyncio.create_task(self._network_scan_loop())
        asyncio.create_task(self._connection_monitor_loop())
        asyncio.create_task(self._traffic_monitor_loop())
        asyncio.create_task(self._ai_analysis_loop())
        
        logger.info("All monitoring tasks started")
    
    async def _on_malicious_file(self, result):
        """Handle malicious file detection."""
        self.stats["threats_detected"] += 1
        threat = {
            "id": f"file_{len(self.threats)}",
            "title": f"Malicious File: {result.threat_name}",
            "description": f"File: {result.filename}, Confidence: {result.confidence:.0%}",
            "severity": "high",
            "source": "file_scanner",
            "indicators": result.indicators,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.threats.append(threat)
        
        for cb in self._on_threat:
            try:
                await cb(threat)
            except Exception:
                pass
    
    async def _on_suspicious_file(self, result):
        """Handle suspicious file detection."""
        # Queue for AI analysis
        await self._analysis_queue.put({
            "type": "file",
            "data": {
                "path": result.path,
                "filename": result.filename,
                "indicators": result.indicators,
                "entropy": result.entropy,
            }
        })
    
    async def stop(self):
        """Stop the autonomous agent."""
        self._running = False
        logger.info("Agent stopped")
    
    # =========================================================================
    # NETWORK DISCOVERY
    # =========================================================================
    
    async def _network_scan_loop(self):
        """Continuous network scanning."""
        while self._running:
            try:
                await self._scan_network()
                self.stats["scans_completed"] += 1
            except Exception as e:
                logger.error(f"Network scan error: {e}")
            
            await asyncio.sleep(self.scan_interval)
    
    async def _scan_network(self):
        """Scan local network for devices with fingerprinting."""
        logger.info("Starting network scan...")
        
        # Get local network info
        local_ip = self._get_local_ip()
        if not local_ip:
            return
        
        # Determine subnet
        parts = local_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
        
        # ARP scan for fast discovery
        discovered = await self._arp_scan(subnet)
        
        # Import fingerprinting module
        try:
            from .fingerprint import fingerprint_device, classify_device
            has_fingerprint = True
        except ImportError:
            has_fingerprint = False
        
        # Update devices with fingerprinting
        for device in discovered:
            device_id = device.get("mac") or device.get("ip")
            if device_id:
                existing = self.devices.get(device_id, {})
                
                # Run fingerprinting for better device identification
                if has_fingerprint and device.get("ip"):
                    try:
                        # Full fingerprint with port scan (only for new/unknown devices)
                        if existing.get("device_type") in (None, "unknown"):
                            fp = await fingerprint_device(
                                ip=device["ip"],
                                mac=device.get("mac", ""),
                                hostname=device.get("hostname"),
                            )
                            device["device_type"] = fp.device_type
                            device["vendor"] = fp.vendor
                            device["model"] = fp.model
                            device["services"] = fp.services
                            device["confidence"] = fp.confidence
                        else:
                            # Quick classify without port scan for known devices
                            fp = classify_device(
                                mac=device.get("mac", ""),
                                ip=device["ip"],
                                hostname=device.get("hostname"),
                            )
                            if fp.confidence > existing.get("confidence", 0):
                                device["device_type"] = fp.device_type
                                device["vendor"] = fp.vendor
                                device["model"] = fp.model
                                device["confidence"] = fp.confidence
                    except Exception as e:
                        logger.debug(f"Fingerprint failed for {device['ip']}: {e}")
                
                device = {**existing, **device}
                device["last_seen"] = datetime.now(timezone.utc).isoformat()
                self.devices[device_id] = device
                
                # Notify callbacks
                for cb in self._on_device_update:
                    try:
                        await cb(device_id, device)
                    except Exception as e:
                        logger.error(f"Device callback error: {e}")
        
        logger.info(f"Network scan complete: {len(self.devices)} devices")
    
    def _get_local_ip(self) -> Optional[str]:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
    
    async def _arp_scan(self, subnet: str) -> list[dict]:
        """Perform ARP scan of subnet."""
        devices = []
        
        if platform.system() == "Windows":
            # Use arp -a on Windows (run in executor to avoid blocking event loop)
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["arp", "-a"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                )
                
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line or "Interface" in line or "Internet" in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").upper()
                        
                        if ip.startswith(subnet):
                            device_type = self._identify_device_type(mac, ip)
                            hostname = await self._resolve_hostname(ip)
                            
                            devices.append({
                                "ip": ip,
                                "mac": mac,
                                "hostname": hostname,
                                "device_type": device_type,
                                "vendor": self._get_mac_vendor(mac),
                            })
            except Exception as e:
                logger.error(f"ARP scan failed: {e}")
        
        # Also add local machine
        local_ip = self._get_local_ip()
        if local_ip:
            devices.append({
                "ip": local_ip,
                "mac": self._get_local_mac(),
                "hostname": socket.gethostname(),
                "device_type": "desktop",
                "vendor": "Local",
                "is_local": True,
            })
        
        return devices
    
    def _get_local_mac(self) -> str:
        """Get local MAC address."""
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family.name == "AF_LINK":
                        mac = addr.address
                        if mac and mac != "00:00:00:00:00:00":
                            return mac.upper()
        except Exception:
            pass
        return "00:00:00:00:00:00"
    
    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname."""
        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyaddr, ip
                ),
                timeout=2.0
            )
            return result[0]
        except Exception:
            return None
    
    def _identify_device_type(self, mac: str, ip: str) -> str:
        """Identify device type from MAC OUI (basic fallback)."""
        try:
            from .fingerprint import classify_device
            fp = classify_device(mac=mac, ip=ip)
            return fp.device_type
        except ImportError:
            pass
        
        # Fallback
        vendor = self._get_mac_vendor(mac).lower()
        if any(x in vendor for x in ["apple"]):
            return "mobile"
        elif any(x in vendor for x in ["samsung", "xiaomi"]):
            return "mobile"
        elif any(x in vendor for x in ["cisco", "ubiquiti", "netgear", "tp-link", "asus"]):
            return "router" if ip.endswith(".1") else "network"
        elif any(x in vendor for x in ["dell", "hp", "lenovo", "intel"]):
            return "desktop"
        elif any(x in vendor for x in ["amazon", "google", "sonos"]):
            return "smart_device"
        elif any(x in vendor for x in ["vmware", "microsoft"]):
            return "server"
        return "unknown"
    
    def _get_mac_vendor(self, mac: str) -> str:
        """Get vendor from MAC OUI."""
        try:
            from .fingerprint import get_vendor_from_mac
            vendor, _ = get_vendor_from_mac(mac)
            return vendor
        except ImportError:
            pass
        
        # Basic fallback
        oui = mac[:8].upper().replace(":", "-")
        vendors = {
            "00-50-56": "VMware",
            "00-0C-29": "VMware",
            "AC-BC-32": "Apple",
            "00-17-88": "Philips Hue",
            "B8-27-EB": "Raspberry Pi",
        }
        return vendors.get(oui, "Unknown")
    
    # =========================================================================
    # CONNECTION MONITORING
    # =========================================================================
    
    async def _connection_monitor_loop(self):
        """Monitor network connections."""
        previous_conns = set()
        
        while self._running:
            try:
                current = []
                
                for conn in psutil.net_connections(kind="inet"):
                    if conn.status in ("ESTABLISHED", "LISTEN"):
                        try:
                            proc_name = "unknown"
                            if conn.pid:
                                try:
                                    proc_name = psutil.Process(conn.pid).name()
                                except Exception:
                                    pass
                            
                            conn_data = {
                                "pid": conn.pid,
                                "process": proc_name,
                                "local_addr": conn.laddr.ip if conn.laddr else "",
                                "local_port": conn.laddr.port if conn.laddr else 0,
                                "remote_addr": conn.raddr.ip if conn.raddr else None,
                                "remote_port": conn.raddr.port if conn.raddr else None,
                                "state": conn.status,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            
                            current.append(conn_data)
                            
                            # Check if new connection
                            conn_key = f"{conn.pid}:{conn.laddr}:{conn.raddr}"
                            if conn_key not in previous_conns:
                                previous_conns.add(conn_key)
                                self.stats["events_processed"] += 1
                                
                                # Notify callbacks
                                for cb in self._on_connection:
                                    try:
                                        await cb(conn_data)
                                    except Exception:
                                        pass
                                
                                # Queue for AI analysis if suspicious
                                if self._is_suspicious_connection(conn_data):
                                    await self._analysis_queue.put({
                                        "type": "connection",
                                        "data": conn_data,
                                    })
                        except Exception:
                            pass
                
                self.connections = current
                
            except Exception as e:
                logger.error(f"Connection monitor error: {e}")
            
            await asyncio.sleep(self.connection_interval)
    
    def _is_suspicious_connection(self, conn: dict) -> bool:
        """Check if connection is suspicious."""
        # Suspicious ports
        suspicious_ports = {4444, 5555, 6666, 31337, 12345, 1234, 9999}
        
        if conn.get("remote_port") in suspicious_ports:
            return True
        
        # System processes making external connections
        suspicious_procs = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}
        if conn.get("process", "").lower() in suspicious_procs:
            if conn.get("remote_addr") and conn.get("remote_port") in {80, 443}:
                return True
        
        return False
    
    # =========================================================================
    # TRAFFIC MONITORING
    # =========================================================================
    
    async def _traffic_monitor_loop(self):
        """Monitor network traffic statistics."""
        prev_stats = psutil.net_io_counters()
        
        while self._running:
            try:
                await asyncio.sleep(1.0)
                
                current = psutil.net_io_counters()
                
                traffic = {
                    "bytes_in": current.bytes_recv,
                    "bytes_out": current.bytes_sent,
                    "packets_in": current.packets_recv,
                    "packets_out": current.packets_sent,
                    "bytes_in_rate": current.bytes_recv - prev_stats.bytes_recv,
                    "bytes_out_rate": current.bytes_sent - prev_stats.bytes_sent,
                    "connections_active": len(self.connections),
                }
                
                prev_stats = current
                
                # Notify callbacks
                for cb in self._on_traffic:
                    try:
                        await cb(traffic)
                    except Exception:
                        pass
                
            except Exception as e:
                logger.error(f"Traffic monitor error: {e}")
    
    # =========================================================================
    # AI ANALYSIS
    # =========================================================================
    
    async def _ai_analysis_loop(self):
        """Process items in analysis queue with AI."""
        while self._running:
            try:
                # Get item from queue (with timeout)
                try:
                    item = await asyncio.wait_for(
                        self._analysis_queue.get(),
                        timeout=self.analysis_interval
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Analyze with AI
                result = await self._analyze_with_ai(item)
                self.stats["ai_analyses"] += 1
                
                # Notify callbacks
                for cb in self._on_ai_analysis:
                    try:
                        await cb(result)
                    except Exception:
                        pass
                
                # If threat detected, add to threats
                if result.get("verdict") in ("suspicious", "threat"):
                    threat = {
                        "title": result.get("title", "Potential Threat"),
                        "description": result.get("summary", ""),
                        "severity": "high" if result["verdict"] == "threat" else "medium",
                        "source": item,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    self.threats.append(threat)
                    self.stats["threats_detected"] += 1
                    
                    for cb in self._on_threat:
                        try:
                            await cb(threat)
                        except Exception:
                            pass
                
            except Exception as e:
                logger.error(f"AI analysis error: {e}")
    
    async def _analyze_with_ai(self, item: dict) -> dict:
        """Analyze item with AI model."""
        try:
            import httpx
            
            prompt = self._build_analysis_prompt(item)
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                    timeout=60.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_ai_response(data.get("response", ""), item)
        except Exception as e:
            logger.error(f"AI request failed: {e}")
        
        return {
            "verdict": "clean",
            "summary": "Unable to analyze",
            "target": str(item.get("type", "unknown")),
        }
    
    def _build_analysis_prompt(self, item: dict) -> str:
        """Build AI analysis prompt."""
        item_type = item.get("type", "unknown")
        data = item.get("data", {})
        
        if item_type == "connection":
            return f"""Analyze this network connection for security threats:
Process: {data.get('process')}
Remote: {data.get('remote_addr')}:{data.get('remote_port')}
Local Port: {data.get('local_port')}
State: {data.get('state')}

Respond with JSON:
{{"verdict": "clean|suspicious|threat", "summary": "brief explanation", "confidence": 0.0-1.0}}"""
        
        return f"Analyze for security threats: {json.dumps(data)}"
    
    def _parse_ai_response(self, response: str, item: dict) -> dict:
        """Parse AI response."""
        try:
            # Try to extract JSON
            import re
            match = re.search(r'\{[^}]+\}', response)
            if match:
                result = json.loads(match.group())
                result["target"] = str(item.get("type", "unknown"))
                return result
        except Exception:
            pass
        
        # Default response
        return {
            "verdict": "clean",
            "summary": response[:200] if response else "No analysis",
            "target": str(item.get("type", "unknown")),
        }
    
    # =========================================================================
    # CALLBACK REGISTRATION
    # =========================================================================
    
    def on_device_update(self, callback):
        self._on_device_update.append(callback)
    
    def on_connection(self, callback):
        self._on_connection.append(callback)
    
    def on_threat(self, callback):
        self._on_threat.append(callback)
    
    def on_ai_analysis(self, callback):
        self._on_ai_analysis.append(callback)
    
    def on_traffic(self, callback):
        self._on_traffic.append(callback)
    
    def get_status(self) -> dict:
        """Get agent status."""
        status = {
            "running": self._running,
            "uptime": self.uptime,
            "model": f"{self.provider}/{self.model}",
            "devices": len(self.devices),
            "connections": len(self.connections),
            "threats": len(self.threats),
            "telemetry_active": self.telemetry is not None,
            "scanner_active": self.scanner is not None,
            "remediation_active": self.remediation is not None,
            **self.stats,
        }
        
        # Add telemetry summary if available
        if self.telemetry:
            status["telemetry"] = self.telemetry.get_activity_summary()
        
        # Add scanner summary if available
        if self.scanner:
            status["scanner"] = self.scanner.get_scan_summary()
        
        return status
    
    async def scan_now(self, paths: list[str] = None) -> dict:
        """Trigger immediate file scan."""
        if not self.scanner:
            return {"error": "Scanner not initialized"}
        
        try:
            stats = await self.scanner.scan_paths(paths or [])
            self.stats["scans_completed"] += 1
            self.stats["files_scanned"] += stats.files_scanned
            return stats.__dict__
        except Exception as e:
            return {"error": str(e)}
    
    def get_telemetry_data(self) -> dict:
        """Get current telemetry data."""
        if not self.telemetry:
            return {"error": "Telemetry not active"}
        
        return {
            "keystrokes": self.telemetry.get_recent_keystrokes(50),
            "mouse": self.telemetry.get_recent_mouse(20),
            "processes": self.telemetry.get_recent_processes(30),
            "services": self.telemetry.get_recent_services(10),
            "summary": self.telemetry.get_activity_summary(),
        }
    
    async def remediate_threat(self, threat_id: str, action: str, auto: bool = False) -> dict:
        """Remediate a detected threat."""
        if not self.remediation:
            return {"error": "Remediation engine not initialized"}
        
        # Find threat
        threat = next((t for t in self.threats if t.get("id") == threat_id), None)
        if not threat:
            return {"error": "Threat not found"}
        
        try:
            from .remediation import ActionType
            action_type = ActionType(action)
            
            result = await self.remediation.create_remediation(
                threat_id=threat_id,
                action_type=action_type,
                target=threat.get("target", ""),
                auto_execute=auto,
            )
            
            return {"status": "created", "action_id": result.id}
        except Exception as e:
            return {"error": str(e)}
