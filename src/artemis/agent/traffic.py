# Artemis Agent - Network Traffic Monitor
"""
Network traffic capture and analysis.
Monitors all network flows, tracks per-device activity.
Requires admin privileges for packet capture.
"""

import asyncio
import ctypes
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, IPv4Address
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("artemis.agent.traffic")


def is_admin() -> bool:
    """Check if running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """Raise if not running as admin."""
    if not is_admin():
        raise PermissionError(
            "Traffic monitoring requires Administrator privileges. "
            "Run as Administrator or use 'runas /user:Administrator artemis agent start'"
        )


class Protocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


@dataclass
class NetworkFlow:
    """Represents a network connection/flow."""
    flow_id: str
    timestamp: datetime
    protocol: Protocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    process_name: str | None = None
    process_id: int | None = None
    state: str = "ESTABLISHED"
    duration_ms: int = 0
    
    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol.value,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "state": self.state,
            "duration_ms": self.duration_ms,
        }


@dataclass
class DeviceTraffic:
    """Traffic statistics for a single device."""
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    connections: int = 0
    dns_queries: list[str] = field(default_factory=list)
    destinations: dict[str, int] = field(default_factory=dict)  # dst_ip -> bytes
    ports_used: set[int] = field(default_factory=set)
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    alerts: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "connections": self.connections,
            "dns_queries": self.dns_queries[-50:],  # Last 50
            "top_destinations": dict(sorted(self.destinations.items(), key=lambda x: -x[1])[:10]),
            "ports_used": list(self.ports_used)[:20],
            "last_seen": self.last_seen.isoformat(),
            "alerts": self.alerts[-10:],
        }


# Well-known ports for service identification
KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5061: "SIPS", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    27017: "MongoDB", 5353: "mDNS", 1900: "SSDP",
}

# Suspicious ports that might indicate threats
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777,  # Common backdoor ports
    31337,  # Elite/Back Orifice
    12345, 12346,  # NetBus
    20034,  # NetBus 2
    1234, 1243,  # SubSeven
    3127, 3128,  # MyDoom
    6667, 6668, 6669,  # IRC (often used by botnets)
    9001, 9030, 9050, 9051,  # Tor
}


class TrafficMonitor:
    """
    Monitors network traffic across all interfaces.
    Tracks per-device activity and detects anomalies.
    """
    
    def __init__(
        self,
        interface: str | None = None,
        log_dir: Path | None = None,
        capture_dns: bool = True,
        local_subnet: str | None = None,
    ):
        """
        Initialize traffic monitor.
        
        Args:
            interface: Network interface to monitor (None = all)
            log_dir: Directory for traffic logs
            capture_dns: Capture and log DNS queries
            local_subnet: Local subnet (e.g., "192.168.1.0/24")
        """
        self.interface = interface
        self.log_dir = log_dir or (Path.home() / ".artemis" / "traffic")
        self.capture_dns = capture_dns
        self.local_subnet = local_subnet
        
        self._running = False
        self._device_traffic: dict[str, DeviceTraffic] = {}
        self._active_flows: dict[str, NetworkFlow] = {}
        self._dns_cache: dict[str, str] = {}  # IP -> hostname
        self._callbacks: list[Callable] = []
        
        # Stats
        self._total_bytes = 0
        self._total_packets = 0
        self._start_time: datetime | None = None
        
    async def start(self) -> None:
        """Start traffic monitoring."""
        require_admin()
        
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Starting traffic monitor")
        
        # Start monitoring tasks
        await asyncio.gather(
            self._monitor_netstat(),
            self._monitor_etw_dns(),
            self._monitor_connections(),
        )
        
    async def stop(self) -> None:
        """Stop traffic monitoring."""
        self._running = False
        await self._save_traffic_log()
        logger.info("Traffic monitor stopped")
        
    def on_flow(self, callback: Callable) -> None:
        """Register callback for new flows."""
        self._callbacks.append(callback)
        
    async def _monitor_netstat(self) -> None:
        """
        Monitor network connections via netstat.
        This is the most compatible approach on Windows.
        """
        logger.info("Starting netstat connection monitor")
        
        while self._running:
            try:
                # Get TCP connections with process info
                result = subprocess.run(
                    ["netstat", "-ano", "-p", "TCP"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                await self._parse_netstat_output(result.stdout, Protocol.TCP)
                
                # Get UDP connections
                result = subprocess.run(
                    ["netstat", "-ano", "-p", "UDP"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                await self._parse_netstat_output(result.stdout, Protocol.UDP)
                
            except Exception as e:
                logger.debug(f"Netstat error: {e}")
                
            await asyncio.sleep(2.0)  # Poll every 2 seconds
            
    async def _parse_netstat_output(self, output: str, protocol: Protocol) -> None:
        """Parse netstat output and update flows."""
        for line in output.splitlines():
            try:
                parts = line.split()
                if len(parts) < 4:
                    continue
                    
                # Skip header lines
                if parts[0] in ("Active", "Proto", "TCP", "UDP") and len(parts) < 5:
                    continue
                    
                if parts[0] not in ("TCP", "UDP"):
                    continue
                    
                local_addr = parts[1]
                foreign_addr = parts[2]
                
                # Parse addresses
                if ":" in local_addr:
                    local_ip, local_port = local_addr.rsplit(":", 1)
                else:
                    continue
                    
                if ":" in foreign_addr:
                    foreign_ip, foreign_port = foreign_addr.rsplit(":", 1)
                else:
                    continue
                    
                # Skip listening sockets and local-only
                if foreign_ip in ("0.0.0.0", "*", "[::]", "[::1]", "127.0.0.1"):
                    continue
                    
                try:
                    local_port = int(local_port)
                    foreign_port = int(foreign_port)
                except ValueError:
                    continue
                    
                # Get state and PID
                state = "ESTABLISHED"
                pid = None
                
                if protocol == Protocol.TCP and len(parts) >= 5:
                    state = parts[3]
                    try:
                        pid = int(parts[4])
                    except (ValueError, IndexError):
                        pass
                elif protocol == Protocol.UDP and len(parts) >= 4:
                    try:
                        pid = int(parts[3])
                    except ValueError:
                        pass
                        
                # Create flow ID
                flow_id = f"{protocol.value}:{local_ip}:{local_port}-{foreign_ip}:{foreign_port}"
                
                # Update or create flow
                if flow_id not in self._active_flows:
                    flow = NetworkFlow(
                        flow_id=flow_id,
                        timestamp=datetime.now(timezone.utc),
                        protocol=protocol,
                        src_ip=local_ip.strip("[]"),
                        src_port=local_port,
                        dst_ip=foreign_ip.strip("[]"),
                        dst_port=foreign_port,
                        process_id=pid,
                        state=state,
                    )
                    
                    # Get process name
                    if pid:
                        flow.process_name = await self._get_process_name(pid)
                        
                    self._active_flows[flow_id] = flow
                    
                    # Update device traffic
                    await self._update_device_traffic(flow)
                    
                    # Check for suspicious activity
                    await self._check_suspicious(flow)
                    
                    # Notify callbacks
                    for callback in self._callbacks:
                        try:
                            await callback(flow)
                        except Exception as e:
                            logger.debug(f"Flow callback error: {e}")
                else:
                    # Update existing flow
                    self._active_flows[flow_id].state = state
                    
            except Exception as e:
                logger.debug(f"Parse error: {e}")
                
    async def _get_process_name(self, pid: int) -> str | None:
        """Get process name from PID."""
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stdout.strip():
                parts = result.stdout.strip().split(",")
                if parts:
                    return parts[0].strip('"')
        except Exception:
            pass
        return None
        
    async def _update_device_traffic(self, flow: NetworkFlow) -> None:
        """Update device traffic statistics."""
        # Track local device
        if self._is_local_ip(flow.src_ip):
            device_ip = flow.src_ip
            is_outbound = True
        else:
            device_ip = flow.dst_ip
            is_outbound = False
            
        if device_ip not in self._device_traffic:
            self._device_traffic[device_ip] = DeviceTraffic(ip_address=device_ip)
            
        device = self._device_traffic[device_ip]
        device.connections += 1
        device.last_seen = datetime.now(timezone.utc)
        
        if is_outbound:
            device.destinations[flow.dst_ip] = device.destinations.get(flow.dst_ip, 0) + 1
            device.ports_used.add(flow.dst_port)
        else:
            device.ports_used.add(flow.src_port)
            
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is on local network."""
        try:
            addr = ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
            
    async def _check_suspicious(self, flow: NetworkFlow) -> None:
        """Check for suspicious network activity."""
        alerts = []
        
        # Check for suspicious ports
        if flow.dst_port in SUSPICIOUS_PORTS:
            alerts.append({
                "type": "suspicious_port",
                "severity": "HIGH",
                "message": f"Connection to suspicious port {flow.dst_port}",
                "flow_id": flow.flow_id,
            })
            
        # Check for potential C2 (connections to uncommon ports)
        if flow.dst_port > 10000 and flow.dst_port not in KNOWN_PORTS:
            # Could be C2, flag for review
            device_ip = flow.src_ip if self._is_local_ip(flow.src_ip) else flow.dst_ip
            if device_ip in self._device_traffic:
                device = self._device_traffic[device_ip]
                # If device has many connections to high ports, suspicious
                high_ports = [p for p in device.ports_used if p > 10000]
                if len(high_ports) > 5:
                    alerts.append({
                        "type": "potential_c2",
                        "severity": "MEDIUM",
                        "message": f"Multiple connections to high ports from {device_ip}",
                    })
                    
        # Check for port scanning behavior
        device_ip = flow.src_ip if self._is_local_ip(flow.src_ip) else flow.dst_ip
        if device_ip in self._device_traffic:
            device = self._device_traffic[device_ip]
            if len(device.ports_used) > 20:  # Many different ports
                if len(device.destinations) < 3:  # But few destinations
                    alerts.append({
                        "type": "port_scan",
                        "severity": "HIGH",
                        "message": f"Potential port scan from {device_ip}",
                    })
                    
        # Log alerts
        for alert in alerts:
            logger.warning(f"[{alert['severity']}] {alert['message']}")
            if device_ip in self._device_traffic:
                self._device_traffic[device_ip].alerts.append({
                    **alert,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                
    async def _monitor_etw_dns(self) -> None:
        """
        Monitor DNS queries via ETW (Event Tracing for Windows).
        Captures all DNS lookups on the system.
        """
        if not self.capture_dns:
            return
            
        logger.info("Starting DNS monitor via PowerShell")
        
        # Use PowerShell to get DNS client cache and events
        while self._running:
            try:
                ps_script = '''
Get-DnsClientCache | Select-Object Entry, Data, TimeToLive | 
    ConvertTo-Json -Compress
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
                            
                        for entry in data:
                            hostname = entry.get("Entry", "")
                            ip = entry.get("Data", "")
                            
                            if hostname and ip:
                                self._dns_cache[ip] = hostname
                                
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"DNS monitor error: {e}")
                
            await asyncio.sleep(10.0)  # Poll every 10 seconds
            
    async def _monitor_connections(self) -> None:
        """
        Monitor connection statistics using PowerShell Get-NetTCPConnection.
        More detailed than netstat on modern Windows.
        """
        logger.info("Starting connection monitor")
        
        while self._running:
            try:
                ps_script = '''
Get-NetTCPConnection -State Established,TimeWait,CloseWait 2>$null |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
                  State, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    ConvertTo-Json -Compress
'''
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                if result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                            
                        for conn in data:
                            remote_ip = conn.get("RemoteAddress", "")
                            
                            # Skip local/loopback
                            if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                                continue
                                
                            local_ip = conn.get("LocalAddress", "")
                            local_port = conn.get("LocalPort", 0)
                            remote_port = conn.get("RemotePort", 0)
                            pid = conn.get("OwningProcess")
                            proc_name = conn.get("ProcessName")
                            state = conn.get("State", "ESTABLISHED")
                            
                            flow_id = f"tcp:{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                            
                            if flow_id not in self._active_flows:
                                flow = NetworkFlow(
                                    flow_id=flow_id,
                                    timestamp=datetime.now(timezone.utc),
                                    protocol=Protocol.TCP,
                                    src_ip=local_ip,
                                    src_port=local_port,
                                    dst_ip=remote_ip,
                                    dst_port=remote_port,
                                    process_id=pid,
                                    process_name=proc_name,
                                    state=state,
                                )
                                
                                self._active_flows[flow_id] = flow
                                await self._update_device_traffic(flow)
                                
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Connection monitor error: {e}")
                
            await asyncio.sleep(5.0)
            
    async def _save_traffic_log(self) -> None:
        """Save traffic log to file."""
        if not self._device_traffic:
            return
            
        log_file = self.log_dir / f"traffic_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
        
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": (datetime.now(timezone.utc) - self._start_time).total_seconds() if self._start_time else 0,
            "total_flows": len(self._active_flows),
            "devices": {ip: device.to_dict() for ip, device in self._device_traffic.items()},
        }
        
        log_file.write_text(json.dumps(data, indent=2))
        logger.info(f"Traffic log saved: {log_file}")
        
    @property
    def devices(self) -> dict[str, DeviceTraffic]:
        """Get all device traffic stats."""
        return self._device_traffic
        
    @property
    def active_flows(self) -> list[NetworkFlow]:
        """Get active flows."""
        return list(self._active_flows.values())
        
    @property
    def dns_cache(self) -> dict[str, str]:
        """Get DNS cache (IP -> hostname)."""
        return self._dns_cache
        
    def get_device_traffic(self, ip: str) -> DeviceTraffic | None:
        """Get traffic stats for a device."""
        return self._device_traffic.get(ip)
        
    def get_top_talkers(self, limit: int = 10) -> list[DeviceTraffic]:
        """Get devices with most traffic."""
        return sorted(
            self._device_traffic.values(),
            key=lambda d: d.bytes_sent + d.bytes_recv,
            reverse=True,
        )[:limit]


class PacketCapture:
    """
    Raw packet capture using Windows raw sockets.
    Requires admin privileges.
    """
    
    def __init__(self, interface: str | None = None):
        """
        Initialize packet capture.
        
        Args:
            interface: Interface IP to capture on (None = primary)
        """
        require_admin()
        self.interface = interface
        self._socket = None
        self._running = False
        
    async def start(self) -> None:
        """Start packet capture."""
        # Get interface to bind to
        if not self.interface:
            self.interface = socket.gethostbyname(socket.gethostname())
            
        logger.info(f"Starting packet capture on {self.interface}")
        
        # Create raw socket
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._socket.bind((self.interface, 0))
            
            # Set to promiscuous mode
            self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self._running = True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            raise
            
    async def stop(self) -> None:
        """Stop packet capture."""
        self._running = False
        if self._socket:
            try:
                self._socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self._socket.close()
            except Exception:
                pass
                
    async def capture(self) -> AsyncIterator[dict]:
        """Capture and yield packets."""
        while self._running:
            try:
                # Receive packet
                data = self._socket.recvfrom(65535)[0]
                
                # Parse IP header
                ip_header = data[:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                
                packet = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "length": len(data),
                }
                
                # Parse TCP/UDP for ports
                if protocol == 6:  # TCP
                    tcp_header = data[20:40]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    packet["src_port"] = tcph[0]
                    packet["dst_port"] = tcph[1]
                    packet["protocol_name"] = "TCP"
                elif protocol == 17:  # UDP
                    udp_header = data[20:28]
                    udph = struct.unpack('!HHHH', udp_header)
                    packet["src_port"] = udph[0]
                    packet["dst_port"] = udph[1]
                    packet["protocol_name"] = "UDP"
                elif protocol == 1:  # ICMP
                    packet["protocol_name"] = "ICMP"
                else:
                    packet["protocol_name"] = f"OTHER({protocol})"
                    
                yield packet
                
            except Exception as e:
                if self._running:
                    logger.debug(f"Capture error: {e}")
                await asyncio.sleep(0.01)


# AsyncIterator type for type hints
from typing import AsyncIterator
