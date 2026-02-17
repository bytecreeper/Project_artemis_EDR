"""
Artemis Real-Time Network Monitor
High-performance background monitoring with packet capture and AI analysis.
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
import threading

import psutil
import orjson

# Optional imports with fallbacks
try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, DNSQR, conf
    conf.use_pcap = True  # Use Npcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Use built-in fingerprint module for MAC vendors
try:
    from artemis.agent.fingerprint import MAC_VENDORS
    MAC_LOOKUP_AVAILABLE = True
    
    def _sync_mac_lookup(mac: str) -> str:
        """Synchronous MAC lookup using built-in database."""
        if not mac:
            return ""
        # Normalize MAC to XX-XX-XX format (first 3 octets)
        mac_clean = mac.upper().replace(':', '-').replace('.', '-')
        if len(mac_clean) >= 8:
            mac_prefix = mac_clean[:8]  # "XX-XX-XX"
            result = MAC_VENDORS.get(mac_prefix)
            if result:
                return result[0] if isinstance(result, tuple) else result
        return ""
except ImportError:
    MAC_LOOKUP_AVAILABLE = False
    MAC_VENDORS = {}
    _sync_mac_lookup = lambda x: ""

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger("artemis.monitor")


@dataclass
class DeviceStats:
    """Per-device statistics."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "unknown"
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    connections: int = 0
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ports_used: set = field(default_factory=set)
    dns_queries: list = field(default_factory=list)
    suspicious_score: float = 0.0


@dataclass  
class ThreatAlert:
    """Threat detection alert."""
    id: str
    timestamp: datetime
    severity: str  # critical, high, medium, low
    title: str
    description: str
    source_ip: str = ""
    dest_ip: str = ""
    indicator: str = ""
    category: str = ""  # malware, intrusion, anomaly, policy


class NetworkMonitor:
    """
    High-performance network monitor with packet capture.
    Runs background threads for continuous monitoring.
    """
    
    # Suspicious ports that might indicate threats
    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 7777, 31337, 12345, 12346,  # Backdoors
        1337, 1234, 54321,  # Common RAT ports
        6667, 6668, 6669,  # IRC (botnets)
        9001, 9030, 9050, 9051,  # Tor
        3389,  # RDP (if unexpected)
        445, 139,  # SMB (lateral movement)
    }
    
    # Suspicious process names
    SUSPICIOUS_PROCESSES = {
        'nc', 'nc.exe', 'ncat', 'ncat.exe', 'netcat',
        'mimikatz', 'mimi.exe', 'sekurlsa',
        'psexec', 'psexec.exe', 'psexec64.exe',
        'wmiexec', 'smbexec', 'atexec',
        'evil-winrm', 'chisel', 'ligolo',
        'cobaltstrike', 'beacon', 'meterpreter',
        'powershell_ise',  # Can be suspicious in some contexts
    }
    
    def __init__(self, local_network: str = "192.168.1.0/24"):
        self.local_network = local_network
        self.local_prefix = ".".join(local_network.split("/")[0].split(".")[:3]) + "."
        
        # State
        self.devices: dict[str, DeviceStats] = {}
        self.connections: list[dict] = []
        self.threats: list[ThreatAlert] = []
        self.dns_cache: dict[str, str] = {}  # IP -> hostname
        self.traffic_stats = {
            "bytes_in": 0, "bytes_out": 0,
            "packets_in": 0, "packets_out": 0,
            "connections_active": 0,
        }
        
        # Process name cache
        self._process_cache: dict[int, str] = {}
        self._process_cache_time: dict[int, float] = {}
        
        # Callbacks
        self._on_device: Optional[Callable] = None
        self._on_threat: Optional[Callable] = None
        self._on_connection: Optional[Callable] = None
        
        # Threading
        self._running = False
        self._lock = threading.Lock()
        self._packet_thread: Optional[threading.Thread] = None
        
    def start(self):
        """Start background monitoring."""
        self._running = True
        
        # Start packet capture in background thread
        if SCAPY_AVAILABLE:
            self._packet_thread = threading.Thread(target=self._packet_capture_loop, daemon=True)
            self._packet_thread.start()
            logger.info("Packet capture started")
        else:
            logger.warning("Scapy not available - packet capture disabled")
    
    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._packet_thread:
            self._packet_thread.join(timeout=2)
    
    def on_device(self, callback: Callable):
        """Register callback for device updates."""
        self._on_device = callback
    
    def on_threat(self, callback: Callable):
        """Register callback for threat alerts."""
        self._on_threat = callback
    
    def on_connection(self, callback: Callable):
        """Register callback for new connections."""
        self._on_connection = callback
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name with caching."""
        now = time.time()
        
        # Check cache (valid for 30 seconds)
        if pid in self._process_cache:
            if now - self._process_cache_time.get(pid, 0) < 30:
                return self._process_cache[pid]
        
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            self._process_cache[pid] = name
            self._process_cache_time[pid] = now
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return str(pid)
    
    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname with caching."""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        if DNS_AVAILABLE:
            try:
                addr = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(addr, "PTR", lifetime=1)
                hostname = str(answers[0]).rstrip('.')
                self.dns_cache[ip] = hostname
                return hostname
            except Exception:
                pass
        
        self.dns_cache[ip] = ip
        return ip
    
    def _lookup_vendor(self, mac: str) -> str:
        """Look up MAC vendor (synchronous)."""
        if MAC_LOOKUP_AVAILABLE:
            try:
                return _sync_mac_lookup(mac)
            except Exception:
                pass
        return ""
    
    def _classify_device(self, vendor: str, mac: str, hostname: str, ports: set = None) -> str:
        """Classify device type based on vendor, MAC, hostname, and open ports."""
        vendor_lower = vendor.lower() if vendor else ""
        hostname_lower = hostname.lower() if hostname else ""
        mac_upper = mac.upper() if mac else ""
        ports = ports or set()
        
        # Check for locally administered MAC (randomized - mobile devices)
        if mac_upper and len(mac_upper) >= 2:
            first_byte = mac_upper[:2]
            try:
                if int(first_byte, 16) & 0x02:  # Locally administered bit set
                    return "mobile"  # Likely iPhone/Android with MAC randomization
            except ValueError:
                pass
        
        # Router/Gateway indicators (always router, no port check needed)
        router_vendors = ['eero', 'netgear', 'ubiquiti', 'linksys', 'cisco', 'mikrotik', 'arris', 'motorola']
        if any(v in vendor_lower for v in router_vendors):
            return "router"
        
        # Network devices that might be routers
        network_vendors = ['asus', 'tp-link', 'dlink', 'd-link', 'huawei', 'zyxel']
        if any(v in vendor_lower for v in network_vendors):
            if ports & {80, 443, 8080, 8443}:
                return "router"
            return "network_device"
        
        # Apple devices
        if 'apple' in vendor_lower:
            # Apple TV ports
            if ports & {3689, 5353, 7000, 7100}:
                return "streaming_device"
            # AirPlay/HomeKit
            if ports & {62078}:
                return "phone"
            # macOS AFP/SMB
            if ports & {548, 445}:
                return "desktop"
            # HomePod
            if 'homepod' in hostname_lower:
                return "smart_speaker"
            return "apple_device"
        
        # Google/Nest devices
        if any(v in vendor_lower for v in ['google', 'nest']):
            if ports & {8008, 8443, 8009}:
                return "streaming_device"  # Chromecast
            if any(h in hostname_lower for h in ['home', 'nest', 'hub', 'mini']):
                return "smart_speaker"
            return "google_device"
        
        # Amazon devices
        if 'amazon' in vendor_lower:
            if any(h in hostname_lower for h in ['echo', 'alexa', 'fire']):
                return "smart_speaker"
            if 'kindle' in hostname_lower:
                return "tablet"
            return "amazon_device"
        
        # Smart TVs
        tv_vendors = ['samsung', 'lg', 'sony', 'vizio', 'tcl', 'hisense', 'roku', 'philips']
        if any(v in vendor_lower for v in tv_vendors):
            if any(v in vendor_lower for v in ['roku']):
                return "streaming_device"
            return "smart_tv"
        
        # Gaming consoles
        if 'microsoft' in vendor_lower and ports & {3074}:
            return "gaming_console"
        if 'sony' in vendor_lower and (ports & {9295, 9296, 9297} or 'playstation' in hostname_lower):
            return "gaming_console"
        if 'nintendo' in vendor_lower:
            return "gaming_console"
        
        # Computers/Servers
        if ports & {22}:  # SSH
            return "server"
        if ports & {3389}:  # RDP
            return "desktop"
        if ports & {5900, 5901}:  # VNC
            return "desktop"
        
        # IoT devices
        iot_vendors = ['espressif', 'tuya', 'shenzhen', 'wemo', 'philips hue', 'lifx', 'ring', 
                       'wyze', 'tp-link kasa', 'eufy', 'arlo']
        if any(v in vendor_lower for v in iot_vendors):
            return "iot_device"
        
        # Mobile devices by vendor
        mobile_vendors = ['samsung', 'huawei', 'xiaomi', 'oneplus', 'oppo', 'vivo', 'realme']
        if any(v in vendor_lower for v in mobile_vendors):
            # Could be phone or tablet
            return "mobile"
        
        # Printer
        printer_vendors = ['hp', 'canon', 'epson', 'brother', 'xerox', 'lexmark']
        if any(v in vendor_lower for v in printer_vendors) or ports & {631, 9100}:
            return "printer"
        
        # ASUSTek - could be router, desktop, or phone
        if 'asus' in vendor_lower or 'asustek' in vendor_lower:
            if ports & {80, 443}:
                return "router"
            return "desktop"
        
        # Intel/Realtek - typically desktops/laptops
        if any(v in vendor_lower for v in ['intel', 'realtek']):
            return "desktop"
        
        return "unknown"
    
    def _packet_capture_loop(self):
        """Background packet capture with scapy."""
        def packet_handler(pkt):
            if not self._running:
                return
            
            try:
                self._process_packet(pkt)
            except Exception as e:
                logger.debug(f"Packet processing error: {e}")
        
        try:
            # Capture packets continuously
            sniff(prn=packet_handler, store=False, stop_filter=lambda p: not self._running)
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
    
    def _process_packet(self, pkt):
        """Process a captured packet."""
        # Handle ARP for device discovery
        if ARP in pkt:
            self._handle_arp(pkt)
            return
        
        # Handle IP packets for traffic analysis
        if IP in pkt:
            self._handle_ip_packet(pkt)
        
        # Handle DNS for query logging
        if DNS in pkt and pkt.haslayer(DNSQR):
            self._handle_dns(pkt)
    
    def _handle_arp(self, pkt):
        """Handle ARP packet for device discovery."""
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        
        if not ip.startswith(self.local_prefix):
            return
        
        with self._lock:
            if ip not in self.devices:
                vendor = self._lookup_vendor(mac)
                hostname = self._resolve_hostname(ip)
                device_type = self._classify_device(vendor, mac, hostname)
                
                device = DeviceStats(
                    ip=ip,
                    mac=mac,
                    vendor=vendor,
                    hostname=hostname,
                    device_type=device_type,
                )
                self.devices[ip] = device
                
                logger.info(f"New device: {ip} ({vendor}) -> {device_type}")
                
                if self._on_device:
                    asyncio.run_coroutine_threadsafe(
                        self._on_device(device),
                        asyncio.get_event_loop()
                    )
            else:
                # Update device type if we have more info now
                device = self.devices[ip]
                device.last_seen = datetime.now(timezone.utc)
                
                # Re-classify if still unknown and we have ports now
                if device.device_type == "unknown" and device.ports_used:
                    new_type = self._classify_device(
                        device.vendor, device.mac, device.hostname, device.ports_used
                    )
                    if new_type != "unknown":
                        device.device_type = new_type
                        logger.info(f"Reclassified {ip}: {new_type}")
    
    def _handle_ip_packet(self, pkt):
        """Handle IP packet for traffic tracking."""
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)
        
        with self._lock:
            # Update source device stats
            if src_ip in self.devices:
                self.devices[src_ip].bytes_sent += pkt_len
                self.devices[src_ip].packets_sent += 1
                self.devices[src_ip].last_seen = datetime.now(timezone.utc)
            
            # Update destination device stats
            if dst_ip in self.devices:
                self.devices[dst_ip].bytes_recv += pkt_len
                self.devices[dst_ip].packets_recv += 1
            
            # Track ports
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                if src_ip in self.devices:
                    self.devices[src_ip].ports_used.add(sport)
                if dst_ip in self.devices:
                    self.devices[dst_ip].ports_used.add(dport)
                
                # Check for suspicious ports
                if dport in self.SUSPICIOUS_PORTS:
                    self._create_threat(
                        severity="medium",
                        title=f"Connection to suspicious port {dport}",
                        description=f"Traffic from {src_ip} to {dst_ip}:{dport}",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        category="suspicious_connection",
                    )
    
    def _handle_dns(self, pkt):
        """Handle DNS query for logging."""
        query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        src_ip = pkt[IP].src if IP in pkt else ""
        
        with self._lock:
            if src_ip in self.devices:
                if len(self.devices[src_ip].dns_queries) < 100:
                    self.devices[src_ip].dns_queries.append(query)
        
        # Check for suspicious domains
        suspicious_tlds = ['.onion', '.bit', '.bazar']
        suspicious_patterns = ['c2.', '.c2.', 'c2-', '-c2.', 'command', 'control', 'beacon.', '.beacon.', 'malware', 'botnet', 'rat.', 'trojan']
        
        # Whitelist known-good domains that trigger false positives
        whitelisted_suffixes = [
            'google.com', 'gvt2.com', 'gvt1.com', 'googleapis.com', 'gstatic.com',
            'adobe.com', 'adobe.io', 'adobess.com', 'adobecc.com',
            'microsoft.com', 'msftconnecttest.com', 'windows.com', 'windowsupdate.com',
            'apple.com', 'icloud.com', 'mzstatic.com',
            'amazon.com', 'amazonaws.com', 'cloudfront.net',
            'facebook.com', 'fbcdn.net', 'instagram.com',
            'twitter.com', 'twimg.com',
            'github.com', 'githubusercontent.com',
            'cloudflare.com', 'cloudflare-dns.com',
            'akamai.com', 'akamaiedge.net', 'akamaitechnologies.com',
            'fastly.net', 'fastlylb.net',
        ]
        
        query_lower = query.lower()
        
        # Skip whitelisted domains
        if any(query_lower.endswith(suffix) for suffix in whitelisted_suffixes):
            return
        
        for tld in suspicious_tlds:
            if query.endswith(tld):
                self._create_threat(
                    severity="high",
                    title=f"Suspicious domain query: {query}",
                    description=f"Device {src_ip} queried suspicious TLD",
                    source_ip=src_ip,
                    indicator=query,
                    category="suspicious_dns",
                )
                return
        
        for pattern in suspicious_patterns:
            if pattern in query_lower:
                self._create_threat(
                    severity="medium",
                    title=f"Suspicious domain pattern: {query}",
                    description=f"Device {src_ip} queried domain matching pattern '{pattern.strip('.-')}'",
                    source_ip=src_ip,
                    indicator=query,
                    category="suspicious_dns",
                )
                return
    
    def _create_threat(self, severity: str, title: str, description: str, 
                       source_ip: str = "", dest_ip: str = "", 
                       indicator: str = "", category: str = ""):
        """Create a threat alert."""
        threat = ThreatAlert(
            id=f"threat-{int(time.time() * 1000)}",
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            dest_ip=dest_ip,
            indicator=indicator,
            category=category,
        )
        
        with self._lock:
            self.threats.insert(0, threat)
            if len(self.threats) > 1000:
                self.threats = self.threats[:1000]
        
        if self._on_threat:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._on_threat(threat),
                    asyncio.get_event_loop()
                )
            except RuntimeError:
                pass  # No event loop
    
    def get_connections_fast(self) -> list[dict]:
        """Get active connections using psutil (fast)."""
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                continue
            if not conn.raddr:
                continue
            if conn.laddr.ip.startswith('127.') or conn.laddr.ip == '::1':
                continue
            
            process_name = self._get_process_name(conn.pid) if conn.pid else "-"
            
            conn_data = {
                "protocol": "TCP" if conn.type == 1 else "UDP",
                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                "state": conn.status,
                "pid": str(conn.pid) if conn.pid else "",
                "process": process_name,
            }
            connections.append(conn_data)
            
            # Threat detection
            if conn.raddr.port in self.SUSPICIOUS_PORTS:
                self._create_threat(
                    severity="medium",
                    title=f"Connection to suspicious port {conn.raddr.port}",
                    description=f"Process '{process_name}' connecting to port {conn.raddr.port}",
                    source_ip=conn.laddr.ip,
                    dest_ip=conn.raddr.ip,
                    category="suspicious_connection",
                )
            
            if process_name.lower() in self.SUSPICIOUS_PROCESSES:
                self._create_threat(
                    severity="high",
                    title=f"Suspicious process: {process_name}",
                    description=f"Known hacking tool '{process_name}' has network activity",
                    source_ip=conn.laddr.ip,
                    dest_ip=conn.raddr.ip,
                    category="malicious_tool",
                )
        
        self.connections = connections[:200]
        return connections[:200]
    
    def get_traffic_stats(self) -> dict:
        """Get network traffic statistics (instant)."""
        net_io = psutil.net_io_counters()
        
        self.traffic_stats = {
            "bytes_in": net_io.bytes_recv,
            "bytes_out": net_io.bytes_sent,
            "packets_in": net_io.packets_recv,
            "packets_out": net_io.packets_sent,
            "connections_active": len(self.connections),
            "errors_in": net_io.errin,
            "errors_out": net_io.errout,
            "drop_in": net_io.dropin,
            "drop_out": net_io.dropout,
        }
        return self.traffic_stats
    
    def get_devices(self) -> list[dict]:
        """Get all discovered devices."""
        with self._lock:
            return [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "hostname": d.hostname or d.ip,
                    "vendor": d.vendor,
                    "type": d.device_type,
                    "bytes_sent": d.bytes_sent,
                    "bytes_recv": d.bytes_recv,
                    "last_seen": d.last_seen.isoformat(),
                    "status": "online" if (datetime.now(timezone.utc) - d.last_seen).seconds < 300 else "offline",
                }
                for d in self.devices.values()
            ]
    
    def get_threats(self) -> list[dict]:
        """Get recent threats."""
        with self._lock:
            return [
                {
                    "id": t.id,
                    "timestamp": t.timestamp.isoformat(),
                    "severity": t.severity,
                    "title": t.title,
                    "description": t.description,
                    "source_ip": t.source_ip,
                    "category": t.category,
                }
                for t in self.threats[:100]
            ]
    
    def scan_arp_table(self) -> list[dict]:
        """Scan ARP table for devices (fast fallback)."""
        import subprocess
        import re
        
        devices = []
        seen_ips = set()
        
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split("\n"):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    
                    if not ip.startswith(self.local_prefix):
                        continue
                    if ip.endswith(".255") or ip in seen_ips:
                        continue
                    
                    seen_ips.add(ip)
                    
                    # Get or create device
                    if ip not in self.devices:
                        vendor = self._lookup_vendor(mac)
                        hostname = self._resolve_hostname(ip)
                        device_type = self._classify_device(vendor, mac, hostname)
                        
                        self.devices[ip] = DeviceStats(
                            ip=ip,
                            mac=mac,
                            vendor=vendor,
                            device_type=device_type,
                            hostname=hostname,
                        )
                    
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": self.devices[ip].hostname,
                        "vendor": self.devices[ip].vendor,
                        "type": self.devices[ip].device_type,
                        "status": "online",
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                    })
            
            devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
            
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        
        return devices
    
# Global monitor instance
_monitor: Optional[NetworkMonitor] = None


def get_monitor(network_range: str = "192.168.1.0/24") -> NetworkMonitor:
    """Get or create the global monitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = NetworkMonitor(local_network=network_range)
        _monitor.start()
    return _monitor


def shutdown_monitor():
    """Shutdown the global monitor."""
    global _monitor
    if _monitor:
        _monitor.stop()
        _monitor = None
