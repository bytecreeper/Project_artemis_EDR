# Artemis Agent - Network Discovery
"""
Network discovery and device inventory module.
Scans local network, identifies devices, tracks changes.
"""

import asyncio
import json
import logging
import re
import socket
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from typing import Any

logger = logging.getLogger("artemis.agent.network")


class DeviceCategory(str, Enum):
    """Device type categories."""
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SERVER = "server"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    SWITCH = "switch"
    FIREWALL = "firewall"
    MOBILE = "mobile"
    IOT = "iot"
    PRINTER = "printer"
    NAS = "nas"
    CAMERA = "camera"
    SMART_TV = "smart_tv"
    GAME_CONSOLE = "game_console"
    VOIP = "voip"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    """Device connection status."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


@dataclass
class NetworkDevice:
    """Represents a discovered network device."""
    device_id: str
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    category: DeviceCategory = DeviceCategory.UNKNOWN
    vendor: str | None = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os_guess: str | None = None
    is_gateway: bool = False
    is_local: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "category": self.category.value,
            "vendor": self.vendor,
            "status": self.status.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "open_ports": self.open_ports,
            "services": self.services,
            "os_guess": self.os_guess,
            "is_gateway": self.is_gateway,
            "is_local": self.is_local,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NetworkDevice":
        """Create from dictionary."""
        return cls(
            device_id=data.get("device_id", str(uuid.uuid4())),
            ip_address=data["ip_address"],
            mac_address=data.get("mac_address"),
            hostname=data.get("hostname"),
            category=DeviceCategory(data.get("category", "unknown")),
            vendor=data.get("vendor"),
            status=DeviceStatus(data.get("status", "unknown")),
            first_seen=datetime.fromisoformat(data.get("first_seen", datetime.now(timezone.utc).isoformat())),
            last_seen=datetime.fromisoformat(data.get("last_seen", datetime.now(timezone.utc).isoformat())),
            open_ports=data.get("open_ports", []),
            services=data.get("services", {}),
            os_guess=data.get("os_guess"),
            is_gateway=data.get("is_gateway", False),
            is_local=data.get("is_local", False),
            metadata=data.get("metadata", {}),
        )


# MAC OUI prefixes for vendor identification (common ones)
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "VirtualBox",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "00:1A:2B": "Cisco",
    "00:1B:54": "Cisco",
    "00:1C:0E": "Cisco",
    "00:17:DF": "Cisco",
    "00:1E:BD": "Cisco",
    "00:22:55": "Cisco",
    "00:24:50": "Cisco Meraki",
    "00:18:0A": "Cisco Meraki",
    "00:1A:A0": "Dell",
    "00:14:22": "Dell",
    "18:A9:05": "HP",
    "00:1E:68": "HP",
    "00:11:0A": "HP",
    "AC:DE:48": "Apple",
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    "00:14:51": "Apple",
    "34:15:9E": "Apple",
    "F0:18:98": "Apple",
    "88:66:A5": "Apple",
    "3C:22:FB": "Apple",
    "98:5A:EB": "Apple",
    "00:11:32": "Synology",
    "00:21:5A": "HP",
    "00:25:B3": "HP",
    "3C:D9:2B": "HP",
    "00:24:DC": "Juniper",
    "00:14:F6": "Juniper",
    "EC:13:DB": "Juniper",
    "4C:EB:42": "Intel",
    "00:1C:C0": "Intel",
    "00:1E:67": "Intel",
    "00:15:17": "Intel",
    "00:1B:21": "Intel",
    "88:12:4E": "Qualcomm",
    "00:0F:00": "Broadcom",
    "00:90:4C": "Broadcom",
    "00:10:18": "Broadcom",
    "00:24:E4": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "18:E8:29": "Ubiquiti",
    "68:D7:9A": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "74:AC:B9": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "E0:63:DA": "Ubiquiti",
    "E4:38:83": "Netgear",
    "00:24:B2": "Netgear",
    "00:1F:33": "Netgear",
    "00:1E:2A": "Netgear",
    "00:14:6C": "Netgear",
    "9C:D3:6D": "ASUS",
    "00:1A:92": "ASUS",
    "00:15:F2": "ASUS",
    "00:1D:60": "ASUS",
    "60:45:CB": "ASUS",
    "74:D4:35": "TP-Link",
    "00:23:CD": "TP-Link",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "14:CC:20": "TP-Link",
    "90:F6:52": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "14:EB:B6": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "34:E8:94": "TP-Link",
    "48:22:54": "TP-Link",
    "44:32:C8": "TP-Link",
    "00:1C:DF": "Belkin",
    "00:1F:C9": "Cisco Linksys",
    "68:7F:74": "Cisco Linksys",
    "00:23:69": "Cisco Linksys",
    "94:10:3E": "Belkin",
    "08:86:3B": "Belkin",
    "C0:56:27": "Belkin",
    "24:F5:A2": "Belkin",
    "64:A2:F9": "OnePlus",
    "CC:46:D6": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "94:EB:2C": "Google Nest",
    "18:D6:C7": "Google Nest",
    "D8:EB:46": "Google Nest",
    "F8:0F:F9": "Google Nest",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "64:18:D8": "Sonos",
    "B8:E9:37": "Sonos",
    "00:0E:58": "Sonos",
    "5C:AA:FD": "Sonos",
    "78:28:CA": "Sonos",
    "94:9F:3E": "Sonos",
    "54:2A:1B": "Sonos",
    "34:7E:5C": "Sonos",
    "48:A6:B8": "Sonos",
    "F0:F6:C1": "Sonos",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "00:1F:80": "Philips Lighting",
    "6C:2A:DF": "Ring",
    "D4:E8:53": "Ring",
    "50:14:79": "Roku",
    "B0:A7:37": "Roku",
    "AC:3A:7A": "Roku",
    "00:0D:4B": "Roku",
    "B8:3E:59": "Roku",
    "84:EA:ED": "Roku",
    "CC:6D:A0": "Roku",
    "D8:31:34": "Roku",
    "10:59:32": "Roku",
    "00:11:75": "Intel",
    "00:1F:3F": "Intel",
    "00:50:F2": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:17:FA": "Microsoft",
    "28:18:78": "Microsoft",
    "50:1A:C5": "Microsoft",
    "7C:1E:52": "Microsoft",
    "00:1D:D8": "Microsoft Xbox",
    "7C:ED:8D": "Microsoft Xbox",
    "60:45:BD": "Microsoft Xbox",
    "98:5F:D3": "Microsoft Xbox",
    "7C:5C:F8": "Amazon",
    "44:65:0D": "Amazon",
    "F0:D2:F1": "Amazon",
    "84:D6:D0": "Amazon",
    "FC:65:DE": "Amazon",
    "4C:EF:C0": "Amazon",
    "18:74:2E": "Amazon",
    "F8:FC:00": "Samsung",
    "94:35:0A": "Samsung",
    "AC:5F:3E": "Samsung",
    "30:96:FB": "Samsung",
    "78:BD:BC": "Samsung",
    "28:98:7B": "Samsung",
    "D0:22:BE": "Samsung",
    "8C:79:F5": "Samsung",
    "E4:92:FB": "Samsung",
    "50:32:75": "Samsung",
    "00:E0:B8": "AMD",
}


def get_vendor_from_mac(mac: str) -> str | None:
    """Look up vendor from MAC address OUI prefix."""
    if not mac:
        return None
    
    # Normalize MAC format
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    prefix = ":".join(mac_clean.split(":")[:3])
    
    return MAC_VENDORS.get(prefix)


def categorize_device(
    hostname: str | None,
    vendor: str | None,
    open_ports: list[int],
    mac: str | None = None,
) -> DeviceCategory:
    """Guess device category based on available information."""
    hostname_lower = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()
    
    # Router indicators
    if any(x in hostname_lower for x in ["router", "gateway", "rt-", "gw-", "ubnt", "unifi", "usg", "edge"]):
        return DeviceCategory.ROUTER
    if any(x in vendor_lower for x in ["netgear", "linksys", "tp-link", "asus", "d-link", "belkin"]):
        if 80 in open_ports or 443 in open_ports:
            return DeviceCategory.ROUTER
    if "ubiquiti" in vendor_lower and any(p in open_ports for p in [22, 80, 443]):
        return DeviceCategory.ROUTER
    
    # Access point indicators
    if any(x in hostname_lower for x in ["ap", "accesspoint", "wap", "uap"]):
        return DeviceCategory.ACCESS_POINT
    if "ubiquiti" in vendor_lower:
        return DeviceCategory.ACCESS_POINT
    
    # Switch indicators
    if any(x in hostname_lower for x in ["switch", "sw-", "usw"]):
        return DeviceCategory.SWITCH
    
    # Firewall indicators
    if any(x in hostname_lower for x in ["firewall", "fw-", "pfsense", "opnsense", "sophos", "fortinet"]):
        return DeviceCategory.FIREWALL
    
    # Server indicators
    if any(x in hostname_lower for x in ["server", "srv", "dc", "ad", "sql", "db", "web", "mail", "nas"]):
        return DeviceCategory.SERVER
    if any(p in open_ports for p in [3389, 22, 23, 3306, 5432, 1433, 27017, 6379]):
        return DeviceCategory.SERVER
    
    # NAS indicators
    if any(x in hostname_lower for x in ["nas", "synology", "qnap", "drobo", "freenas", "truenas"]):
        return DeviceCategory.NAS
    if "synology" in vendor_lower:
        return DeviceCategory.NAS
    if 5000 in open_ports or 5001 in open_ports:  # Synology DSM
        return DeviceCategory.NAS
    
    # Printer indicators
    if any(x in hostname_lower for x in ["printer", "print", "hp-", "epson", "brother", "canon"]):
        return DeviceCategory.PRINTER
    if 515 in open_ports or 631 in open_ports or 9100 in open_ports:
        return DeviceCategory.PRINTER
    
    # Camera indicators
    if any(x in hostname_lower for x in ["camera", "cam", "ipcam", "nvr", "dvr", "hikvision", "dahua"]):
        return DeviceCategory.CAMERA
    if 554 in open_ports:  # RTSP
        return DeviceCategory.CAMERA
    
    # Smart TV indicators
    if any(x in hostname_lower for x in ["tv", "roku", "firetv", "chromecast", "appletv"]):
        return DeviceCategory.SMART_TV
    if "roku" in vendor_lower or "samsung" in vendor_lower:
        if 8060 in open_ports:  # Roku ECP
            return DeviceCategory.SMART_TV
    if "lg" in vendor_lower or "samsung" in vendor_lower or "sony" in vendor_lower:
        if any(x in hostname_lower for x in ["lg", "samsung", "sony", "bravia"]):
            return DeviceCategory.SMART_TV
    
    # Game console indicators
    if any(x in hostname_lower for x in ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch"]):
        return DeviceCategory.GAME_CONSOLE
    if "xbox" in vendor_lower or "sony" in vendor_lower:
        return DeviceCategory.GAME_CONSOLE
    
    # VoIP indicators
    if any(x in hostname_lower for x in ["phone", "voip", "sip", "polycom", "cisco-cp"]):
        return DeviceCategory.VOIP
    if 5060 in open_ports or 5061 in open_ports:
        return DeviceCategory.VOIP
    
    # Mobile indicators
    if any(x in hostname_lower for x in ["iphone", "ipad", "android", "galaxy", "pixel"]):
        return DeviceCategory.MOBILE
    if "apple" in vendor_lower and not any(x in hostname_lower for x in ["macbook", "imac", "mac-"]):
        return DeviceCategory.MOBILE
    
    # IoT indicators
    if any(x in hostname_lower for x in ["nest", "hue", "echo", "ring", "sonos", "alexa", "smartthings"]):
        return DeviceCategory.IOT
    if any(x in vendor_lower for x in ["nest", "philips hue", "sonos", "ring", "amazon"]):
        return DeviceCategory.IOT
    
    # Laptop indicators
    if any(x in hostname_lower for x in ["laptop", "macbook", "notebook", "thinkpad", "surface"]):
        return DeviceCategory.LAPTOP
    
    # Desktop indicators
    if any(x in hostname_lower for x in ["desktop", "pc", "workstation", "imac"]):
        return DeviceCategory.DESKTOP
    
    # Default based on vendor
    if "vmware" in vendor_lower or "virtualbox" in vendor_lower or "hyper-v" in vendor_lower:
        return DeviceCategory.SERVER
    
    if "apple" in vendor_lower:
        return DeviceCategory.DESKTOP
    
    if "microsoft" in vendor_lower:
        return DeviceCategory.DESKTOP
    
    if "intel" in vendor_lower or "dell" in vendor_lower or "hp" in vendor_lower or "lenovo" in vendor_lower:
        return DeviceCategory.DESKTOP
    
    if "raspberry" in vendor_lower:
        return DeviceCategory.IOT
    
    return DeviceCategory.UNKNOWN


class NetworkScanner:
    """
    Network discovery and device inventory management.
    Uses ARP scanning, port probing, and hostname resolution.
    """
    
    def __init__(
        self,
        subnet: str | None = None,
        scan_ports: list[int] | None = None,
        inventory_file: Path | None = None,
    ):
        """
        Initialize the network scanner.
        
        Args:
            subnet: Network to scan (e.g., "192.168.1.0/24"). Auto-detect if None.
            scan_ports: Ports to probe on discovered devices.
            inventory_file: File to persist device inventory.
        """
        self.subnet = subnet
        self.scan_ports = scan_ports or [22, 23, 80, 443, 445, 3389, 5000, 8080, 8443]
        self.inventory_file = inventory_file or (Path.home() / ".artemis" / "network_inventory.json")
        
        self._devices: dict[str, NetworkDevice] = {}
        self._local_ip: str | None = None
        self._gateway_ip: str | None = None
        self._gateway_mac: str | None = None
        
    async def initialize(self) -> None:
        """Initialize scanner - detect local network settings."""
        self._local_ip = await self._get_local_ip()
        self._gateway_ip, self._gateway_mac = await self._get_gateway_info()
        
        if not self.subnet and self._local_ip:
            # Auto-detect subnet from local IP
            parts = self._local_ip.rsplit(".", 1)
            self.subnet = f"{parts[0]}.0/24"
        
        # Load existing inventory
        await self._load_inventory()
        
        logger.info(f"Network scanner initialized: subnet={self.subnet}, local_ip={self._local_ip}, gateway={self._gateway_ip}")
        
    async def _get_local_ip(self) -> str | None:
        """Get local IP address."""
        try:
            # Connect to a public DNS to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.warning(f"Failed to get local IP: {e}")
            return None
            
    async def _get_gateway_info(self) -> tuple[str | None, str | None]:
        """Get default gateway IP and MAC."""
        try:
            # Use route command on Windows
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            # Parse output for gateway IP
            for line in result.stdout.splitlines():
                if "0.0.0.0" in line and "On-link" not in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r"\d+\.\d+\.\d+\.\d+", part) and part != "0.0.0.0":
                            gateway_ip = part
                            # Get MAC from ARP cache
                            gateway_mac = await self._get_mac_for_ip(gateway_ip)
                            return gateway_ip, gateway_mac
                            
        except Exception as e:
            logger.warning(f"Failed to get gateway: {e}")
            
        return None, None
        
    async def _get_mac_for_ip(self, ip: str) -> str | None:
        """Get MAC address for an IP from ARP cache."""
        try:
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            for line in result.stdout.splitlines():
                if ip in line:
                    # Find MAC address pattern
                    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
                    if mac_match:
                        return mac_match.group().upper().replace("-", ":")
                        
        except Exception as e:
            logger.debug(f"Failed to get MAC for {ip}: {e}")
            
        return None
        
    async def scan(self) -> list[NetworkDevice]:
        """
        Perform full network scan.
        Returns list of discovered devices.
        """
        if not self.subnet:
            logger.error("No subnet configured")
            return []
        
        logger.info(f"Starting network scan of {self.subnet}")
        
        # Step 1: ARP scan to discover live hosts
        live_hosts = await self._arp_scan()
        logger.info(f"Found {len(live_hosts)} live hosts via ARP")
        
        # Step 2: Process each host
        tasks = []
        for ip, mac in live_hosts:
            tasks.append(self._process_host(ip, mac))
        
        # Run with some concurrency
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        new_devices = []
        for result in results:
            if isinstance(result, NetworkDevice):
                new_devices.append(result)
            elif isinstance(result, Exception):
                logger.debug(f"Host processing error: {result}")
        
        # Update inventory
        for device in new_devices:
            existing = self._devices.get(device.ip_address)
            if existing:
                # Update existing device
                existing.last_seen = datetime.now(timezone.utc)
                existing.status = DeviceStatus.ONLINE
                existing.mac_address = device.mac_address or existing.mac_address
                existing.hostname = device.hostname or existing.hostname
                existing.open_ports = device.open_ports or existing.open_ports
                existing.vendor = device.vendor or existing.vendor
                existing.category = device.category if device.category != DeviceCategory.UNKNOWN else existing.category
            else:
                # New device
                self._devices[device.ip_address] = device
        
        # Mark offline devices
        now = datetime.now(timezone.utc)
        seen_ips = {d.ip_address for d in new_devices}
        for ip, device in self._devices.items():
            if ip not in seen_ips:
                # Check if recently seen
                age = (now - device.last_seen).total_seconds()
                if age > 300:  # 5 minutes
                    device.status = DeviceStatus.OFFLINE
        
        # Save inventory
        await self._save_inventory()
        
        logger.info(f"Scan complete: {len(new_devices)} devices found, {len(self._devices)} total in inventory")
        
        return new_devices
        
    async def _arp_scan(self) -> list[tuple[str, str | None]]:
        """Perform ARP scan to discover live hosts."""
        live_hosts: list[tuple[str, str | None]] = []
        
        try:
            # Method 1: Parse existing ARP cache
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            for line in result.stdout.splitlines():
                # Parse Windows ARP output format
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
                    line
                )
                if match:
                    ip = match.group(1)
                    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
                    mac = mac_match.group().upper().replace("-", ":") if mac_match else None
                    
                    # Filter to our subnet
                    if self._is_in_subnet(ip):
                        live_hosts.append((ip, mac))
                        
        except Exception as e:
            logger.warning(f"ARP scan failed: {e}")
        
        # Method 2: Ping sweep to populate ARP cache
        if len(live_hosts) < 5:  # If ARP cache was sparse
            logger.info("Performing ping sweep to discover hosts...")
            await self._ping_sweep()
            
            # Re-check ARP cache
            try:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
                        line
                    )
                    if match:
                        ip = match.group(1)
                        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
                        mac = mac_match.group().upper().replace("-", ":") if mac_match else None
                        
                        if self._is_in_subnet(ip) and not any(h[0] == ip for h in live_hosts):
                            live_hosts.append((ip, mac))
                            
            except Exception as e:
                logger.warning(f"Post-ping ARP scan failed: {e}")
        
        return live_hosts
        
    async def _ping_sweep(self) -> None:
        """Ping sweep the subnet to populate ARP cache."""
        if not self.subnet:
            return
        
        try:
            network = IPv4Network(self.subnet, strict=False)
        except ValueError:
            return
        
        # Limit to reasonable size
        hosts = list(network.hosts())[:255]
        
        async def ping_host(ip: str) -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-n", "1", "-w", "200", ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=1.0)
            except Exception:
                pass
        
        # Ping in batches
        batch_size = 50
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            await asyncio.gather(*[ping_host(str(ip)) for ip in batch])
            await asyncio.sleep(0.1)
            
    def _is_in_subnet(self, ip: str) -> bool:
        """Check if IP is in our target subnet."""
        if not self.subnet:
            return True
        
        try:
            network = IPv4Network(self.subnet, strict=False)
            return ip_address(ip) in network
        except ValueError:
            return False
            
    async def _process_host(self, ip: str, mac: str | None) -> NetworkDevice:
        """Process a discovered host - resolve hostname, probe ports."""
        # Resolve hostname
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            pass
        
        # Get vendor from MAC
        vendor = get_vendor_from_mac(mac) if mac else None
        
        # Port scan (quick check)
        open_ports = await self._quick_port_scan(ip)
        
        # Categorize device
        category = categorize_device(hostname, vendor, open_ports, mac)
        
        # Check if this is local or gateway
        is_local = ip == self._local_ip
        is_gateway = ip == self._gateway_ip
        
        device = NetworkDevice(
            device_id=str(uuid.uuid4()),
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            category=category,
            vendor=vendor,
            status=DeviceStatus.ONLINE,
            open_ports=open_ports,
            is_local=is_local,
            is_gateway=is_gateway,
        )
        
        return device
        
    async def _quick_port_scan(self, ip: str) -> list[int]:
        """Quick port scan of common ports."""
        open_ports = []
        
        async def check_port(port: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=0.5,
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None
        
        results = await asyncio.gather(*[check_port(p) for p in self.scan_ports])
        open_ports = [p for p in results if p is not None]
        
        return sorted(open_ports)
        
    async def _load_inventory(self) -> None:
        """Load device inventory from file."""
        if not self.inventory_file.exists():
            return
        
        try:
            data = json.loads(self.inventory_file.read_text())
            for device_data in data.get("devices", []):
                device = NetworkDevice.from_dict(device_data)
                self._devices[device.ip_address] = device
            logger.info(f"Loaded {len(self._devices)} devices from inventory")
        except Exception as e:
            logger.warning(f"Failed to load inventory: {e}")
            
    async def _save_inventory(self) -> None:
        """Save device inventory to file."""
        self.inventory_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            data = {
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "subnet": self.subnet,
                "local_ip": self._local_ip,
                "gateway_ip": self._gateway_ip,
                "devices": [d.to_dict() for d in self._devices.values()],
            }
            self.inventory_file.write_text(json.dumps(data, indent=2))
            logger.debug(f"Saved {len(self._devices)} devices to inventory")
        except Exception as e:
            logger.warning(f"Failed to save inventory: {e}")
            
    @property
    def devices(self) -> list[NetworkDevice]:
        """Get all known devices."""
        return list(self._devices.values())
        
    @property
    def online_devices(self) -> list[NetworkDevice]:
        """Get online devices."""
        return [d for d in self._devices.values() if d.status == DeviceStatus.ONLINE]
        
    @property
    def local_ip(self) -> str | None:
        """Get local machine IP."""
        return self._local_ip
        
    @property
    def gateway_ip(self) -> str | None:
        """Get gateway IP."""
        return self._gateway_ip
        
    def get_device(self, ip: str) -> NetworkDevice | None:
        """Get device by IP."""
        return self._devices.get(ip)
        
    def get_devices_by_category(self, category: DeviceCategory) -> list[NetworkDevice]:
        """Get devices by category."""
        return [d for d in self._devices.values() if d.category == category]
        
    def get_new_devices(self, since_hours: int = 24) -> list[NetworkDevice]:
        """Get devices discovered in the last N hours."""
        cutoff = datetime.now(timezone.utc).timestamp() - (since_hours * 3600)
        return [
            d for d in self._devices.values()
            if d.first_seen.timestamp() > cutoff
        ]
        
    async def monitor_changes(self, interval: float = 60.0) -> None:
        """
        Continuously monitor for network changes.
        Yields when new devices appear or devices go offline.
        """
        while True:
            try:
                await self.scan()
            except Exception as e:
                logger.error(f"Scan error: {e}")
            
            await asyncio.sleep(interval)
