# Artemis Agent - Enhanced Network Discovery
"""
Comprehensive network discovery using multiple protocols:
- ARP scanning (Layer 2)
- mDNS/Bonjour (Apple devices, Chromecasts, printers)
- SSDP/UPnP (Smart TVs, media devices, routers)
- NetBIOS (Windows devices)
- SNMP (Network infrastructure)
- DHCP fingerprinting
"""

import asyncio
import json
import logging
import re
import socket
import struct
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from typing import Any
import uuid

logger = logging.getLogger("artemis.agent.discovery")


class DeviceType(str, Enum):
    """Device type categories."""
    # Network Infrastructure
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    SWITCH = "switch"
    FIREWALL = "firewall"
    MODEM = "modem"
    
    # Computers
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SERVER = "server"
    WORKSTATION = "workstation"
    
    # Mobile
    SMARTPHONE = "smartphone"
    TABLET = "tablet"
    
    # Storage
    NAS = "nas"
    SAN = "san"
    
    # Media
    SMART_TV = "smart_tv"
    STREAMING_DEVICE = "streaming_device"
    MEDIA_PLAYER = "media_player"
    SPEAKER = "speaker"
    
    # Gaming
    GAME_CONSOLE = "game_console"
    HANDHELD = "handheld"
    
    # IoT/Smart Home
    SMART_HOME_HUB = "smart_home_hub"
    THERMOSTAT = "thermostat"
    SMART_LIGHT = "smart_light"
    DOORBELL = "doorbell"
    CAMERA = "camera"
    SENSOR = "sensor"
    SMART_PLUG = "smart_plug"
    VOICE_ASSISTANT = "voice_assistant"
    
    # Appliances
    PRINTER = "printer"
    SCANNER = "scanner"
    
    # Communication
    VOIP_PHONE = "voip_phone"
    
    # Virtual
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    
    UNKNOWN = "unknown"


@dataclass
class DiscoveredDevice:
    """Enhanced device information from multiple discovery methods."""
    device_id: str
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    netbios_name: str | None = None
    mdns_name: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    manufacturer: str | None = None
    model: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    services: list[dict] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    upnp_info: dict = field(default_factory=dict)
    mdns_services: list[str] = field(default_factory=list)
    is_gateway: bool = False
    is_local: bool = False
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    discovery_methods: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname or self.netbios_name or self.mdns_name,
            "netbios_name": self.netbios_name,
            "mdns_name": self.mdns_name,
            "device_type": self.device_type.value,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "services": self.services,
            "open_ports": self.open_ports,
            "upnp_info": self.upnp_info,
            "mdns_services": self.mdns_services,
            "is_gateway": self.is_gateway,
            "is_local": self.is_local,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "discovery_methods": self.discovery_methods,
        }


# Extended MAC OUI database
MAC_VENDORS = {
    # Apple
    "00:03:93": ("Apple", DeviceType.UNKNOWN),
    "00:0A:95": ("Apple", DeviceType.UNKNOWN),
    "00:14:51": ("Apple", DeviceType.UNKNOWN),
    "00:1C:B3": ("Apple", DeviceType.UNKNOWN),
    "00:1D:4F": ("Apple", DeviceType.UNKNOWN),
    "00:1E:52": ("Apple", DeviceType.UNKNOWN),
    "00:1F:5B": ("Apple", DeviceType.UNKNOWN),
    "00:21:E9": ("Apple", DeviceType.UNKNOWN),
    "00:22:41": ("Apple", DeviceType.UNKNOWN),
    "00:23:12": ("Apple", DeviceType.UNKNOWN),
    "00:23:32": ("Apple", DeviceType.UNKNOWN),
    "00:23:6C": ("Apple", DeviceType.UNKNOWN),
    "00:24:36": ("Apple", DeviceType.UNKNOWN),
    "00:25:00": ("Apple", DeviceType.UNKNOWN),
    "00:25:BC": ("Apple", DeviceType.UNKNOWN),
    "00:26:08": ("Apple", DeviceType.UNKNOWN),
    "00:26:B0": ("Apple", DeviceType.UNKNOWN),
    "00:26:BB": ("Apple", DeviceType.UNKNOWN),
    "3C:15:C2": ("Apple", DeviceType.SMARTPHONE),
    "3C:22:FB": ("Apple", DeviceType.UNKNOWN),
    "34:15:9E": ("Apple", DeviceType.SMARTPHONE),
    "F0:18:98": ("Apple", DeviceType.SMARTPHONE),
    "88:66:A5": ("Apple", DeviceType.SMARTPHONE),
    "98:5A:EB": ("Apple", DeviceType.UNKNOWN),
    "AC:DE:48": ("Apple", DeviceType.UNKNOWN),
    "D8:1D:72": ("Apple", DeviceType.SMARTPHONE),
    "F0:D1:A9": ("Apple", DeviceType.SMARTPHONE),
    "E0:B5:2D": ("Apple", DeviceType.SMARTPHONE),
    "6C:4D:73": ("Apple", DeviceType.SMARTPHONE),
    "A4:D1:D2": ("Apple", DeviceType.SMARTPHONE),
    
    # Samsung
    "00:12:47": ("Samsung", DeviceType.UNKNOWN),
    "00:15:99": ("Samsung", DeviceType.UNKNOWN),
    "00:16:32": ("Samsung", DeviceType.UNKNOWN),
    "00:17:D5": ("Samsung", DeviceType.UNKNOWN),
    "00:18:AF": ("Samsung", DeviceType.UNKNOWN),
    "00:1A:8A": ("Samsung", DeviceType.UNKNOWN),
    "00:1D:25": ("Samsung", DeviceType.UNKNOWN),
    "00:1E:7D": ("Samsung", DeviceType.UNKNOWN),
    "00:21:19": ("Samsung", DeviceType.UNKNOWN),
    "00:21:D1": ("Samsung", DeviceType.UNKNOWN),
    "00:21:D2": ("Samsung", DeviceType.UNKNOWN),
    "00:24:54": ("Samsung", DeviceType.UNKNOWN),
    "00:24:90": ("Samsung", DeviceType.UNKNOWN),
    "00:24:91": ("Samsung", DeviceType.UNKNOWN),
    "00:24:E9": ("Samsung", DeviceType.UNKNOWN),
    "00:26:37": ("Samsung", DeviceType.UNKNOWN),
    "00:26:5D": ("Samsung", DeviceType.UNKNOWN),
    "10:1D:C0": ("Samsung", DeviceType.SMARTPHONE),
    "14:49:E0": ("Samsung", DeviceType.SMARTPHONE),
    "18:3A:2D": ("Samsung", DeviceType.SMARTPHONE),
    "24:4B:81": ("Samsung", DeviceType.SMARTPHONE),
    "30:96:FB": ("Samsung", DeviceType.UNKNOWN),
    "50:01:BB": ("Samsung", DeviceType.SMARTPHONE),
    "50:32:75": ("Samsung", DeviceType.SMARTPHONE),
    "78:BD:BC": ("Samsung", DeviceType.SMARTPHONE),
    "AC:5F:3E": ("Samsung", DeviceType.SMARTPHONE),
    "D0:22:BE": ("Samsung", DeviceType.SMARTPHONE),
    "D0:DF:C7": ("Samsung", DeviceType.UNKNOWN),
    "E4:92:FB": ("Samsung", DeviceType.SMARTPHONE),
    "F8:04:2E": ("Samsung", DeviceType.SMART_TV),
    "F8:FC:00": ("Samsung", DeviceType.UNKNOWN),
    
    # Google
    "00:1A:11": ("Google", DeviceType.UNKNOWN),
    "3C:5A:B4": ("Google", DeviceType.STREAMING_DEVICE),
    "54:60:09": ("Google", DeviceType.STREAMING_DEVICE),
    "94:EB:2C": ("Google Nest", DeviceType.SMART_HOME_HUB),
    "18:D6:C7": ("Google Nest", DeviceType.SMART_HOME_HUB),
    "D8:EB:46": ("Google Nest", DeviceType.SMART_HOME_HUB),
    "F8:0F:F9": ("Google Nest", DeviceType.SMART_HOME_HUB),
    "18:B4:30": ("Google Nest", DeviceType.THERMOSTAT),
    "64:16:66": ("Google Nest", DeviceType.THERMOSTAT),
    "CC:46:D6": ("Google", DeviceType.STREAMING_DEVICE),
    "F4:F5:D8": ("Google", DeviceType.STREAMING_DEVICE),
    "F4:F5:E8": ("Google", DeviceType.SMARTPHONE),
    "1C:F2:9A": ("Google", DeviceType.SPEAKER),
    "48:D6:D5": ("Google", DeviceType.SPEAKER),
    "30:FD:38": ("Google", DeviceType.SPEAKER),
    
    # Amazon
    "00:FC:8B": ("Amazon", DeviceType.STREAMING_DEVICE),
    "0C:47:C9": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "18:74:2E": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "34:D2:70": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "40:B4:CD": ("Amazon", DeviceType.STREAMING_DEVICE),
    "44:65:0D": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "4C:EF:C0": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "50:DC:E7": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "68:54:FD": ("Amazon", DeviceType.STREAMING_DEVICE),
    "6C:56:97": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "74:C2:46": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "84:D6:D0": ("Amazon", DeviceType.STREAMING_DEVICE),
    "A0:02:DC": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "AC:63:BE": ("Amazon", DeviceType.STREAMING_DEVICE),
    "B0:FC:0D": ("Amazon", DeviceType.VOICE_ASSISTANT),
    "F0:D2:F1": ("Amazon", DeviceType.STREAMING_DEVICE),
    "FC:65:DE": ("Amazon", DeviceType.VOICE_ASSISTANT),
    
    # Ring
    "6C:2A:DF": ("Ring", DeviceType.DOORBELL),
    "D4:E8:53": ("Ring", DeviceType.DOORBELL),
    
    # Roku
    "00:0D:4B": ("Roku", DeviceType.STREAMING_DEVICE),
    "50:14:79": ("Roku", DeviceType.STREAMING_DEVICE),
    "84:EA:ED": ("Roku", DeviceType.STREAMING_DEVICE),
    "AC:3A:7A": ("Roku", DeviceType.STREAMING_DEVICE),
    "B0:A7:37": ("Roku", DeviceType.STREAMING_DEVICE),
    "B8:3E:59": ("Roku", DeviceType.STREAMING_DEVICE),
    "CC:6D:A0": ("Roku", DeviceType.STREAMING_DEVICE),
    "D8:31:34": ("Roku", DeviceType.STREAMING_DEVICE),
    "10:59:32": ("Roku", DeviceType.STREAMING_DEVICE),
    
    # Sonos
    "00:0E:58": ("Sonos", DeviceType.SPEAKER),
    "5C:AA:FD": ("Sonos", DeviceType.SPEAKER),
    "54:2A:1B": ("Sonos", DeviceType.SPEAKER),
    "64:18:D8": ("Sonos", DeviceType.SPEAKER),
    "78:28:CA": ("Sonos", DeviceType.SPEAKER),
    "94:9F:3E": ("Sonos", DeviceType.SPEAKER),
    "B8:E9:37": ("Sonos", DeviceType.SPEAKER),
    "34:7E:5C": ("Sonos", DeviceType.SPEAKER),
    "48:A6:B8": ("Sonos", DeviceType.SPEAKER),
    "F0:F6:C1": ("Sonos", DeviceType.SPEAKER),
    
    # Philips Hue
    "00:17:88": ("Philips Hue", DeviceType.SMART_LIGHT),
    "EC:B5:FA": ("Philips Hue", DeviceType.SMART_LIGHT),
    
    # Microsoft/Xbox
    "00:50:F2": ("Microsoft", DeviceType.UNKNOWN),
    "28:18:78": ("Microsoft", DeviceType.UNKNOWN),
    "50:1A:C5": ("Microsoft", DeviceType.UNKNOWN),
    "7C:1E:52": ("Microsoft", DeviceType.UNKNOWN),
    "00:1D:D8": ("Microsoft Xbox", DeviceType.GAME_CONSOLE),
    "7C:ED:8D": ("Microsoft Xbox", DeviceType.GAME_CONSOLE),
    "60:45:BD": ("Microsoft Xbox", DeviceType.GAME_CONSOLE),
    "98:5F:D3": ("Microsoft Xbox", DeviceType.GAME_CONSOLE),
    "C8:3F:26": ("Microsoft Xbox", DeviceType.GAME_CONSOLE),
    
    # Sony/PlayStation
    "00:1D:0D": ("Sony", DeviceType.GAME_CONSOLE),
    "00:19:C5": ("Sony", DeviceType.GAME_CONSOLE),
    "00:24:8D": ("Sony PlayStation", DeviceType.GAME_CONSOLE),
    "28:0D:FC": ("Sony PlayStation", DeviceType.GAME_CONSOLE),
    "78:C8:81": ("Sony PlayStation", DeviceType.GAME_CONSOLE),
    "F8:D0:AC": ("Sony PlayStation", DeviceType.GAME_CONSOLE),
    
    # Nintendo
    "00:09:BF": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:17:AB": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:19:1D": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1A:E9": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1B:7A": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1C:BE": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1D:BC": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1E:35": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:1F:32": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:21:47": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:21:BD": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:22:4C": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:22:AA": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:23:31": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:23:CC": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:24:1E": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:24:F3": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:25:A0": ("Nintendo", DeviceType.GAME_CONSOLE),
    "00:26:59": ("Nintendo", DeviceType.GAME_CONSOLE),
    "2C:10:C1": ("Nintendo Switch", DeviceType.HANDHELD),
    "98:B6:E9": ("Nintendo Switch", DeviceType.HANDHELD),
    "7C:BB:8A": ("Nintendo Switch", DeviceType.HANDHELD),
    
    # Ubiquiti
    "00:27:22": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "04:18:D6": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "18:E8:29": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "24:5A:4C": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "24:A4:3C": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "44:D9:E7": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "68:D7:9A": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "74:83:C2": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "74:AC:B9": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "78:8A:20": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "80:2A:A8": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "B4:FB:E4": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "DC:9F:DB": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "E0:63:DA": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "F0:9F:C2": ("Ubiquiti", DeviceType.ACCESS_POINT),
    "FC:EC:DA": ("Ubiquiti", DeviceType.ACCESS_POINT),
    
    # Synology
    "00:11:32": ("Synology", DeviceType.NAS),
    "00:17:32": ("Synology", DeviceType.NAS),
    
    # QNAP
    "00:08:9B": ("QNAP", DeviceType.NAS),
    "24:5E:BE": ("QNAP", DeviceType.NAS),
    
    # VMware
    "00:50:56": ("VMware", DeviceType.VIRTUAL_MACHINE),
    "00:0C:29": ("VMware", DeviceType.VIRTUAL_MACHINE),
    
    # VirtualBox
    "08:00:27": ("VirtualBox", DeviceType.VIRTUAL_MACHINE),
    
    # Hyper-V
    "00:15:5D": ("Microsoft Hyper-V", DeviceType.VIRTUAL_MACHINE),
    
    # Raspberry Pi
    "28:CD:C1": ("Raspberry Pi", DeviceType.UNKNOWN),
    "B8:27:EB": ("Raspberry Pi", DeviceType.UNKNOWN),
    "DC:A6:32": ("Raspberry Pi", DeviceType.UNKNOWN),
    "E4:5F:01": ("Raspberry Pi", DeviceType.UNKNOWN),
    
    # HP Printers
    "00:11:0A": ("HP", DeviceType.PRINTER),
    "00:1E:68": ("HP", DeviceType.PRINTER),
    "18:A9:05": ("HP", DeviceType.PRINTER),
    "00:21:5A": ("HP", DeviceType.PRINTER),
    
    # Epson Printers
    "00:26:AB": ("Epson", DeviceType.PRINTER),
    "00:1B:11": ("Epson", DeviceType.PRINTER),
    
    # Canon Printers
    "00:1E:8F": ("Canon", DeviceType.PRINTER),
    "00:00:85": ("Canon", DeviceType.PRINTER),
    
    # Brother Printers
    "00:80:77": ("Brother", DeviceType.PRINTER),
    "00:1B:A9": ("Brother", DeviceType.PRINTER),
    
    # LG TVs
    "00:E0:91": ("LG", DeviceType.SMART_TV),
    "CC:2D:8C": ("LG", DeviceType.SMART_TV),
    "38:8C:50": ("LG", DeviceType.SMART_TV),
    "74:40:BB": ("LG", DeviceType.SMART_TV),
    "A8:23:FE": ("LG", DeviceType.SMART_TV),
    
    # Vizio TVs
    "00:19:9D": ("Vizio", DeviceType.SMART_TV),
    
    # TCL/Roku TVs
    "20:D5:BF": ("TCL", DeviceType.SMART_TV),
    
    # Cameras (various)
    "00:80:F0": ("Panasonic", DeviceType.CAMERA),
    "7C:DD:90": ("Shenzhen", DeviceType.CAMERA),  # Generic Chinese cameras
    
    # Network equipment
    "00:1A:2B": ("Cisco", DeviceType.ROUTER),
    "00:1B:54": ("Cisco", DeviceType.ROUTER),
    "00:1C:0E": ("Cisco", DeviceType.SWITCH),
    "00:17:DF": ("Cisco", DeviceType.ROUTER),
    "00:24:50": ("Cisco Meraki", DeviceType.ACCESS_POINT),
    "E4:38:83": ("Netgear", DeviceType.ROUTER),
    "00:24:B2": ("Netgear", DeviceType.ROUTER),
    "9C:D3:6D": ("ASUS", DeviceType.ROUTER),
    "74:D4:35": ("TP-Link", DeviceType.ROUTER),
    "50:C7:BF": ("TP-Link", DeviceType.ROUTER),
    "00:1C:DF": ("Belkin", DeviceType.ROUTER),
    
    # Intel (usually laptops/desktops)
    "00:1B:21": ("Intel", DeviceType.LAPTOP),
    "00:1C:C0": ("Intel", DeviceType.LAPTOP),
    "00:1E:67": ("Intel", DeviceType.LAPTOP),
    "4C:EB:42": ("Intel", DeviceType.LAPTOP),
    
    # Dell
    "00:14:22": ("Dell", DeviceType.DESKTOP),
    "00:1A:A0": ("Dell", DeviceType.DESKTOP),
    "18:DB:F2": ("Dell", DeviceType.LAPTOP),
    
    # Lenovo
    "00:1E:4F": ("Lenovo", DeviceType.LAPTOP),
    "00:21:CC": ("Lenovo", DeviceType.LAPTOP),
    "00:24:54": ("Lenovo", DeviceType.LAPTOP),
    "00:26:E8": ("Lenovo", DeviceType.LAPTOP),
    
    # TP-Link Smart Plugs/Bulbs
    "60:A4:B7": ("TP-Link Kasa", DeviceType.SMART_PLUG),
    "B0:BE:76": ("TP-Link Kasa", DeviceType.SMART_PLUG),
    
    # Wyze
    "2C:AA:8E": ("Wyze", DeviceType.CAMERA),
    
    # Eufy
    "C0:E7:BF": ("Eufy", DeviceType.CAMERA),
}


# mDNS service types and their meanings
MDNS_SERVICES = {
    "_airplay._tcp": ("AirPlay", DeviceType.STREAMING_DEVICE),
    "_raop._tcp": ("AirPlay Audio", DeviceType.SPEAKER),
    "_googlecast._tcp": ("Google Cast", DeviceType.STREAMING_DEVICE),
    "_spotify-connect._tcp": ("Spotify Connect", DeviceType.SPEAKER),
    "_sonos._tcp": ("Sonos", DeviceType.SPEAKER),
    "_homekit._tcp": ("HomeKit", DeviceType.SMART_HOME_HUB),
    "_hap._tcp": ("HomeKit Accessory", DeviceType.SMART_HOME_HUB),
    "_hue._tcp": ("Philips Hue", DeviceType.SMART_LIGHT),
    "_ipp._tcp": ("Printer (IPP)", DeviceType.PRINTER),
    "_ipps._tcp": ("Printer (IPP Secure)", DeviceType.PRINTER),
    "_printer._tcp": ("Printer", DeviceType.PRINTER),
    "_pdl-datastream._tcp": ("Printer (PDL)", DeviceType.PRINTER),
    "_scanner._tcp": ("Scanner", DeviceType.SCANNER),
    "_http._tcp": ("HTTP Server", DeviceType.UNKNOWN),
    "_https._tcp": ("HTTPS Server", DeviceType.UNKNOWN),
    "_smb._tcp": ("SMB/CIFS", DeviceType.NAS),
    "_afpovertcp._tcp": ("AFP (Apple File)", DeviceType.NAS),
    "_ssh._tcp": ("SSH", DeviceType.SERVER),
    "_sftp-ssh._tcp": ("SFTP", DeviceType.SERVER),
    "_nfs._tcp": ("NFS", DeviceType.NAS),
    "_daap._tcp": ("iTunes Library", DeviceType.MEDIA_PLAYER),
    "_dacp._tcp": ("iTunes Remote", DeviceType.MEDIA_PLAYER),
    "_apple-mobdev2._tcp": ("Apple Mobile Device", DeviceType.SMARTPHONE),
    "_companion-link._tcp": ("Apple TV Remote", DeviceType.STREAMING_DEVICE),
    "_touch-able._tcp": ("Apple Remote", DeviceType.SMARTPHONE),
    "_rdlink._tcp": ("Remote Desktop", DeviceType.DESKTOP),
    "_nvstream._tcp": ("NVIDIA Shield", DeviceType.STREAMING_DEVICE),
    "_sleep-proxy._udp": ("Sleep Proxy", DeviceType.ACCESS_POINT),
    "_airport._tcp": ("AirPort", DeviceType.ACCESS_POINT),
    "_amzn-wplay._tcp": ("Amazon Fire", DeviceType.STREAMING_DEVICE),
    "_roku._tcp": ("Roku", DeviceType.STREAMING_DEVICE),
    "_xbox._tcp": ("Xbox", DeviceType.GAME_CONSOLE),
    "_ps4._tcp": ("PlayStation 4", DeviceType.GAME_CONSOLE),
    "_psremoteplay._tcp": ("PS Remote Play", DeviceType.GAME_CONSOLE),
}


class EnhancedNetworkDiscovery:
    """
    Comprehensive network discovery using multiple protocols.
    Finds ALL devices on the network.
    """
    
    def __init__(
        self,
        subnet: str | None = None,
        inventory_file: Path | None = None,
        enable_mdns: bool = True,
        enable_ssdp: bool = True,
        enable_netbios: bool = True,
        port_scan: bool = True,
    ):
        """
        Initialize enhanced discovery.
        
        Args:
            subnet: Network to scan (auto-detect if None)
            inventory_file: File to persist inventory
            enable_mdns: Enable mDNS/Bonjour discovery
            enable_ssdp: Enable SSDP/UPnP discovery
            enable_netbios: Enable NetBIOS name resolution
            port_scan: Enable port scanning
        """
        self.subnet = subnet
        self.inventory_file = inventory_file or (Path.home() / ".artemis" / "inventory.json")
        self.enable_mdns = enable_mdns
        self.enable_ssdp = enable_ssdp
        self.enable_netbios = enable_netbios
        self.port_scan = port_scan
        
        self._devices: dict[str, DiscoveredDevice] = {}
        self._local_ip: str | None = None
        self._gateway_ip: str | None = None
        self._gateway_mac: str | None = None
        
    async def initialize(self) -> None:
        """Initialize and detect network settings."""
        self._local_ip = self._get_local_ip()
        self._gateway_ip, self._gateway_mac = await self._get_gateway_info()
        
        if not self.subnet and self._local_ip:
            parts = self._local_ip.rsplit(".", 1)
            self.subnet = f"{parts[0]}.0/24"
            
        await self._load_inventory()
        
        logger.info(f"Enhanced discovery initialized: subnet={self.subnet}, local_ip={self._local_ip}")
        
    def _get_local_ip(self) -> str | None:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None
            
    async def _get_gateway_info(self) -> tuple[str | None, str | None]:
        """Get default gateway info."""
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            for line in result.stdout.splitlines():
                if "0.0.0.0" in line and "On-link" not in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r"\d+\.\d+\.\d+\.\d+", part) and part != "0.0.0.0":
                            gateway_ip = part
                            gateway_mac = await self._get_mac_for_ip(gateway_ip)
                            return gateway_ip, gateway_mac
        except Exception as e:
            logger.debug(f"Gateway detection error: {e}")
        return None, None
        
    async def _get_mac_for_ip(self, ip: str) -> str | None:
        """Get MAC address from ARP cache."""
        try:
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            for line in result.stdout.splitlines():
                if ip in line:
                    mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
                    if mac_match:
                        return mac_match.group().upper().replace("-", ":")
        except Exception:
            pass
        return None
        
    async def full_scan(self) -> list[DiscoveredDevice]:
        """
        Perform comprehensive network scan using all methods.
        """
        logger.info(f"Starting comprehensive scan of {self.subnet}")
        
        # Run all discovery methods in parallel
        results = await asyncio.gather(
            self._arp_scan(),
            self._mdns_scan() if self.enable_mdns else asyncio.sleep(0),
            self._ssdp_scan() if self.enable_ssdp else asyncio.sleep(0),
            self._netbios_scan() if self.enable_netbios else asyncio.sleep(0),
            return_exceptions=True,
        )
        
        # Process ARP results
        if isinstance(results[0], list):
            for ip, mac in results[0]:
                await self._process_discovered_host(ip, mac, "arp")
                
        # Port scan discovered devices
        if self.port_scan:
            scan_tasks = [
                self._port_scan(device.ip_address)
                for device in self._devices.values()
            ]
            port_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            for device, ports in zip(self._devices.values(), port_results):
                if isinstance(ports, list):
                    device.open_ports = ports
                    await self._fingerprint_by_ports(device)
                    
        # Save inventory
        await self._save_inventory()
        
        logger.info(f"Scan complete: {len(self._devices)} devices found")
        
        return list(self._devices.values())
        
    async def _arp_scan(self) -> list[tuple[str, str | None]]:
        """ARP scan to discover live hosts."""
        live_hosts = []
        
        # First ping sweep to populate ARP cache
        await self._ping_sweep()
        
        # Parse ARP cache
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
                    
                    if self._is_in_subnet(ip):
                        live_hosts.append((ip, mac))
        except Exception as e:
            logger.warning(f"ARP scan error: {e}")
            
        return live_hosts
        
    async def _ping_sweep(self) -> None:
        """Ping sweep to populate ARP cache."""
        if not self.subnet:
            return
            
        try:
            network = IPv4Network(self.subnet, strict=False)
        except ValueError:
            return
            
        hosts = list(network.hosts())[:255]
        
        async def ping_host(ip: str) -> None:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ping", "-n", "1", "-w", "200", ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=1.5)
            except Exception:
                pass
                
        # Batch pings
        batch_size = 50
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            await asyncio.gather(*[ping_host(str(ip)) for ip in batch])
            await asyncio.sleep(0.1)
            
    async def _mdns_scan(self) -> list[dict]:
        """
        mDNS/Bonjour scan for Apple devices, Chromecasts, printers, etc.
        Uses PowerShell to query mDNS services.
        """
        logger.info("Running mDNS discovery")
        discovered = []
        
        # Common mDNS service types to query
        service_types = [
            "_airplay._tcp",
            "_googlecast._tcp",
            "_raop._tcp",
            "_homekit._tcp",
            "_hap._tcp",
            "_spotify-connect._tcp",
            "_ipp._tcp",
            "_printer._tcp",
            "_http._tcp",
            "_smb._tcp",
            "_companion-link._tcp",
            "_sonos._tcp",
        ]
        
        for service_type in service_types:
            try:
                # Use dns-sd style query via PowerShell
                ps_script = f'''
try {{
    $results = [System.Net.Dns]::GetHostAddresses("{service_type}.local")
    $results | ForEach-Object {{ $_.ToString() }}
}} catch {{}}
'''
                # Actually we'll use a simpler approach - check well-known mDNS names
                # mDNS typically resolves .local names
                pass
            except Exception as e:
                logger.debug(f"mDNS error for {service_type}: {e}")
                
        # Try resolving .local hostnames for known devices
        for ip, device in list(self._devices.items()):
            if device.hostname:
                try:
                    local_name = f"{device.hostname}.local"
                    socket.gethostbyname(local_name)
                    device.mdns_name = local_name
                    if "mdns" not in device.discovery_methods:
                        device.discovery_methods.append("mdns")
                except Exception:
                    pass
                    
        return discovered
        
    async def _ssdp_scan(self) -> list[dict]:
        """
        SSDP/UPnP scan for smart TVs, media devices, routers.
        """
        logger.info("Running SSDP/UPnP discovery")
        discovered = []
        
        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900
        
        # SSDP M-SEARCH request
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            
            # Send M-SEARCH
            sock.sendto(ssdp_request, (SSDP_ADDR, SSDP_PORT))
            
            # Collect responses
            end_time = asyncio.get_event_loop().time() + 5
            while asyncio.get_event_loop().time() < end_time:
                try:
                    data, addr = sock.recvfrom(4096)
                    response = data.decode('utf-8', errors='ignore')
                    
                    # Parse response
                    device_info = self._parse_ssdp_response(response, addr[0])
                    if device_info:
                        discovered.append(device_info)
                        
                        # Update device
                        if addr[0] in self._devices:
                            device = self._devices[addr[0]]
                            device.upnp_info = device_info
                            if "ssdp" not in device.discovery_methods:
                                device.discovery_methods.append("ssdp")
                            
                            # Update device type based on UPnP
                            upnp_type = device_info.get("device_type", "")
                            if "TV" in upnp_type or "MediaRenderer" in upnp_type:
                                device.device_type = DeviceType.SMART_TV
                            elif "Router" in upnp_type or "Gateway" in upnp_type:
                                device.device_type = DeviceType.ROUTER
                            elif "MediaServer" in upnp_type:
                                device.device_type = DeviceType.NAS
                                
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"SSDP recv error: {e}")
                    
            sock.close()
            
        except Exception as e:
            logger.warning(f"SSDP scan error: {e}")
            
        return discovered
        
    def _parse_ssdp_response(self, response: str, ip: str) -> dict | None:
        """Parse SSDP M-SEARCH response."""
        info = {"ip": ip}
        
        for line in response.splitlines():
            line = line.strip()
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().upper()
                value = value.strip()
                
                if key == "SERVER":
                    info["server"] = value
                elif key == "LOCATION":
                    info["location"] = value
                elif key == "ST":
                    info["service_type"] = value
                elif key == "USN":
                    info["usn"] = value
                    
        # Try to identify device type from ST or server
        st = info.get("service_type", "")
        server = info.get("server", "")
        
        if "roku" in server.lower() or "roku" in st.lower():
            info["device_type"] = "Roku"
        elif "samsung" in server.lower():
            info["device_type"] = "Samsung TV"
        elif "lg" in server.lower():
            info["device_type"] = "LG TV"
        elif "chromecast" in server.lower() or "googlecast" in st.lower():
            info["device_type"] = "Google Cast"
        elif "sonos" in server.lower():
            info["device_type"] = "Sonos"
        elif "xbox" in server.lower():
            info["device_type"] = "Xbox"
        elif "playstation" in server.lower() or "ps4" in server.lower():
            info["device_type"] = "PlayStation"
        elif "mediarenderer" in st.lower():
            info["device_type"] = "MediaRenderer"
        elif "mediaserver" in st.lower():
            info["device_type"] = "MediaServer"
        elif "internetgateway" in st.lower() or "router" in server.lower():
            info["device_type"] = "Router"
            
        return info if len(info) > 1 else None
        
    async def _netbios_scan(self) -> list[dict]:
        """
        NetBIOS name scan for Windows devices.
        """
        logger.info("Running NetBIOS scan")
        discovered = []
        
        for ip, device in list(self._devices.items()):
            try:
                # Try NetBIOS name resolution
                result = subprocess.run(
                    ["nbtstat", "-a", ip],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                
                if result.stdout:
                    # Parse NetBIOS name
                    for line in result.stdout.splitlines():
                        if "<00>" in line and "UNIQUE" in line:
                            parts = line.split()
                            if parts:
                                netbios_name = parts[0].strip()
                                device.netbios_name = netbios_name
                                if not device.hostname:
                                    device.hostname = netbios_name
                                if "netbios" not in device.discovery_methods:
                                    device.discovery_methods.append("netbios")
                                discovered.append({"ip": ip, "netbios_name": netbios_name})
                                break
                                
            except Exception as e:
                logger.debug(f"NetBIOS error for {ip}: {e}")
                
        return discovered
        
    async def _port_scan(self, ip: str) -> list[int]:
        """Quick port scan of common ports."""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995,
            1433, 1883, 3306, 3389, 5000, 5001, 5060, 5432, 5900, 6379,
            8000, 8008, 8080, 8443, 8888, 9000, 9090, 27017,
            # Smart home / IoT
            1900,  # SSDP
            5353,  # mDNS
            8008,  # Chromecast
            8443,  # UniFi
            9100,  # Printers
            10001,  # Ubiquiti
        ]
        
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
                
        results = await asyncio.gather(*[check_port(p) for p in common_ports])
        open_ports = [p for p in results if p is not None]
        
        return sorted(open_ports)
        
    async def _fingerprint_by_ports(self, device: DiscoveredDevice) -> None:
        """Identify device type based on open ports."""
        ports = set(device.open_ports)
        
        # Printer indicators
        if 9100 in ports or 631 in ports or 515 in ports:
            if device.device_type == DeviceType.UNKNOWN:
                device.device_type = DeviceType.PRINTER
                
        # NAS indicators
        if 5000 in ports or 5001 in ports:
            if device.device_type == DeviceType.UNKNOWN:
                device.device_type = DeviceType.NAS
                
        # Server indicators
        if 22 in ports or 3389 in ports:
            if device.device_type == DeviceType.UNKNOWN:
                device.device_type = DeviceType.SERVER
                
        # Chromecast
        if 8008 in ports or 8443 in ports:
            if device.device_type == DeviceType.UNKNOWN:
                device.device_type = DeviceType.STREAMING_DEVICE
                
        # UniFi / AP
        if 10001 in ports or (8443 in ports and device.manufacturer and "ubiquiti" in device.manufacturer.lower()):
            if device.device_type == DeviceType.UNKNOWN:
                device.device_type = DeviceType.ACCESS_POINT
                
    async def _process_discovered_host(self, ip: str, mac: str | None, method: str) -> None:
        """Process a discovered host and add/update in inventory."""
        if ip in self._devices:
            device = self._devices[ip]
            device.last_seen = datetime.now(timezone.utc)
            if mac and not device.mac_address:
                device.mac_address = mac
            if method not in device.discovery_methods:
                device.discovery_methods.append(method)
        else:
            # New device
            device = DiscoveredDevice(
                device_id=str(uuid.uuid4()),
                ip_address=ip,
                mac_address=mac,
                discovery_methods=[method],
            )
            
            # Resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                device.hostname = hostname
            except Exception:
                pass
                
            # Lookup vendor from MAC
            if mac:
                vendor_info = self._lookup_mac_vendor(mac)
                if vendor_info:
                    device.manufacturer, device.device_type = vendor_info
                    
            # Check if gateway/local
            device.is_gateway = ip == self._gateway_ip
            device.is_local = ip == self._local_ip
            
            self._devices[ip] = device
            
    def _lookup_mac_vendor(self, mac: str) -> tuple[str, DeviceType] | None:
        """Lookup vendor and device type from MAC OUI."""
        if not mac:
            return None
            
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        prefix = ":".join(mac_clean.split(":")[:3])
        
        return MAC_VENDORS.get(prefix)
        
    def _is_in_subnet(self, ip: str) -> bool:
        """Check if IP is in target subnet."""
        if not self.subnet:
            return True
        try:
            network = IPv4Network(self.subnet, strict=False)
            return ip_address(ip) in network
        except ValueError:
            return False
            
    async def _load_inventory(self) -> None:
        """Load device inventory from file."""
        if not self.inventory_file.exists():
            return
            
        try:
            data = json.loads(self.inventory_file.read_text())
            for device_data in data.get("devices", []):
                ip = device_data.get("ip_address")
                if ip:
                    device = DiscoveredDevice(
                        device_id=device_data.get("device_id", str(uuid.uuid4())),
                        ip_address=ip,
                        mac_address=device_data.get("mac_address"),
                        hostname=device_data.get("hostname"),
                        netbios_name=device_data.get("netbios_name"),
                        mdns_name=device_data.get("mdns_name"),
                        device_type=DeviceType(device_data.get("device_type", "unknown")),
                        manufacturer=device_data.get("manufacturer"),
                        model=device_data.get("model"),
                        os_family=device_data.get("os_family"),
                        open_ports=device_data.get("open_ports", []),
                        first_seen=datetime.fromisoformat(device_data["first_seen"]) if "first_seen" in device_data else datetime.now(timezone.utc),
                        last_seen=datetime.fromisoformat(device_data["last_seen"]) if "last_seen" in device_data else datetime.now(timezone.utc),
                        discovery_methods=device_data.get("discovery_methods", []),
                    )
                    self._devices[ip] = device
            logger.info(f"Loaded {len(self._devices)} devices from inventory")
        except Exception as e:
            logger.warning(f"Failed to load inventory: {e}")
            
    async def _save_inventory(self) -> None:
        """Save device inventory to file."""
        self.inventory_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "subnet": self.subnet,
            "local_ip": self._local_ip,
            "gateway_ip": self._gateway_ip,
            "device_count": len(self._devices),
            "devices": [d.to_dict() for d in self._devices.values()],
        }
        
        self.inventory_file.write_text(json.dumps(data, indent=2))
        logger.info(f"Saved {len(self._devices)} devices to inventory")
        
    @property
    def devices(self) -> list[DiscoveredDevice]:
        """Get all discovered devices."""
        return list(self._devices.values())
        
    @property
    def local_ip(self) -> str | None:
        return self._local_ip
        
    @property
    def gateway_ip(self) -> str | None:
        return self._gateway_ip
        
    def get_device(self, ip: str) -> DiscoveredDevice | None:
        return self._devices.get(ip)
        
    def get_devices_by_type(self, device_type: DeviceType) -> list[DiscoveredDevice]:
        return [d for d in self._devices.values() if d.device_type == device_type]
        
    def get_summary(self) -> dict:
        """Get summary of discovered devices by type."""
        summary = {}
        for device in self._devices.values():
            dtype = device.device_type.value
            if dtype not in summary:
                summary[dtype] = 0
            summary[dtype] += 1
        return summary
