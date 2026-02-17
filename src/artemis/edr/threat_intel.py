"""Threat Intelligence feed integration for Project Artemis.

Supports pulling IoCs from:
- abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker)
- AlienVault OTX (requires API key)
- Local custom feeds

IoC types: IP, domain, URL, hash (MD5/SHA1/SHA256)
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Set
from urllib.parse import urlparse

import aiohttp
import aiofiles

logger = logging.getLogger("artemis.edr.threat_intel")


class IoCType(Enum):
    """Type of Indicator of Compromise."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"


@dataclass
class IoC:
    """An Indicator of Compromise."""
    type: IoCType
    value: str
    source: str
    tags: list[str] = field(default_factory=list)
    confidence: int = 50  # 0-100
    severity: str = "medium"  # low, medium, high, critical
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reference: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "value": self.value,
            "source": self.source,
            "tags": self.tags,
            "confidence": self.confidence,
            "severity": self.severity,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "reference": self.reference,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "IoC":
        return cls(
            type=IoCType(data["type"]),
            value=data["value"],
            source=data["source"],
            tags=data.get("tags", []),
            confidence=data.get("confidence", 50),
            severity=data.get("severity", "medium"),
            description=data.get("description"),
            first_seen=datetime.fromisoformat(data["first_seen"]) if data.get("first_seen") else None,
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            reference=data.get("reference"),
        )


class ThreatIntelFeed:
    """Threat intelligence feed manager."""
    
    # Free feeds (no API key required)
    FREE_FEEDS = {
        "urlhaus": {
            "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
            "type": "urlhaus",
            "description": "abuse.ch URLhaus - malicious URLs",
        },
        "feodo_ipblocklist": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "type": "feodo",
            "description": "Feodo Tracker - botnet C2 IPs",
        },
        "threatfox_iocs": {
            "url": "https://threatfox.abuse.ch/downloads/iocs/",
            "type": "threatfox_csv",
            "description": "ThreatFox - crowdsourced IoCs",
        },
        "malwarebazaar_recent": {
            "url": "https://bazaar.abuse.ch/export/csv/recent/",
            "type": "malwarebazaar_csv", 
            "description": "MalwareBazaar - recent malware samples",
        },
        "blocklist_de": {
            "url": "https://lists.blocklist.de/lists/all.txt",
            "type": "ip_list",
            "description": "blocklist.de - attacking IPs",
        },
        "emerging_threats_compromised": {
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "type": "ip_list",
            "description": "Emerging Threats - compromised IPs",
        },
    }
    
    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the threat intel feed manager.
        
        Args:
            data_dir: Directory to store IoC database
        """
        self.data_dir = data_dir or Path("data/threat_intel")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.ioc_file = self.data_dir / "iocs.json"
        self.state_file = self.data_dir / "state.json"
        
        # In-memory lookup sets for fast matching
        self._ips: Set[str] = set()
        self._domains: Set[str] = set()
        self._urls: Set[str] = set()
        self._hashes: Set[str] = set()
        
        # Full IoC storage
        self._iocs: dict[str, IoC] = {}
        
        # Statistics
        self.stats = {
            "total_iocs": 0,
            "iocs_by_type": {},
            "iocs_by_source": {},
            "last_update": None,
            "feeds_status": {},
        }
        
        self._load_data()
    
    def _load_data(self):
        """Load IoC data from disk."""
        if self.ioc_file.exists():
            try:
                with open(self.ioc_file) as f:
                    data = json.load(f)
                    for key, ioc_data in data.items():
                        ioc = IoC.from_dict(ioc_data)
                        self._iocs[key] = ioc
                        self._add_to_lookup(ioc)
                
                self._update_stats()
                logger.info(f"Loaded {len(self._iocs)} IoCs from disk")
            except Exception as e:
                logger.error(f"Failed to load IoC data: {e}")
        
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    self.stats = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
    
    def _save_data(self):
        """Save IoC data to disk."""
        try:
            with open(self.ioc_file, "w") as f:
                json.dump({k: v.to_dict() for k, v in self._iocs.items()}, f)
        except Exception as e:
            logger.error(f"Failed to save IoC data: {e}")
        
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.stats, f)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
    
    def _add_to_lookup(self, ioc: IoC):
        """Add IoC to lookup sets."""
        value_lower = ioc.value.lower()
        
        if ioc.type == IoCType.IP:
            self._ips.add(value_lower)
        elif ioc.type == IoCType.DOMAIN:
            self._domains.add(value_lower)
        elif ioc.type == IoCType.URL:
            self._urls.add(value_lower)
        elif ioc.type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
            self._hashes.add(value_lower)
    
    def _update_stats(self):
        """Update statistics."""
        self.stats["total_iocs"] = len(self._iocs)
        self.stats["iocs_by_type"] = {}
        self.stats["iocs_by_source"] = {}
        
        for ioc in self._iocs.values():
            ioc_type = ioc.type.value
            self.stats["iocs_by_type"][ioc_type] = self.stats["iocs_by_type"].get(ioc_type, 0) + 1
            self.stats["iocs_by_source"][ioc.source] = self.stats["iocs_by_source"].get(ioc.source, 0) + 1
    
    def _make_key(self, ioc_type: IoCType, value: str) -> str:
        """Create unique key for an IoC."""
        return f"{ioc_type.value}:{value.lower()}"
    
    def add_ioc(self, ioc: IoC) -> bool:
        """Add a single IoC to the database.
        
        Returns:
            True if added, False if already exists
        """
        key = self._make_key(ioc.type, ioc.value)
        
        if key in self._iocs:
            # Update last_seen if exists
            self._iocs[key].last_seen = datetime.now()
            return False
        
        self._iocs[key] = ioc
        self._add_to_lookup(ioc)
        return True
    
    def check_ip(self, ip: str) -> Optional[IoC]:
        """Check if an IP is in the threat intel database."""
        ip_lower = ip.lower().strip()
        if ip_lower in self._ips:
            key = self._make_key(IoCType.IP, ip_lower)
            return self._iocs.get(key)
        return None
    
    def check_domain(self, domain: str) -> Optional[IoC]:
        """Check if a domain is in the threat intel database."""
        domain_lower = domain.lower().strip()
        if domain_lower in self._domains:
            key = self._make_key(IoCType.DOMAIN, domain_lower)
            return self._iocs.get(key)
        return None
    
    def check_url(self, url: str) -> Optional[IoC]:
        """Check if a URL is in the threat intel database."""
        url_lower = url.lower().strip()
        if url_lower in self._urls:
            key = self._make_key(IoCType.URL, url_lower)
            return self._iocs.get(key)
        return None
    
    def check_hash(self, file_hash: str) -> Optional[IoC]:
        """Check if a file hash is in the threat intel database."""
        hash_lower = file_hash.lower().strip()
        if hash_lower in self._hashes:
            # Try each hash type
            for hash_type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
                key = self._make_key(hash_type, hash_lower)
                if key in self._iocs:
                    return self._iocs[key]
        return None
    
    def check_all(self, value: str) -> Optional[IoC]:
        """Check a value against all IoC types."""
        value = value.strip()
        
        # Try to determine type
        if self._is_ip(value):
            return self.check_ip(value)
        elif self._is_hash(value):
            return self.check_hash(value)
        elif self._is_url(value):
            return self.check_url(value)
        else:
            # Assume domain
            return self.check_domain(value)
    
    def _is_ip(self, value: str) -> bool:
        """Check if value looks like an IP address."""
        parts = value.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False
    
    def _is_hash(self, value: str) -> bool:
        """Check if value looks like a hash."""
        if re.match(r"^[a-fA-F0-9]{32}$", value):
            return True  # MD5
        if re.match(r"^[a-fA-F0-9]{40}$", value):
            return True  # SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", value):
            return True  # SHA256
        return False
    
    def _is_url(self, value: str) -> bool:
        """Check if value looks like a URL."""
        return value.startswith("http://") or value.startswith("https://")
    
    async def update_feed(self, feed_name: str) -> int:
        """Update a specific feed.
        
        Args:
            feed_name: Name of the feed to update
            
        Returns:
            Number of new IoCs added
        """
        if feed_name not in self.FREE_FEEDS:
            raise ValueError(f"Unknown feed: {feed_name}")
        
        feed = self.FREE_FEEDS[feed_name]
        feed_type = feed["type"]
        url = feed["url"]
        
        logger.info(f"Updating feed: {feed_name}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as response:
                    if response.status != 200:
                        logger.error(f"Feed {feed_name} returned status {response.status}")
                        self.stats["feeds_status"][feed_name] = {
                            "status": "error",
                            "message": f"HTTP {response.status}",
                            "last_attempt": datetime.now().isoformat(),
                        }
                        return 0
                    
                    content = await response.text()
            
            # Parse based on feed type
            new_iocs = 0
            
            if feed_type == "urlhaus":
                new_iocs = self._parse_urlhaus(content, feed_name)
            elif feed_type == "feodo":
                new_iocs = self._parse_feodo(content, feed_name)
            elif feed_type == "ip_list":
                new_iocs = self._parse_ip_list(content, feed_name)
            elif feed_type == "threatfox_csv":
                new_iocs = self._parse_threatfox_csv(content, feed_name)
            elif feed_type == "malwarebazaar_csv":
                new_iocs = self._parse_malwarebazaar_csv(content, feed_name)
            
            self.stats["feeds_status"][feed_name] = {
                "status": "success",
                "new_iocs": new_iocs,
                "last_update": datetime.now().isoformat(),
            }
            
            self._update_stats()
            self._save_data()
            
            logger.info(f"Feed {feed_name}: added {new_iocs} new IoCs")
            return new_iocs
            
        except asyncio.TimeoutError:
            logger.error(f"Feed {feed_name} timed out")
            self.stats["feeds_status"][feed_name] = {
                "status": "error",
                "message": "Timeout",
                "last_attempt": datetime.now().isoformat(),
            }
            return 0
        except Exception as e:
            logger.error(f"Failed to update feed {feed_name}: {e}")
            self.stats["feeds_status"][feed_name] = {
                "status": "error",
                "message": str(e),
                "last_attempt": datetime.now().isoformat(),
            }
            return 0
    
    def _parse_urlhaus(self, content: str, source: str) -> int:
        """Parse URLhaus JSON feed."""
        try:
            data = json.loads(content)
            new_count = 0
            
            for entry in data.get("urls", []):
                url = entry.get("url", "")
                if not url:
                    continue
                
                ioc = IoC(
                    type=IoCType.URL,
                    value=url,
                    source=source,
                    tags=entry.get("tags", []),
                    severity="high",
                    description=f"URLhaus: {entry.get('threat', 'malware')}",
                    first_seen=datetime.fromisoformat(entry["dateadded"].replace(" ", "T")) if entry.get("dateadded") else None,
                    reference=f"https://urlhaus.abuse.ch/url/{entry.get('id', '')}",
                )
                
                if self.add_ioc(ioc):
                    new_count += 1
                
                # Also extract domain
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        domain_ioc = IoC(
                            type=IoCType.DOMAIN,
                            value=parsed.hostname,
                            source=source,
                            tags=entry.get("tags", []),
                            severity="high",
                            description=f"URLhaus domain: {entry.get('threat', 'malware')}",
                        )
                        if self.add_ioc(domain_ioc):
                            new_count += 1
                except:
                    pass
            
            return new_count
        except Exception as e:
            logger.error(f"Failed to parse URLhaus: {e}")
            return 0
    
    def _parse_feodo(self, content: str, source: str) -> int:
        """Parse Feodo Tracker JSON feed."""
        try:
            data = json.loads(content)
            new_count = 0
            
            for entry in data:
                ip = entry.get("ip_address", "")
                if not ip:
                    continue
                
                ioc = IoC(
                    type=IoCType.IP,
                    value=ip,
                    source=source,
                    tags=[entry.get("malware", "botnet")],
                    severity="critical",
                    confidence=90,
                    description=f"Feodo Tracker C2: {entry.get('malware', 'unknown')}",
                    first_seen=datetime.fromisoformat(entry["first_seen"].replace(" ", "T")) if entry.get("first_seen") else None,
                    last_seen=datetime.fromisoformat(entry["last_online"].replace(" ", "T")) if entry.get("last_online") else None,
                )
                
                if self.add_ioc(ioc):
                    new_count += 1
            
            return new_count
        except Exception as e:
            logger.error(f"Failed to parse Feodo: {e}")
            return 0
    
    def _parse_ip_list(self, content: str, source: str) -> int:
        """Parse simple IP list (one per line)."""
        new_count = 0
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Extract IP (might have additional info after)
            ip = line.split()[0] if line else ""
            
            if not self._is_ip(ip):
                continue
            
            ioc = IoC(
                type=IoCType.IP,
                value=ip,
                source=source,
                severity="high",
                description=f"Blocklist: {source}",
            )
            
            if self.add_ioc(ioc):
                new_count += 1
        
        return new_count
    
    def _parse_threatfox_csv(self, content: str, source: str) -> int:
        """Parse ThreatFox CSV export."""
        new_count = 0
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith('"first_seen'):
                continue
            
            try:
                # CSV format: first_seen,ioc_type,ioc,threat_type,malware,...
                parts = line.replace('"', '').split(",")
                if len(parts) < 5:
                    continue
                
                ioc_type_str = parts[1].strip()
                ioc_value = parts[2].strip()
                threat_type = parts[3].strip()
                malware = parts[4].strip() if len(parts) > 4 else "unknown"
                
                # Map type
                if "ip" in ioc_type_str.lower():
                    ioc_type = IoCType.IP
                elif "domain" in ioc_type_str.lower():
                    ioc_type = IoCType.DOMAIN
                elif "url" in ioc_type_str.lower():
                    ioc_type = IoCType.URL
                elif "md5" in ioc_type_str.lower():
                    ioc_type = IoCType.MD5
                elif "sha256" in ioc_type_str.lower():
                    ioc_type = IoCType.SHA256
                else:
                    continue
                
                ioc = IoC(
                    type=ioc_type,
                    value=ioc_value,
                    source=source,
                    tags=[malware, threat_type],
                    severity="high",
                    description=f"ThreatFox: {malware} - {threat_type}",
                )
                
                if self.add_ioc(ioc):
                    new_count += 1
                    
            except Exception:
                continue
        
        return new_count
    
    def _parse_malwarebazaar_csv(self, content: str, source: str) -> int:
        """Parse MalwareBazaar CSV export."""
        new_count = 0
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            try:
                # CSV format varies, but typically: first_seen,sha256,md5,sha1,...
                parts = line.replace('"', '').split(",")
                if len(parts) < 4:
                    continue
                
                sha256 = parts[1].strip() if len(parts) > 1 else ""
                md5 = parts[2].strip() if len(parts) > 2 else ""
                sha1 = parts[3].strip() if len(parts) > 3 else ""
                signature = parts[7].strip() if len(parts) > 7 else "malware"
                
                if sha256 and len(sha256) == 64:
                    ioc = IoC(
                        type=IoCType.SHA256,
                        value=sha256,
                        source=source,
                        tags=[signature],
                        severity="critical",
                        description=f"MalwareBazaar: {signature}",
                    )
                    if self.add_ioc(ioc):
                        new_count += 1
                
                if md5 and len(md5) == 32:
                    ioc = IoC(
                        type=IoCType.MD5,
                        value=md5,
                        source=source,
                        tags=[signature],
                        severity="critical",
                        description=f"MalwareBazaar: {signature}",
                    )
                    if self.add_ioc(ioc):
                        new_count += 1
                        
            except Exception:
                continue
        
        return new_count
    
    async def update_all_feeds(self) -> dict[str, int]:
        """Update all configured feeds.
        
        Returns:
            Dictionary of feed_name -> new IoC count
        """
        results = {}
        
        for feed_name in self.FREE_FEEDS:
            try:
                count = await self.update_feed(feed_name)
                results[feed_name] = count
            except Exception as e:
                logger.error(f"Failed to update {feed_name}: {e}")
                results[feed_name] = -1
        
        self.stats["last_update"] = datetime.now().isoformat()
        self._save_data()
        
        return results
    
    def get_stats(self) -> dict:
        """Get feed statistics."""
        return {
            **self.stats,
            "lookup_sets": {
                "ips": len(self._ips),
                "domains": len(self._domains),
                "urls": len(self._urls),
                "hashes": len(self._hashes),
            },
        }
    
    def search(
        self,
        query: Optional[str] = None,
        ioc_type: Optional[IoCType] = None,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[IoC]:
        """Search IoCs."""
        results = []
        
        for ioc in self._iocs.values():
            if ioc_type and ioc.type != ioc_type:
                continue
            if source and ioc.source != source:
                continue
            if severity and ioc.severity != severity:
                continue
            if query and query.lower() not in ioc.value.lower():
                continue
            
            results.append(ioc)
            
            if len(results) >= limit:
                break
        
        return results
    
    def clear(self):
        """Clear all IoC data."""
        self._iocs.clear()
        self._ips.clear()
        self._domains.clear()
        self._urls.clear()
        self._hashes.clear()
        
        if self.ioc_file.exists():
            self.ioc_file.unlink()
        
        self.stats = {
            "total_iocs": 0,
            "iocs_by_type": {},
            "iocs_by_source": {},
            "last_update": None,
            "feeds_status": {},
        }
        self._save_data()
