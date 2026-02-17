"""
File Scanner - Continuous malware and threat hunting.
Integrates with AI for intelligent file analysis.
"""

import asyncio
import hashlib
import logging
import math
import os
import platform
import struct
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Generator
from dataclasses import dataclass, field

logger = logging.getLogger("artemis.agent.scanner")


# Known malicious hashes (sample - would be much larger in production)
KNOWN_MALICIOUS_HASHES = {
    # Example hashes - these would come from threat intel feeds
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".com", ".pif",
    ".hta", ".cpl", ".msc", ".jar", ".vbe", ".ws",
}

# High-risk locations
HIGH_RISK_PATHS = [
    "temp", "tmp", "downloads", "appdata\\local\\temp",
    "appdata\\roaming", "programdata", "startup",
]


@dataclass
class ScanResult:
    """Result of file scan."""
    path: str
    filename: str
    size: int
    hash_md5: str
    hash_sha256: str
    entropy: float
    is_executable: bool
    is_suspicious: bool
    is_malicious: bool
    threat_name: str = ""
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    pe_info: dict = field(default_factory=dict)
    ai_analysis: dict = field(default_factory=dict)


@dataclass
class ScanStats:
    """Scan statistics."""
    files_scanned: int = 0
    files_clean: int = 0
    files_suspicious: int = 0
    files_malicious: int = 0
    bytes_scanned: int = 0
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0


class FileScanner:
    """
    Comprehensive file scanner with AI integration.
    
    Features:
    - Hash-based detection
    - Entropy analysis
    - PE header analysis
    - Signature detection
    - AI-powered analysis
    - Continuous monitoring
    """
    
    def __init__(
        self,
        model: str = "deepseek-r1:70b",
        provider: str = "ollama",
        max_file_size_mb: int = 100,
        enable_ai_analysis: bool = True,
        scan_archives: bool = True,
    ):
        self.model = model
        self.provider = provider
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.enable_ai_analysis = enable_ai_analysis
        self.scan_archives = scan_archives
        
        self._running = False
        self._scan_queue: asyncio.Queue = asyncio.Queue()
        
        # Results
        self.results: list[ScanResult] = []
        self.malicious_files: list[ScanResult] = []
        self.suspicious_files: list[ScanResult] = []
        
        # Statistics
        self.stats = ScanStats()
        
        # Callbacks
        self._on_malicious: list[callable] = []
        self._on_suspicious: list[callable] = []
        self._on_scan_complete: list[callable] = []
        
        # YARA rules (simplified patterns)
        self._yara_patterns = self._load_yara_patterns()
    
    def _load_yara_patterns(self) -> list[dict]:
        """Load YARA-like detection patterns."""
        return [
            {
                "name": "Suspicious_PowerShell",
                "strings": [
                    b"-encodedcommand",
                    b"-enc ",
                    b"invoke-expression",
                    b"downloadstring",
                    b"iex(",
                    b"bypass",
                    b"hidden",
                ],
                "description": "Suspicious PowerShell patterns",
            },
            {
                "name": "Mimikatz_Indicators",
                "strings": [
                    b"sekurlsa",
                    b"logonpasswords",
                    b"mimikatz",
                    b"gentilkiwi",
                ],
                "description": "Mimikatz credential dumping tool",
            },
            {
                "name": "Reverse_Shell",
                "strings": [
                    b"socket.socket",
                    b"subprocess.popen",
                    b"/bin/sh",
                    b"cmd.exe /c",
                    b"nc -e",
                    b"ncat -e",
                ],
                "description": "Reverse shell indicators",
            },
            {
                "name": "Persistence_Registry",
                "strings": [
                    b"currentversion\\run",
                    b"currentversion\\runonce",
                    b"winlogon\\shell",
                    b"userinit",
                ],
                "description": "Registry persistence mechanisms",
            },
            {
                "name": "Ransomware_Indicators",
                "strings": [
                    b"your files have been encrypted",
                    b"bitcoin",
                    b"pay the ransom",
                    b"decrypt your files",
                    b".onion",
                ],
                "description": "Ransomware indicators",
            },
        ]
    
    async def start_continuous_scan(
        self,
        paths: list[str] = None,
        interval_minutes: int = 60,
    ):
        """Start continuous background scanning."""
        self._running = True
        
        if paths is None:
            paths = self._get_default_scan_paths()
        
        logger.info(f"Starting continuous scan of {len(paths)} paths")
        
        while self._running:
            await self.scan_paths(paths)
            await asyncio.sleep(interval_minutes * 60)
    
    def stop(self):
        """Stop continuous scanning."""
        self._running = False
    
    async def scan_paths(self, paths: list[str]) -> ScanStats:
        """Scan multiple paths."""
        self.stats = ScanStats(start_time=datetime.now(timezone.utc).isoformat())
        
        for path in paths:
            if os.path.isfile(path):
                await self.scan_file(path)
            elif os.path.isdir(path):
                await self.scan_directory(path)
        
        self.stats.end_time = datetime.now(timezone.utc).isoformat()
        
        # Calculate duration
        start = datetime.fromisoformat(self.stats.start_time.replace("Z", "+00:00"))
        end = datetime.fromisoformat(self.stats.end_time.replace("Z", "+00:00"))
        self.stats.duration_seconds = (end - start).total_seconds()
        
        # Notify
        for cb in self._on_scan_complete:
            try:
                await cb(self.stats)
            except Exception:
                pass
        
        return self.stats
    
    async def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        extensions: set = None,
    ):
        """Scan directory for threats."""
        try:
            for root, dirs, files in os.walk(path):
                # Skip certain directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d.lower() not in {
                    'node_modules', '.git', '__pycache__', 'venv', '.venv'
                }]
                
                for filename in files:
                    filepath = os.path.join(root, filename)
                    
                    # Filter by extension if specified
                    if extensions:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext not in extensions:
                            continue
                    
                    await self.scan_file(filepath)
                    
                    # Yield control periodically
                    if self.stats.files_scanned % 100 == 0:
                        await asyncio.sleep(0.01)
                
                if not recursive:
                    break
                    
        except PermissionError:
            pass
        except Exception as e:
            logger.error(f"Directory scan error {path}: {e}")
    
    async def scan_file(self, filepath: str) -> Optional[ScanResult]:
        """Scan a single file."""
        try:
            path = Path(filepath)
            
            if not path.exists() or not path.is_file():
                return None
            
            # Skip if too large
            size = path.stat().st_size
            if size > self.max_file_size:
                return None
            
            if size == 0:
                return None
            
            self.stats.files_scanned += 1
            self.stats.bytes_scanned += size
            
            # Read file
            try:
                content = path.read_bytes()
            except PermissionError:
                return None
            
            # Calculate hashes
            hash_md5 = hashlib.md5(content).hexdigest()
            hash_sha256 = hashlib.sha256(content).hexdigest()
            
            # Calculate entropy
            entropy = self._calculate_entropy(content)
            
            # Check file type
            ext = path.suffix.lower()
            is_executable = ext in SUSPICIOUS_EXTENSIONS
            
            # Initialize result
            result = ScanResult(
                path=str(path),
                filename=path.name,
                size=size,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                entropy=entropy,
                is_executable=is_executable,
                is_suspicious=False,
                is_malicious=False,
            )
            
            # Check known malicious hashes
            if hash_md5 in KNOWN_MALICIOUS_HASHES:
                result.is_malicious = True
                result.threat_name = "Known Malware"
                result.confidence = 1.0
                result.indicators.append("Known malicious hash")
            
            # Check YARA-like patterns
            matched_rules = self._check_patterns(content)
            if matched_rules:
                result.is_suspicious = True
                result.indicators.extend([f"Pattern: {r['name']}" for r in matched_rules])
                
                # Multiple matches increase confidence
                if len(matched_rules) >= 2:
                    result.is_malicious = True
                    result.threat_name = matched_rules[0]["name"]
                    result.confidence = min(0.9, 0.5 + len(matched_rules) * 0.2)
            
            # High entropy check (packed/encrypted)
            if entropy > 7.5 and is_executable:
                result.is_suspicious = True
                result.indicators.append(f"High entropy: {entropy:.2f}")
            
            # PE analysis for executables
            if is_executable and ext in {".exe", ".dll", ".sys"}:
                pe_info = self._analyze_pe(content)
                result.pe_info = pe_info
                
                if pe_info.get("suspicious_imports"):
                    result.is_suspicious = True
                    result.indicators.append("Suspicious imports")
                
                if pe_info.get("no_signature"):
                    result.indicators.append("No digital signature")
            
            # Check path risk
            path_lower = str(path).lower()
            for risk_path in HIGH_RISK_PATHS:
                if risk_path in path_lower:
                    if result.is_suspicious:
                        result.indicators.append(f"High-risk location: {risk_path}")
                    break
            
            # AI analysis for suspicious files
            if result.is_suspicious and self.enable_ai_analysis:
                ai_result = await self._ai_analyze_file(result, content[:4096])
                result.ai_analysis = ai_result
                
                if ai_result.get("verdict") == "malicious":
                    result.is_malicious = True
                    result.threat_name = ai_result.get("threat_name", "AI Detected Threat")
                    result.confidence = max(result.confidence, ai_result.get("confidence", 0.7))
            
            # Store result
            self.results.append(result)
            
            if result.is_malicious:
                self.stats.files_malicious += 1
                self.malicious_files.append(result)
                
                for cb in self._on_malicious:
                    try:
                        await cb(result)
                    except Exception:
                        pass
                        
            elif result.is_suspicious:
                self.stats.files_suspicious += 1
                self.suspicious_files.append(result)
                
                for cb in self._on_suspicious:
                    try:
                        await cb(result)
                    except Exception:
                        pass
            else:
                self.stats.files_clean += 1
            
            return result
            
        except Exception as e:
            logger.debug(f"Scan error {filepath}: {e}")
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        
        for count in freq.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return round(entropy, 2)
    
    def _check_patterns(self, content: bytes) -> list[dict]:
        """Check content against detection patterns."""
        matched = []
        content_lower = content.lower()
        
        for rule in self._yara_patterns:
            for pattern in rule["strings"]:
                if pattern.lower() in content_lower:
                    matched.append(rule)
                    break
        
        return matched
    
    def _analyze_pe(self, content: bytes) -> dict:
        """Analyze PE file structure."""
        result = {
            "is_pe": False,
            "machine": "",
            "subsystem": "",
            "imports": [],
            "suspicious_imports": False,
            "no_signature": True,
        }
        
        try:
            # Check MZ header
            if content[:2] != b"MZ":
                return result
            
            result["is_pe"] = True
            
            # Get PE offset
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            
            if content[pe_offset:pe_offset+4] != b"PE\x00\x00":
                return result
            
            # Machine type
            machine = struct.unpack_from("<H", content, pe_offset + 4)[0]
            machines = {0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM"}
            result["machine"] = machines.get(machine, f"0x{machine:04x}")
            
            # Suspicious import DLLs
            suspicious_dlls = {
                b"ws2_32.dll",  # Networking
                b"wininet.dll",  # Internet
                b"crypt32.dll",  # Crypto
                b"advapi32.dll",  # Registry
            }
            
            content_lower = content.lower()
            for dll in suspicious_dlls:
                if dll in content_lower:
                    result["imports"].append(dll.decode())
            
            if len(result["imports"]) >= 3:
                result["suspicious_imports"] = True
                
        except Exception:
            pass
        
        return result
    
    async def _ai_analyze_file(self, result: ScanResult, sample: bytes) -> dict:
        """AI analysis of suspicious file."""
        try:
            import httpx
            
            # Prepare safe sample representation
            sample_hex = sample[:256].hex()
            
            prompt = f"""Analyze this potentially malicious file:

Filename: {result.filename}
Size: {result.size} bytes
MD5: {result.hash_md5}
Entropy: {result.entropy}
Indicators: {', '.join(result.indicators)}
PE Info: {result.pe_info}
First 256 bytes (hex): {sample_hex}

Provide security verdict as JSON:
{{
    "verdict": "clean|suspicious|malicious",
    "threat_name": "name if malicious",
    "confidence": 0.0-1.0,
    "description": "brief explanation",
    "recommended_action": "quarantine|delete|monitor|ignore"
}}"""
            
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
                    text = data.get("response", "")
                    
                    import re
                    match = re.search(r'\{[\s\S]*\}', text)
                    if match:
                        return json.loads(match.group())
                        
        except Exception as e:
            logger.error(f"AI file analysis failed: {e}")
        
        return {"verdict": "unknown"}
    
    def _get_default_scan_paths(self) -> list[str]:
        """Get default paths to scan."""
        if platform.system() == "Windows":
            return [
                os.path.expandvars("%USERPROFILE%\\Downloads"),
                os.path.expandvars("%USERPROFILE%\\Desktop"),
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%APPDATA%"),
                os.path.expandvars("%LOCALAPPDATA%\\Temp"),
            ]
        else:
            return [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                "/tmp",
            ]
    
    def on_malicious(self, callback):
        self._on_malicious.append(callback)
    
    def on_suspicious(self, callback):
        self._on_suspicious.append(callback)
    
    def on_scan_complete(self, callback):
        self._on_scan_complete.append(callback)
    
    def get_scan_summary(self) -> dict:
        """Get scan summary."""
        return {
            "files_scanned": self.stats.files_scanned,
            "files_clean": self.stats.files_clean,
            "files_suspicious": self.stats.files_suspicious,
            "files_malicious": self.stats.files_malicious,
            "bytes_scanned": self.stats.bytes_scanned,
            "duration_seconds": self.stats.duration_seconds,
            "malicious_files": [
                {
                    "path": r.path,
                    "threat": r.threat_name,
                    "confidence": r.confidence,
                }
                for r in self.malicious_files[-20:]
            ],
            "suspicious_files": [
                {
                    "path": r.path,
                    "indicators": r.indicators[:3],
                }
                for r in self.suspicious_files[-20:]
            ],
        }


# Required for AI analysis
import json
