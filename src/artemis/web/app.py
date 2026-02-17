"""FastAPI web application for Project Artemis."""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request

logger = logging.getLogger("artemis.web")
from fastapi.responses import HTMLResponse, JSONResponse, ORJSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from artemis.core import Artemis
from artemis.models import RuleFormat, Severity
from artemis.web.realtime import router as realtime_router, state as security_state
from artemis.web.monitor import get_monitor, shutdown_monitor, NetworkMonitor


# Get paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup: Initialize the network monitor
    settings = load_settings()
    network_range = settings.get("network_range", "192.168.4.0/24")
    monitor = get_monitor(network_range)
    
    # Register callbacks to update security_state
    async def on_threat(threat):
        await security_state.add_threat({
            "id": threat.id,
            "title": threat.title,
            "description": threat.description,
            "severity": threat.severity,
            "source": threat.source_ip,
            "type": threat.category,
        })
    
    monitor.on_threat(on_threat)
    print(f"🛡️ Artemis Monitor started - watching {network_range}")
    
    yield
    
    # Shutdown
    shutdown_monitor()
    print("🛡️ Artemis Monitor stopped")


# Create FastAPI app with ORJSON for fast serialization
app = FastAPI(
    title="Project Artemis",
    description="Autonomous AI-powered security operations platform",
    version="2.0.0",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

# Include real-time WebSocket routes
app.include_router(realtime_router)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class GenerateRequest(BaseModel):
    """Request model for rule generation."""
    description: str
    format: str = "sigma"
    provider: str = "ollama"
    model: str = "qwen3:14b"
    context: Optional[str] = None
    indicators: Optional[list[str]] = None
    severity: Optional[str] = None


class GenerateResponse(BaseModel):
    """Response model for rule generation."""
    success: bool
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_content: Optional[str] = None
    format: Optional[str] = None
    severity: Optional[str] = None
    mitre: Optional[list[dict]] = None
    is_valid: bool = False
    validation_errors: list[str] = []
    model_used: Optional[str] = None
    generation_time_ms: Optional[int] = None
    error: Optional[str] = None


class ValidateRequest(BaseModel):
    """Request model for rule validation."""
    content: str
    format: str = "sigma"


class ValidateResponse(BaseModel):
    """Response model for rule validation."""
    is_valid: bool
    errors: list[str]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Redirect to dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the real-time security dashboard."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    """Serve the rule generation interface."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/formats")
async def get_formats():
    """Get available rule formats."""
    return {
        "formats": [
            {"id": "sigma", "name": "Sigma", "description": "Generic SIEM format"},
            {"id": "yara", "name": "YARA", "description": "Malware/file patterns"},
            {"id": "splunk", "name": "Splunk SPL", "description": "Splunk queries"},
            {"id": "kql", "name": "KQL", "description": "Microsoft Sentinel/Defender"},
            {"id": "snort", "name": "Snort/Suricata", "description": "Network IDS rules"},
        ]
    }


@app.get("/api/providers")
async def get_providers():
    """Get available LLM providers."""
    return {
        "providers": [
            {
                "id": "ollama",
                "name": "Ollama (Local)",
                "models": ["qwen3:14b", "qwen3:32b", "deepseek-r1:70b"],
            },
            {
                "id": "anthropic", 
                "name": "Anthropic",
                "models": ["claude-sonnet-4-20250514"],
            },
            {
                "id": "openai",
                "name": "OpenAI", 
                "models": ["gpt-4o"],
            },
        ]
    }


@app.post("/api/generate", response_model=GenerateResponse)
async def generate_rule(req: GenerateRequest):
    """Generate a detection rule."""
    try:
        # Validate format
        try:
            rule_format = RuleFormat(req.format)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid format: {req.format}")
        
        # Initialize Artemis
        engine = Artemis(provider=req.provider, model=req.model)
        
        # Generate rule
        result = await engine.generate(
            description=req.description,
            format=rule_format,
            context=req.context,
            indicators=req.indicators,
            severity_hint=req.severity,
        )
        
        if result.success and result.rule:
            return GenerateResponse(
                success=True,
                rule_id=result.rule.id,
                rule_name=result.rule.name,
                rule_content=result.rule.content,
                format=result.rule.format.value,
                severity=result.rule.severity.value,
                mitre=[m.model_dump() for m in result.rule.mitre] if result.rule.mitre else [],
                is_valid=result.rule.is_valid,
                validation_errors=result.rule.validation_errors or [],
                model_used=result.model_used,
                generation_time_ms=result.generation_time_ms,
            )
        else:
            return GenerateResponse(
                success=False,
                error=result.error or "Unknown error",
                model_used=result.model_used,
                generation_time_ms=result.generation_time_ms,
            )
            
    except HTTPException:
        raise
    except Exception as e:
        return GenerateResponse(
            success=False,
            error=str(e),
        )


@app.post("/api/validate", response_model=ValidateResponse)
async def validate_rule(req: ValidateRequest):
    """Validate an existing rule."""
    try:
        from artemis.generators import (
            SigmaGenerator, YaraGenerator, SplunkGenerator, 
            KqlGenerator, SnortGenerator
        )
        from artemis.models import DetectionRule
        
        generators = {
            "sigma": SigmaGenerator,
            "yara": YaraGenerator,
            "splunk": SplunkGenerator,
            "kql": KqlGenerator,
            "snort": SnortGenerator,
        }
        
        if req.format not in generators:
            raise HTTPException(status_code=400, detail=f"Invalid format: {req.format}")
        
        # Create minimal rule for validation
        rule = DetectionRule(
            id="validation",
            name="Validation Check",
            description="",
            format=RuleFormat(req.format),
            content=req.content,
            severity=Severity.MEDIUM,
        )
        
        generator = generators[req.format](llm=None)
        is_valid, errors = generator.validate_rule(rule)
        
        return ValidateResponse(is_valid=is_valid, errors=errors)
        
    except HTTPException:
        raise
    except Exception as e:
        return ValidateResponse(is_valid=False, errors=[str(e)])


# ============================================================================
# AI Analysis Endpoints
# ============================================================================

class AIAnalysisRequest(BaseModel):
    """Request for AI analysis."""
    context: Optional[str] = None
    connections: Optional[list] = None
    threats: Optional[list] = None
    devices: Optional[list] = None
    model: str = "deepseek-r1:70b"


class AIAnalysisResponse(BaseModel):
    """AI analysis response."""
    success: bool
    analysis: Optional[str] = None
    risk_level: Optional[int] = None
    recommendations: list[str] = []
    error: Optional[str] = None


@app.post("/api/ai/analyze", response_model=AIAnalysisResponse)
async def ai_analyze_security(req: AIAnalysisRequest):
    """Run AI analysis on current security context."""
    from artemis.llm import get_provider
    
    try:
        provider = get_provider("ollama", model=req.model)
        
        # Build context
        context_parts = []
        
        if req.connections:
            suspicious = [c for c in req.connections if c.get('suspicious')]
            context_parts.append(f"Active connections: {len(req.connections)}")
            if suspicious:
                context_parts.append(f"Suspicious connections: {len(suspicious)}")
                for conn in suspicious[:5]:
                    context_parts.append(f"  - {conn.get('process', 'unknown')} -> {conn.get('remote', 'unknown')}")
        
        if req.threats:
            context_parts.append(f"Recent threats: {len(req.threats)}")
            for threat in req.threats[:5]:
                context_parts.append(f"  - [{threat.get('severity', 'unknown')}] {threat.get('title', 'Unknown threat')}")
        
        if req.devices:
            context_parts.append(f"Devices on network: {len(req.devices)}")
        
        if req.context:
            context_parts.append(f"Additional context: {req.context}")
        
        context_str = "\n".join(context_parts) if context_parts else "No specific context provided."
        
        system_prompt = """You are a cybersecurity analyst AI embedded in a home network security dashboard.
Your job is to analyze network activity and identify potential threats.
Be concise but thorough. Focus on actionable insights.
Format your response as:
RISK LEVEL: [1-10]
ANALYSIS: [brief analysis]
RECOMMENDATIONS:
- [action 1]
- [action 2]
"""
        
        prompt = f"""Analyze this network security context:

{context_str}

Provide your security assessment."""

        response = await provider.generate(prompt, system=system_prompt)
        
        # Parse response
        risk_level = 1
        recommendations = []
        
        lines = response.split('\n')
        for line in lines:
            if 'RISK LEVEL:' in line.upper():
                try:
                    risk_level = int(''.join(filter(str.isdigit, line.split(':')[1][:3])))
                except:
                    pass
            if line.strip().startswith('-'):
                recommendations.append(line.strip()[1:].strip())
        
        return AIAnalysisResponse(
            success=True,
            analysis=response,
            risk_level=min(10, max(1, risk_level)),
            recommendations=recommendations[:5],
        )
        
    except Exception as e:
        import traceback
        error_msg = str(e) if str(e) else f"{type(e).__name__}: {repr(e)}"
        logger.error(f"AI analysis error: {error_msg}\n{traceback.format_exc()}")
        return AIAnalysisResponse(
            success=False,
            error=error_msg or "Unknown error - check server logs",
        )


@app.post("/api/ai/analyze-connection")
async def ai_analyze_connection(
    process: str,
    remote: str,
    port: int,
    model: str = "qwen3:14b"  # Use faster model for quick analysis
):
    """Quick AI analysis of a specific connection."""
    from artemis.llm import get_provider
    
    try:
        provider = get_provider("ollama", model=model)
        
        prompt = f"""Is this network connection suspicious?
Process: {process}
Remote: {remote}
Port: {port}

Reply in 2-3 sentences: what this connection likely is, and if it's suspicious."""

        response = await provider.generate(prompt)
        
        return {
            "success": True,
            "analysis": response.strip(),
            "suspicious": any(word in response.lower() for word in ['suspicious', 'malicious', 'concerning', 'unusual']),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# Pentest API Endpoints
# ============================================================================

class PentestStartRequest(BaseModel):
    """Request to start a pentest."""
    target_url: str
    repo_path: Optional[str] = None
    model: str = "deepseek-r1:70b"
    provider: str = "ollama"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    parallel: bool = True


class PentestStatusResponse(BaseModel):
    """Pentest status response."""
    running: bool
    status: str
    current_agent: Optional[str] = None
    progress_percent: float = 0.0
    current_task: str = ""
    completed_agents: list[str] = []
    vulnerability_count: int = 0
    start_time: Optional[str] = None
    elapsed_seconds: Optional[float] = None


class VulnerabilityResponse(BaseModel):
    """Vulnerability finding."""
    id: str
    title: str
    type: str
    severity: str
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    description: str = ""
    exploited: bool = False


# Global pentest state
_pentest_pipeline = None
_pentest_task = None


@app.post("/api/pentest/start")
async def start_pentest(req: PentestStartRequest):
    """Start a new penetration test."""
    global _pentest_pipeline, _pentest_task
    
    if _pentest_pipeline is not None and _pentest_task is not None:
        if not _pentest_task.done():
            raise HTTPException(status_code=409, detail="Pentest already running")
    
    from artemis.pentest import PentestPipeline, PentestConfig
    
    # Build config
    credentials = None
    if req.username and req.password:
        credentials = {"username": req.username, "password": req.password}
    
    config = PentestConfig(
        target_url=req.target_url,
        repo_path=req.repo_path,
        provider=req.provider,
        model=req.model,
        login_url=req.login_url,
        credentials=credentials,
        parallel_agents=req.parallel,
    )
    
    # Progress callback that updates WebSocket state
    def on_progress(state):
        asyncio.create_task(security_state.update_pentest_state(state.to_dict()))
    
    # Log callback that streams logs to WebSocket
    def on_log(level, message):
        asyncio.create_task(security_state.add_pentest_log(level, message))
    
    _pentest_pipeline = PentestPipeline(config, on_progress=on_progress, on_log=on_log)
    
    # Start in background
    _pentest_task = asyncio.create_task(_pentest_pipeline.run())
    
    return {
        "success": True,
        "message": "Pentest started",
        "target": req.target_url,
        "output_dir": config.output_dir,
    }


@app.post("/api/pentest/cancel")
async def cancel_pentest():
    """Cancel the running pentest."""
    global _pentest_pipeline
    
    if _pentest_pipeline is None:
        raise HTTPException(status_code=404, detail="No pentest running")
    
    _pentest_pipeline.cancel()
    return {"success": True, "message": "Pentest cancellation requested"}


@app.get("/api/pentest/status", response_model=PentestStatusResponse)
async def get_pentest_status():
    """Get current pentest status."""
    global _pentest_pipeline, _pentest_task
    
    if _pentest_pipeline is None:
        return PentestStatusResponse(running=False, status="idle")
    
    state = _pentest_pipeline.state
    running = _pentest_task is not None and not _pentest_task.done()
    
    elapsed = None
    if state.start_time:
        from datetime import datetime, timezone
        elapsed = (datetime.now(timezone.utc) - state.start_time).total_seconds()
    
    return PentestStatusResponse(
        running=running,
        status=state.status.value,
        current_agent=state.current_agent,
        progress_percent=state.progress_percent,
        current_task=state.current_task,
        completed_agents=state.completed_agents,
        vulnerability_count=len(state.vulnerabilities),
        start_time=state.start_time.isoformat() if state.start_time else None,
        elapsed_seconds=elapsed,
    )


@app.get("/api/pentest/vulnerabilities")
async def get_pentest_vulnerabilities():
    """Get discovered vulnerabilities."""
    global _pentest_pipeline
    
    if _pentest_pipeline is None:
        return {"vulnerabilities": []}
    
    return {
        "vulnerabilities": [
            {
                "id": v.get("id", f"vuln-{i}"),
                "title": v.get("title", "Unknown"),
                "type": v.get("type", "unknown"),
                "severity": v.get("severity", "medium"),
                "endpoint": v.get("endpoint"),
                "parameter": v.get("parameter"),
                "description": v.get("description", ""),
                "exploited": v.get("exploited", False),
                "payload": v.get("payload"),
                "proof": v.get("exploit_proof"),
            }
            for i, v in enumerate(_pentest_pipeline.state.vulnerabilities)
        ]
    }


@app.get("/api/pentest/report")
async def get_pentest_report():
    """Get the pentest report content."""
    global _pentest_pipeline
    
    if _pentest_pipeline is None:
        raise HTTPException(status_code=404, detail="No pentest data")
    
    report_path = _pentest_pipeline.deliverables_dir / "pentest_report.md"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not yet generated")
    
    return {
        "content": report_path.read_text(),
        "html_path": str(_pentest_pipeline.deliverables_dir / "pentest_report.html"),
    }


@app.get("/api/pentest/sessions")
async def list_pentest_sessions():
    """List all pentest sessions."""
    from pathlib import Path
    import json
    
    sessions = []
    audit_dir = Path("./audit-logs")
    
    if audit_dir.exists():
        for session_file in audit_dir.rglob("session.json"):
            try:
                data = json.loads(session_file.read_text())
                data["path"] = str(session_file.parent)
                sessions.append(data)
            except Exception:
                pass
    
    return {"sessions": sessions}


@app.get("/api/pentest/tools")
async def get_pentest_tools():
    """Get available pentest tools status."""
    from artemis.pentest.tools import get_tools
    
    tools = get_tools()
    available = tools.get_available_tools()
    
    all_tools = ["nmap", "subfinder", "httpx", "katana", "ffuf", "gobuster", "sqlmap"]
    
    return {
        "tools": {
            tool: {
                "available": tool in available,
                "path": tools.TOOL_PATHS.get(tool),
            }
            for tool in all_tools
        },
        "available_count": len(available),
        "total_count": len(all_tools),
    }


# ============================================================================
# Device & Network API Endpoints
# ============================================================================

@app.get("/api/devices")
async def get_devices():
    """Get all discovered devices from monitor."""
    monitor = get_monitor()
    devices = monitor.get_devices()
    return {"devices": devices}


@app.get("/api/devices/{device_id}")
async def get_device(device_id: str):
    """Get specific device details."""
    device = security_state.devices.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.get("/api/connections")
async def get_connections():
    """Get active network connections using high-performance monitor."""
    monitor = get_monitor()
    connections = monitor.get_connections_fast()
    security_state.connections = connections
    return {"connections": connections}


@app.get("/api/threats")
async def get_threats():
    """Get recent threats from monitor."""
    monitor = get_monitor()
    threats = monitor.get_threats()
    return {"threats": threats}


@app.get("/api/traffic")
async def get_traffic():
    """Get traffic statistics using high-performance monitor."""
    monitor = get_monitor()
    stats = monitor.get_traffic_stats()
    await security_state.update_traffic(stats)
    return stats


@app.get("/api/topology")
async def get_topology():
    """Get network topology."""
    return security_state.network_topology


@app.get("/api/state")
async def get_full_state():
    """Get complete security state."""
    return security_state.get_full_state()


@app.post("/api/scan/network")
async def scan_network():
    """Trigger a network scan using high-performance monitor."""
    settings = load_settings()
    network_range = settings.get("network_range", "192.168.4.0/24")
    
    monitor = get_monitor(network_range)
    devices = monitor.scan_arp_table()
    
    # Update security state for each device
    for device in devices:
        await security_state.update_device(device["ip"], device)
    
    return {
        "success": True,
        "devices_found": len(devices),
        "network_range": network_range,
        "devices": devices,
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.1.5"}


# ============================================================================
# Settings Persistence
# ============================================================================

import json as json_module
from pathlib import Path

SETTINGS_FILE = Path(__file__).parent.parent.parent.parent / "settings.json"

DEFAULT_SETTINGS = {
    "provider": "ollama",
    "model": "deepseek-r1:70b",
    "scan_interval": 60,
    "network_range": "192.168.4.0/24",
    "auto_quarantine": False,
    "double_verify": True,
    "require_approval": True,
    "scan_path": "C:\\Users",
}


def load_settings() -> dict:
    """Load settings from file or return defaults."""
    try:
        if SETTINGS_FILE.exists():
            return json_module.loads(SETTINGS_FILE.read_text())
    except Exception as e:
        print(f"Failed to load settings: {e}")
    return DEFAULT_SETTINGS.copy()


def save_settings_to_file(settings: dict) -> bool:
    """Save settings to file."""
    try:
        SETTINGS_FILE.write_text(json_module.dumps(settings, indent=2))
        return True
    except Exception as e:
        print(f"Failed to save settings: {e}")
        return False


class SettingsRequest(BaseModel):
    """Settings update request."""
    provider: Optional[str] = None
    model: Optional[str] = None
    scan_interval: Optional[int] = None
    network_range: Optional[str] = None
    auto_quarantine: Optional[bool] = None
    double_verify: Optional[bool] = None
    require_approval: Optional[bool] = None
    scan_path: Optional[str] = None


@app.get("/api/settings")
async def get_settings():
    """Get current settings."""
    return load_settings()


@app.post("/api/settings")
async def update_settings(req: SettingsRequest):
    """Update and persist settings."""
    current = load_settings()
    
    # Update only provided fields
    if req.provider is not None:
        current["provider"] = req.provider
    if req.model is not None:
        current["model"] = req.model
    if req.scan_interval is not None:
        current["scan_interval"] = req.scan_interval
    if req.network_range is not None:
        current["network_range"] = req.network_range
    if req.auto_quarantine is not None:
        current["auto_quarantine"] = req.auto_quarantine
    if req.double_verify is not None:
        current["double_verify"] = req.double_verify
    if req.require_approval is not None:
        current["require_approval"] = req.require_approval
    if req.scan_path is not None:
        current["scan_path"] = req.scan_path
    
    if save_settings_to_file(current):
        return {"success": True, "settings": current}
    else:
        raise HTTPException(status_code=500, detail="Failed to save settings")


# ============================================================================
# File Scanner
# ============================================================================

class ScanRequest(BaseModel):
    """File scan request."""
    path: str
    deep: bool = False
    ai_analysis: bool = True
    recursive: bool = True


class ScanResult(BaseModel):
    """Scan result item."""
    file: str
    status: str
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[str] = None


_scan_results: list[dict] = []
_scan_running: bool = False


@app.post("/api/scan/files")
async def start_file_scan(req: ScanRequest):
    """Start a file scan in the specified directory."""
    global _scan_running, _scan_results
    
    import os
    import hashlib
    
    scan_path = Path(req.path)
    
    if not scan_path.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {req.path}")
    
    _scan_running = True
    _scan_results = []
    
    # Known suspicious patterns (basic heuristics)
    suspicious_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.pif', '.com'}
    suspicious_names = {'mimikatz', 'cobaltstrike', 'metasploit', 'nc.exe', 'netcat', 'psexec', 'payload', 'backdoor', 'trojan', 'keylogger'}
    
    files_scanned = 0
    threats_found = 0
    
    try:
        # Scan files
        if scan_path.is_file():
            files_to_scan = [scan_path]
        elif req.recursive:
            files_to_scan = list(scan_path.rglob("*"))[:1000]  # Limit to 1000 files
        else:
            files_to_scan = list(scan_path.glob("*"))
        
        for file_path in files_to_scan:
            if not file_path.is_file():
                continue
                
            files_scanned += 1
            file_name = file_path.name.lower()
            file_ext = file_path.suffix.lower()
            
            result = {
                "file": str(file_path),
                "status": "clean",
                "threat_type": None,
                "severity": None,
                "details": None,
            }
            
            # Check for suspicious extensions in unusual locations
            if file_ext in suspicious_extensions:
                # Check if in temp or download folders
                path_lower = str(file_path).lower()
                if any(x in path_lower for x in ['temp', 'tmp', 'download', 'appdata\\local', 'appdata\\roaming']):
                    result["status"] = "suspicious"
                    result["threat_type"] = "suspicious_location"
                    result["severity"] = "low"
                    result["details"] = f"Executable in suspicious location"
            
            # Check for known malicious tool names
            for sus_name in suspicious_names:
                if sus_name in file_name:
                    result["status"] = "malicious"
                    result["threat_type"] = "known_malicious"
                    result["severity"] = "high"
                    result["details"] = f"Matches known malicious tool pattern: {sus_name}"
                    threats_found += 1
                    
                    # Add to threats
                    await security_state.add_threat({
                        "title": f"Malicious file detected: {file_path.name}",
                        "description": result["details"],
                        "severity": "high",
                        "source": str(file_path),
                        "type": "malware",
                    })
                    break
            
            # Check for double extensions (e.g., document.pdf.exe)
            parts = file_name.rsplit('.', 2)
            if len(parts) > 2 and f".{parts[-1]}" in suspicious_extensions:
                result["status"] = "suspicious"
                result["threat_type"] = "double_extension"
                result["severity"] = "medium"
                result["details"] = "File has suspicious double extension"
                threats_found += 1
            
            _scan_results.append(result)
        
        return {
            "success": True,
            "files_scanned": files_scanned,
            "threats_found": threats_found,
            "results": _scan_results[:100],  # Return first 100
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        _scan_running = False


@app.get("/api/scan/results")
async def get_scan_results():
    """Get current scan results."""
    return {
        "running": _scan_running,
        "results": _scan_results,
        "total": len(_scan_results),
        "threats": sum(1 for r in _scan_results if r.get("status") in ["suspicious", "malicious"]),
    }


# =============================================================================
# RED TEAM / SHANNON INTEGRATION
# =============================================================================

# Lazy-load red team controller to avoid circular imports
_redteam_controller = None

def get_redteam_controller():
    """Get or create the red team controller."""
    global _redteam_controller
    if _redteam_controller is None:
        from artemis.redteam import RedTeamController
        project_dir = Path(__file__).parent.parent.parent.parent
        _redteam_controller = RedTeamController(data_dir=project_dir)
    return _redteam_controller


class LaunchJobRequest(BaseModel):
    """Request to launch a pentest job."""
    target: str
    mode: str = "recon"  # recon, vuln_scan, full_audit, counter_recon, counter_full
    config: Optional[dict] = None


class ApproveJobRequest(BaseModel):
    """Request to approve a job."""
    approved_by: str = "user"


@app.get("/api/redteam/status")
async def redteam_status():
    """Get red team system status."""
    try:
        controller = get_redteam_controller()
        stats = controller.get_stats()
        
        # Check Shannon availability
        shannon_available = False
        try:
            from artemis.redteam.shannon import ShannonEngine
            shannon_dir = Path(__file__).parent.parent.parent.parent / "shannon-integration"
            if shannon_dir.exists():
                engine = ShannonEngine(shannon_dir, controller.reports_dir)
                shannon_available = engine.is_available()
        except:
            pass
        
        return {
            "enabled": True,
            "shannon_available": shannon_available,
            "stats": stats,
        }
    except Exception as e:
        return {
            "enabled": False,
            "error": str(e),
        }


@app.get("/api/redteam/jobs")
async def list_redteam_jobs(status: Optional[str] = None, limit: int = 50):
    """List pentest jobs."""
    controller = get_redteam_controller()
    
    from artemis.redteam import JobStatus
    status_filter = JobStatus(status) if status else None
    
    jobs = controller.list_jobs(status=status_filter, limit=limit)
    return {
        "jobs": [j.to_dict() for j in jobs],
        "total": len(jobs),
    }


@app.post("/api/redteam/launch")
async def launch_redteam_job(req: LaunchJobRequest):
    """Launch a new pentest job."""
    controller = get_redteam_controller()
    
    from artemis.redteam import ScanMode, TriggerType
    
    try:
        mode = ScanMode(req.mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {req.mode}")
    
    try:
        job = await controller.create_job(
            target=req.target,
            mode=mode,
            trigger=TriggerType.MANUAL,
            config=req.config,
        )
        return {
            "success": True,
            "job": job.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/redteam/jobs/{job_id}")
async def get_redteam_job(job_id: str):
    """Get a specific job."""
    controller = get_redteam_controller()
    job = controller.get_job(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {"job": job.to_dict()}


@app.post("/api/redteam/jobs/{job_id}/approve")
async def approve_redteam_job(job_id: str, req: ApproveJobRequest):
    """Approve a job requiring approval."""
    controller = get_redteam_controller()
    
    try:
        job = await controller.approve_job(job_id, req.approved_by)
        return {
            "success": True,
            "job": job.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/redteam/jobs/{job_id}/cancel")
async def cancel_redteam_job(job_id: str):
    """Cancel a job."""
    controller = get_redteam_controller()
    
    try:
        job = await controller.cancel_job(job_id)
        return {
            "success": True,
            "job": job.to_dict(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/redteam/jobs/{job_id}/report")
async def get_redteam_report(job_id: str):
    """Get the report for a completed job."""
    controller = get_redteam_controller()
    
    job = controller.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    report = controller.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not available")
    
    return {
        "job_id": job_id,
        "report": report,
        "format": "markdown",
    }


@app.post("/api/redteam/quick-recon")
async def quick_recon(target: str):
    """Quick reconnaissance scan."""
    controller = get_redteam_controller()
    job = await controller.quick_recon(target)
    return {"success": True, "job": job.to_dict()}


@app.post("/api/redteam/counter-attack")
async def counter_attack(target: str, full: bool = False):
    """
    Counter-attack a threat actor.
    
    Args:
        target: IP/hostname of threat
        full: If True, requires approval for full pentest
    """
    controller = get_redteam_controller()
    job = await controller.counter_attack(target, full=full)
    return {
        "success": True,
        "job": job.to_dict(),
        "requires_approval": job.requires_approval,
    }


# ============================================================================
# EDR (Endpoint Detection & Response) Endpoints
# ============================================================================

# Lazy-loaded EDR components
_sysmon_parser = None
_process_monitor = None
_threat_intel = None


def get_sysmon_parser():
    """Get or create Sysmon parser instance."""
    global _sysmon_parser
    if _sysmon_parser is None:
        from artemis.edr import SysmonParser
        _sysmon_parser = SysmonParser()
    return _sysmon_parser


def get_process_monitor():
    """Get or create process monitor instance."""
    global _process_monitor
    if _process_monitor is None:
        from artemis.edr import ProcessMonitor
        _process_monitor = ProcessMonitor()
    return _process_monitor


def get_threat_intel():
    """Get or create threat intel feed instance."""
    global _threat_intel
    if _threat_intel is None:
        from artemis.edr import ThreatIntelFeed
        _threat_intel = ThreatIntelFeed()
    return _threat_intel


# --- Sysmon Endpoints ---

class SysmonEventRequest(BaseModel):
    """Request for ingesting Sysmon events."""
    events: list[dict]
    format: str = "json"  # "json" or "xml"


@app.post("/api/edr/sysmon/ingest")
async def ingest_sysmon_events(req: SysmonEventRequest):
    """Ingest Sysmon events for analysis."""
    parser = get_sysmon_parser()
    
    processed = 0
    alerts = 0
    errors = []
    
    for event_data in req.events:
        try:
            if req.format == "xml":
                event = parser.parse_xml(event_data.get("xml", ""))
            else:
                event = parser.parse_json(event_data)
            
            if event:
                processed += 1
                if event.alerts:
                    alerts += 1
        except Exception as e:
            errors.append(str(e))
    
    return {
        "success": True,
        "processed": processed,
        "alerts": alerts,
        "errors": errors[:10],  # Limit errors in response
    }


@app.get("/api/edr/sysmon/events")
async def get_sysmon_events(
    limit: int = 100,
    event_type: Optional[int] = None,
):
    """Get recent Sysmon events."""
    parser = get_sysmon_parser()
    events = parser.get_recent_events(limit=limit, event_type=event_type)
    return {
        "events": events,
        "total": len(events),
    }


@app.get("/api/edr/sysmon/alerts")
async def get_sysmon_alerts(limit: int = 50):
    """Get recent Sysmon alerts."""
    parser = get_sysmon_parser()
    alerts = parser.get_recent_alerts(limit=limit)
    return {
        "alerts": alerts,
        "total": len(alerts),
    }


@app.get("/api/edr/sysmon/stats")
async def get_sysmon_stats():
    """Get Sysmon parser statistics."""
    parser = get_sysmon_parser()
    return parser.get_stats()


# --- Process Monitor Endpoints ---

@app.get("/api/edr/processes")
async def get_processes():
    """Get currently running processes."""
    monitor = get_process_monitor()
    processes = monitor.get_current_processes()
    return {
        "processes": processes,
        "total": len(processes),
    }


@app.get("/api/edr/processes/{pid}")
async def get_process_detail(pid: int):
    """Get detailed information about a specific process."""
    monitor = get_process_monitor()
    info = monitor.analyze_process(pid)
    
    if info is None:
        raise HTTPException(status_code=404, detail="Process not found")
    
    return info


@app.get("/api/edr/processes/events")
async def get_process_events(
    limit: int = 100,
    event_type: Optional[str] = None,
):
    """Get recent process events."""
    monitor = get_process_monitor()
    events = monitor.get_recent_events(limit=limit, event_type=event_type)
    return {
        "events": events,
        "total": len(events),
    }


@app.get("/api/edr/processes/alerts")
async def get_process_alerts(limit: int = 50):
    """Get recent process alerts."""
    monitor = get_process_monitor()
    alerts = monitor.get_recent_alerts(limit=limit)
    return {
        "alerts": alerts,
        "total": len(alerts),
    }


@app.post("/api/edr/processes/monitor/start")
async def start_process_monitor():
    """Start the process monitor."""
    monitor = get_process_monitor()
    monitor.start()
    return {
        "success": True,
        "message": "Process monitor started",
        "stats": monitor.get_stats(),
    }


@app.post("/api/edr/processes/monitor/stop")
async def stop_process_monitor():
    """Stop the process monitor."""
    monitor = get_process_monitor()
    monitor.stop()
    return {
        "success": True,
        "message": "Process monitor stopped",
    }


@app.get("/api/edr/processes/monitor/stats")
async def get_process_monitor_stats():
    """Get process monitor statistics."""
    monitor = get_process_monitor()
    return monitor.get_stats()


# --- Threat Intelligence Endpoints ---

@app.get("/api/edr/threat-intel/status")
async def get_threat_intel_status():
    """Get threat intelligence feed status."""
    ti = get_threat_intel()
    return {
        "stats": ti.get_stats(),
        "available_feeds": list(ti.FREE_FEEDS.keys()),
    }


@app.post("/api/edr/threat-intel/update")
async def update_threat_intel_feeds(feed: Optional[str] = None):
    """Update threat intelligence feeds."""
    ti = get_threat_intel()
    
    if feed:
        # Update specific feed
        if feed not in ti.FREE_FEEDS:
            raise HTTPException(status_code=400, detail=f"Unknown feed: {feed}")
        count = await ti.update_feed(feed)
        return {
            "success": True,
            "feed": feed,
            "new_iocs": count,
        }
    else:
        # Update all feeds
        results = await ti.update_all_feeds()
        return {
            "success": True,
            "results": results,
            "stats": ti.get_stats(),
        }


class IoCCheckRequest(BaseModel):
    """Request to check IoCs."""
    values: list[str]


@app.post("/api/edr/threat-intel/check")
async def check_iocs(req: IoCCheckRequest):
    """Check values against threat intelligence database."""
    ti = get_threat_intel()
    
    results = []
    for value in req.values:
        match = ti.check_all(value)
        results.append({
            "value": value,
            "match": match.to_dict() if match else None,
            "is_malicious": match is not None,
        })
    
    return {
        "results": results,
        "total_checked": len(req.values),
        "matches": sum(1 for r in results if r["is_malicious"]),
    }


@app.get("/api/edr/threat-intel/search")
async def search_iocs(
    query: Optional[str] = None,
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
):
    """Search threat intelligence database."""
    ti = get_threat_intel()
    
    from artemis.edr import IoCType
    
    type_filter = None
    if ioc_type:
        try:
            type_filter = IoCType(ioc_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IoC type: {ioc_type}")
    
    results = ti.search(
        query=query,
        ioc_type=type_filter,
        source=source,
        severity=severity,
        limit=limit,
    )
    
    return {
        "results": [ioc.to_dict() for ioc in results],
        "total": len(results),
    }


# --- Combined EDR Status ---

@app.get("/api/edr/status")
async def get_edr_status():
    """Get overall EDR system status."""
    sysmon = get_sysmon_parser()
    process_mon = get_process_monitor()
    ti = get_threat_intel()
    
    return {
        "sysmon": sysmon.get_stats(),
        "process_monitor": process_mon.get_stats(),
        "threat_intel": ti.get_stats(),
        "components": {
            "sysmon": True,
            "process_monitor": process_mon.stats.get("running", False),
            "threat_intel": ti.stats.get("total_iocs", 0) > 0,
        },
    }


@app.get("/api/edr/alerts")
async def get_all_edr_alerts(limit: int = 50):
    """Get all EDR alerts combined."""
    sysmon = get_sysmon_parser()
    process_mon = get_process_monitor()
    
    sysmon_alerts = sysmon.get_recent_alerts(limit=limit)
    process_alerts = process_mon.get_recent_alerts(limit=limit)
    
    # Tag and combine
    for alert in sysmon_alerts:
        alert["source"] = "sysmon"
    for alert in process_alerts:
        alert["source"] = "process_monitor"
    
    # Combine and sort by timestamp
    all_alerts = sysmon_alerts + process_alerts
    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return {
        "alerts": all_alerts[:limit],
        "total": len(all_alerts),
        "by_source": {
            "sysmon": len(sysmon_alerts),
            "process_monitor": len(process_alerts),
        },
    }


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
