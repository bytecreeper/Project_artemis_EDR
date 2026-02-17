"""FastAPI web application for Project Artemis."""

import asyncio
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from artemis.core import Artemis
from artemis.models import RuleFormat, Severity
from artemis.web.realtime import router as realtime_router, state as security_state


# Get paths
WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"

# Create FastAPI app
app = FastAPI(
    title="Project Artemis",
    description="Autonomous AI-powered security operations platform",
    version="1.0.0",
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
    """Get all discovered devices."""
    return {"devices": list(security_state.devices.values())}


@app.get("/api/devices/{device_id}")
async def get_device(device_id: str):
    """Get specific device details."""
    device = security_state.devices.get(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@app.get("/api/connections")
async def get_connections():
    """Get active network connections."""
    return {"connections": security_state.connections[-100:]}


@app.get("/api/threats")
async def get_threats():
    """Get recent threats."""
    return {"threats": security_state.threats}


@app.get("/api/traffic")
async def get_traffic():
    """Get traffic statistics."""
    return security_state.traffic_stats


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
    """Trigger a network scan to discover devices."""
    import subprocess
    import re
    from datetime import datetime, timezone
    
    devices = []
    seen_ips = set()
    network_range = "192.168.4.0/24"  # Default
    
    try:
        # Run ARP scan - gets all cached entries
        arp_result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=30
        )
        
        # Parse all ARP entries
        current_interface = ""
        for line in arp_result.stdout.split("\n"):
            # Check for interface line
            if "Interface:" in line:
                iface_match = re.search(r'Interface:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if iface_match:
                    current_interface = iface_match.group(1)
                    # Use 192.168.x.x network if found
                    if current_interface.startswith("192.168"):
                        network_range = ".".join(current_interface.split(".")[:3]) + ".0/24"
                continue
            
            # Match IP and MAC
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                entry_type = match.group(3)
                
                # Skip broadcast and multicast
                if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                    continue
                
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    
                    # Determine device type from MAC prefix
                    mac_prefix = mac[:8].upper().replace(":", "-")
                    device_type = "desktop"
                    vendor = ""
                    
                    # Common vendor prefixes (expanded)
                    vendor_map = {
                        "00-50-56": ("server", "VMware"),
                        "00-0C-29": ("server", "VMware"),
                        "00-15-5D": ("server", "Hyper-V"),
                        "00-1C-42": ("server", "Parallels"),
                        "AC-DE-48": ("iot", "Raspberry Pi"),
                        "B8-27-EB": ("iot", "Raspberry Pi"),
                        "DC-A6-32": ("iot", "Raspberry Pi"),
                        "E4-5F-01": ("iot", "Raspberry Pi"),
                        "00-1A-79": ("router", "Ubiquiti"),
                        "78-8A-20": ("router", "Ubiquiti"),
                        "F0-9F-C2": ("router", "Ubiquiti"),
                        "00-18-0A": ("router", "Cisco"),
                        "00-1B-54": ("router", "Cisco"),
                        "18-E8-29": ("router", "Netgear"),
                        "A0-63-91": ("router", "Netgear"),
                        "F8-FF-C2": ("mobile", "Apple"),
                        "A4-83-E7": ("mobile", "Apple"),
                        "3C-06-30": ("mobile", "Apple"),
                        "70-56-81": ("mobile", "Apple"),
                        "A4-C3-F0": ("mobile", "Intel"),
                        "5C-E0-C5": ("mobile", "Samsung"),
                        "CC-46-D6": ("desktop", "Google"),
                        "74-D4-35": ("desktop", "Giga-Byte"),
                        "04-D9-F5": ("desktop", "Asus"),
                        "00-25-22": ("desktop", "ASRock"),
                        "74-D0-2B": ("desktop", "ASUSTek"),
                        "D8-BB-C1": ("desktop", "Micro-Star"),
                    }
                    
                    for prefix, (dtype, vend) in vendor_map.items():
                        if mac_prefix.startswith(prefix):
                            device_type = dtype
                            vendor = vend
                            break
                    
                    device = {
                        "ip": ip,
                        "mac": mac,
                        "hostname": ip,
                        "type": device_type,
                        "vendor": vendor,
                        "status": "online",
                        "last_seen": datetime.now(timezone.utc).isoformat(),
                    }
                    devices.append(device)
                    
                    # Update security state
                    await security_state.update_device(ip, device)
        
        # Sort by IP
        devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
        
        return {
            "success": True,
            "devices_found": len(devices),
            "network_range": network_range,
            "devices": devices,
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "devices": [],
        }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "1.1.2"}


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
