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


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.5.0"}


def run_server(host: str = "127.0.0.1", port: int = 8000):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
