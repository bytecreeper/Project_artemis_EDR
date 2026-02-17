# Artemis Dashboard - Real-time Security Monitoring
"""
FastAPI + WebSocket dashboard for live threat monitoring.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..agent import (
    ArtemisDaemon,
    ThreatAssessment,
    NormalizedEvent,
    DefensiveAction,
    EventSeverity,
    EnhancedNetworkDiscovery,
    DeviceType,
)
from ..agent.endpoint import EndpointMonitor, EndpointEvent

logger = logging.getLogger("artemis.web.dashboard")

# Dashboard app
dashboard_app = FastAPI(title="Artemis Dashboard", version="0.6.0")

# Templates
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

# Static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    dashboard_app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Global state
class DashboardState:
    daemon: ArtemisDaemon | None = None
    network_scanner: EnhancedNetworkDiscovery | None = None
    endpoint_monitor: EndpointMonitor | None = None
    connections: list[WebSocket] = []
    terminal_connections: list[WebSocket] = []
    event_buffer: list[dict] = []
    threat_buffer: list[dict] = []
    action_buffer: list[dict] = []
    endpoint_events: list[dict] = []
    network_devices: list[dict] = []
    max_buffer_size: int = 100
    max_endpoint_events: int = 2000
    scan_in_progress: bool = False
    
state = DashboardState()


# Terminal WebSocket manager
class TerminalManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Terminal connected. Total: {len(self.active_connections)}")
        
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"Terminal disconnected. Total: {len(self.active_connections)}")
        
    async def broadcast(self, message: dict):
        dead = []
        for conn in self.active_connections:
            try:
                await conn.send_json(message)
            except Exception:
                dead.append(conn)
        for conn in dead:
            self.disconnect(conn)

terminal_manager = TerminalManager()


# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")
        
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
        
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        
        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

manager = ConnectionManager()


# Event handlers for daemon integration
async def on_events(events: list[NormalizedEvent]):
    """Called when new events are received."""
    for event in events[-10:]:  # Only send last 10
        msg = {
            "type": "event",
            "data": {
                "id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source.value,
                "event_code": event.event_code,
                "process": event.process_name,
                "user": event.username,
                "command_line": event.command_line[:100] if event.command_line else "",
            }
        }
        state.event_buffer.append(msg["data"])
        if len(state.event_buffer) > state.max_buffer_size:
            state.event_buffer.pop(0)
        await manager.broadcast(msg)


async def on_threat(assessment: ThreatAssessment):
    """Called when a threat is detected."""
    msg = {
        "type": "threat",
        "data": {
            "id": assessment.assessment_id,
            "timestamp": assessment.timestamp.isoformat(),
            "is_threat": assessment.is_threat,
            "confidence": assessment.confidence,
            "severity": assessment.severity.name,
            "threat_type": assessment.threat_type,
            "description": assessment.description,
            "mitre_tactics": assessment.mitre_tactics,
            "mitre_techniques": assessment.mitre_techniques,
            "recommended_actions": assessment.recommended_actions,
            "auto_action_eligible": assessment.auto_action_eligible,
        }
    }
    state.threat_buffer.append(msg["data"])
    if len(state.threat_buffer) > state.max_buffer_size:
        state.threat_buffer.pop(0)
    await manager.broadcast(msg)


async def on_actions(actions: list[DefensiveAction]):
    """Called when defensive actions are created."""
    for action in actions:
        msg = {
            "type": "action",
            "data": {
                "id": action.action_id,
                "action_type": action.action_type.value,
                "description": action.description,
                "target": action.target,
                "status": action.status.value,
                "requires_approval": action.requires_approval,
                "created_at": action.created_at.isoformat(),
            }
        }
        state.action_buffer.append(msg["data"])
        if len(state.action_buffer) > state.max_buffer_size:
            state.action_buffer.pop(0)
        await manager.broadcast(msg)


# Endpoint event handler
async def on_endpoint_event(event: EndpointEvent):
    """Handle endpoint telemetry events."""
    event_dict = event.to_dict()
    state.endpoint_events.append(event_dict)
    
    # Trim buffer
    if len(state.endpoint_events) > state.max_endpoint_events:
        state.endpoint_events = state.endpoint_events[-state.max_endpoint_events:]
    
    # Broadcast to terminal clients
    await terminal_manager.broadcast({
        "type": "event",
        "data": event_dict,
    })


# Routes
@dashboard_app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Main dashboard page - new SOC dashboard."""
    return templates.TemplateResponse("dashboard_v2.html", {
        "request": request,
        "title": "Artemis SOC",
    })


@dashboard_app.get("/terminal", response_class=HTMLResponse)
async def terminal_page(request: Request):
    """Hacker-level terminal interface."""
    return templates.TemplateResponse("terminal.html", {
        "request": request,
        "title": "Artemis Terminal",
    })


@dashboard_app.get("/classic", response_class=HTMLResponse)
async def dashboard_classic(request: Request):
    """Classic dashboard page."""
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "title": "Artemis Dashboard",
    })


@dashboard_app.get("/api/status")
async def get_status():
    """Get daemon status."""
    if state.daemon:
        return {
            "running": state.daemon.is_running,
            "stats": state.daemon.stats,
        }
    return {"running": False, "stats": {}}


@dashboard_app.get("/api/events")
async def get_events(limit: int = 50):
    """Get recent events."""
    return {"events": state.event_buffer[-limit:]}


@dashboard_app.get("/api/threats")
async def get_threats(limit: int = 50):
    """Get recent threats."""
    return {"threats": state.threat_buffer[-limit:]}


@dashboard_app.get("/api/actions")
async def get_actions():
    """Get pending and recent actions."""
    pending = []
    if state.daemon:
        pending = [a.to_dict() for a in state.daemon.pending_actions]
    return {
        "pending": pending,
        "recent": state.action_buffer[-20:],
    }


@dashboard_app.post("/api/actions/{action_id}/approve")
async def approve_action(action_id: str):
    """Approve a pending action."""
    if not state.daemon:
        return {"success": False, "error": "Daemon not running"}
    
    success = await state.daemon.approve_action(action_id)
    if success:
        await manager.broadcast({
            "type": "action_update",
            "data": {"id": action_id, "status": "approved"}
        })
    return {"success": success}


@dashboard_app.post("/api/actions/{action_id}/reject")
async def reject_action(action_id: str):
    """Reject a pending action."""
    if not state.daemon:
        return {"success": False, "error": "Daemon not running"}
    
    success = await state.daemon.reject_action(action_id)
    if success:
        await manager.broadcast({
            "type": "action_update",
            "data": {"id": action_id, "status": "rejected"}
        })
    return {"success": success}


# Network Discovery API
@dashboard_app.get("/api/network/devices")
async def get_network_devices():
    """Get discovered network devices."""
    return {
        "devices": state.network_devices,
        "scan_in_progress": state.scan_in_progress,
    }


@dashboard_app.post("/api/network/scan")
async def start_network_scan():
    """Start a network scan."""
    if state.scan_in_progress:
        return {"success": False, "error": "Scan already in progress"}
    
    state.scan_in_progress = True
    
    # Broadcast scan started
    await manager.broadcast({
        "type": "network_scan_started",
        "data": {}
    })
    
    try:
        # Initialize scanner if needed
        if not state.network_scanner:
            state.network_scanner = EnhancedNetworkDiscovery()
            await state.network_scanner.initialize()
        
        # Run scan
        devices = await state.network_scanner.full_scan()
        
        # Convert to dicts
        state.network_devices = [d.to_dict() for d in devices]
        
        # Broadcast results
        await manager.broadcast({
            "type": "network_scan_complete",
            "data": {
                "devices": state.network_devices,
                "count": len(state.network_devices),
            }
        })
        
        return {
            "success": True,
            "count": len(state.network_devices),
            "devices": state.network_devices,
        }
        
    except Exception as e:
        logger.error(f"Network scan error: {e}")
        await manager.broadcast({
            "type": "network_scan_error",
            "data": {"error": str(e)}
        })
        return {"success": False, "error": str(e)}
        
    finally:
        state.scan_in_progress = False


@dashboard_app.get("/api/network/summary")
async def get_network_summary():
    """Get network summary by device type."""
    if not state.network_devices:
        return {"summary": {}, "total": 0}
    
    summary = {}
    for device in state.network_devices:
        dtype = device.get("device_type", "unknown")
        summary[dtype] = summary.get(dtype, 0) + 1
    
    return {
        "summary": summary,
        "total": len(state.network_devices),
        "local_ip": state.network_scanner.local_ip if state.network_scanner else None,
        "gateway_ip": state.network_scanner.gateway_ip if state.network_scanner else None,
    }


@dashboard_app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    
    # Send initial state
    await websocket.send_json({
        "type": "init",
        "data": {
            "events": state.event_buffer[-20:],
            "threats": state.threat_buffer[-10:],
            "actions": state.action_buffer[-10:],
            "daemon_running": state.daemon.is_running if state.daemon else False,
        }
    })
    
    try:
        while True:
            # Keep connection alive, handle incoming messages
            data = await websocket.receive_text()
            msg = json.loads(data)
            
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@dashboard_app.websocket("/ws/terminal")
async def terminal_websocket(websocket: WebSocket):
    """WebSocket for terminal real-time endpoint telemetry."""
    await terminal_manager.connect(websocket)
    
    # Get process info
    processes = {}
    if state.endpoint_monitor:
        processes = {
            pid: proc.to_dict() 
            for pid, proc in state.endpoint_monitor.processes.items()
        }
    
    # Send initial state
    await websocket.send_json({
        "type": "init",
        "data": {
            "events": state.endpoint_events[-500:],
            "processes": processes,
            "devices": state.network_devices,
        }
    })
    
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif msg.get("type") == "get_processes":
                if state.endpoint_monitor:
                    await websocket.send_json({
                        "type": "process_update",
                        "data": {
                            "processes": {
                                pid: proc.to_dict()
                                for pid, proc in state.endpoint_monitor.processes.items()
                            }
                        }
                    })
                    
    except WebSocketDisconnect:
        terminal_manager.disconnect(websocket)


# Endpoint monitoring API
@dashboard_app.get("/api/endpoint/stats")
async def get_endpoint_stats():
    """Get endpoint monitor statistics."""
    if state.endpoint_monitor:
        return state.endpoint_monitor.stats
    return {"running": False}


@dashboard_app.get("/api/endpoint/processes")
async def get_processes():
    """Get current processes."""
    if state.endpoint_monitor:
        return {
            "processes": [
                proc.to_dict()
                for proc in state.endpoint_monitor.processes.values()
            ]
        }
    return {"processes": []}


@dashboard_app.get("/api/endpoint/events")
async def get_endpoint_events(limit: int = 500, event_type: str | None = None):
    """Get endpoint events."""
    events = state.endpoint_events
    if event_type:
        events = [e for e in events if e.get("event_type") == event_type]
    return {"events": events[-limit:]}


def create_dashboard_with_daemon(
    provider: str = "ollama",
    model: str = "deepseek-r1:70b",
    channels: list[str] | None = None,
    priority_only: bool = False,
    auto_actions: bool = False,
    enable_endpoint_monitor: bool = True,
) -> tuple[FastAPI, ArtemisDaemon]:
    """
    Create dashboard app with integrated daemon and endpoint monitor.
    
    Returns:
        Tuple of (FastAPI app, ArtemisDaemon instance)
    """
    daemon = ArtemisDaemon(
        provider=provider,
        model=model,
        channels=channels,
        priority_only=priority_only,
        auto_actions=auto_actions,
        notify_enabled=True,
    )
    
    # Register callbacks
    daemon.on_event(on_events)
    daemon.on_threat(on_threat)
    daemon.on_action(on_actions)
    
    # Store in state
    state.daemon = daemon
    
    # Create endpoint monitor for real-time telemetry
    if enable_endpoint_monitor:
        state.endpoint_monitor = EndpointMonitor(
            poll_interval_ms=200,  # 200ms for responsive UI
            include_window_events=True,
        )
        state.endpoint_monitor.on_event(on_endpoint_event)
    
    return dashboard_app, daemon


async def start_endpoint_monitor():
    """Start the endpoint monitor if configured."""
    if state.endpoint_monitor:
        await state.endpoint_monitor.start()
        logger.info("Endpoint monitor started")


async def start_network_scanner():
    """Initialize and scan network."""
    if not state.network_scanner:
        state.network_scanner = EnhancedNetworkDiscovery()
        await state.network_scanner.initialize()
        logger.info(f"Network scanner initialized: {state.network_scanner.subnet}")
