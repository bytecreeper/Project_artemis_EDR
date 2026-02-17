"""
Real-time WebSocket API for Artemis Autonomous Security Platform.
Provides live streaming of network data, threats, and AI analysis.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from collections import defaultdict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

logger = logging.getLogger("artemis.web.realtime")

router = APIRouter(prefix="/ws", tags=["realtime"])


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        
        data = json.dumps(message, default=str)
        disconnected = []
        
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected
        for conn in disconnected:
            await self.disconnect(conn)
    
    async def send_to(self, websocket: WebSocket, message: dict):
        """Send message to specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception as e:
            logger.error(f"Failed to send: {e}")


# Global connection manager
manager = ConnectionManager()


# In-memory state (will be populated by agent)
class SecurityState:
    """Global security state for dashboard."""
    
    def __init__(self):
        self.devices: dict[str, dict] = {}
        self.connections: list[dict] = []
        self.threats: list[dict] = []
        self.events: list[dict] = []
        self.ai_analyses: list[dict] = []
        self.traffic_stats: dict = {
            "bytes_in": 0,
            "bytes_out": 0,
            "packets_in": 0,
            "packets_out": 0,
            "connections_active": 0,
        }
        self.network_topology: dict = {
            "nodes": [],
            "edges": [],
        }
        self.agent_status: dict = {
            "running": False,
            "uptime": 0,
            "model": "deepseek-r1:70b",
            "events_processed": 0,
            "threats_detected": 0,
            "last_scan": None,
        }
        self._lock = asyncio.Lock()
    
    async def update_device(self, device_id: str, data: dict):
        async with self._lock:
            self.devices[device_id] = {
                **data,
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
        await manager.broadcast({
            "type": "device_update",
            "device_id": device_id,
            "data": self.devices[device_id],
        })
    
    async def add_connection(self, conn: dict):
        async with self._lock:
            self.connections.append(conn)
            # Keep last 1000
            if len(self.connections) > 1000:
                self.connections = self.connections[-1000:]
        await manager.broadcast({
            "type": "connection",
            "data": conn,
        })
    
    async def add_threat(self, threat: dict):
        async with self._lock:
            threat["timestamp"] = datetime.now(timezone.utc).isoformat()
            self.threats.insert(0, threat)
            # Keep last 100 threats
            if len(self.threats) > 100:
                self.threats = self.threats[:100]
        await manager.broadcast({
            "type": "threat",
            "data": threat,
        })
    
    async def add_ai_analysis(self, analysis: dict):
        async with self._lock:
            analysis["timestamp"] = datetime.now(timezone.utc).isoformat()
            self.ai_analyses.insert(0, analysis)
            if len(self.ai_analyses) > 50:
                self.ai_analyses = self.ai_analyses[:50]
        await manager.broadcast({
            "type": "ai_analysis",
            "data": analysis,
        })
    
    async def update_traffic(self, stats: dict):
        async with self._lock:
            self.traffic_stats.update(stats)
        await manager.broadcast({
            "type": "traffic_update",
            "data": self.traffic_stats,
        })
    
    async def update_topology(self, nodes: list, edges: list):
        async with self._lock:
            self.network_topology = {"nodes": nodes, "edges": edges}
        await manager.broadcast({
            "type": "topology_update",
            "data": self.network_topology,
        })
    
    async def update_agent_status(self, status: dict):
        async with self._lock:
            self.agent_status.update(status)
        await manager.broadcast({
            "type": "agent_status",
            "data": self.agent_status,
        })
    
    async def update_pentest_state(self, pentest_state: dict):
        """Update pentest state and broadcast to clients."""
        async with self._lock:
            self.pentest_state = pentest_state
        await manager.broadcast({
            "type": "pentest_update",
            "data": pentest_state,
        })
    
    async def add_pentest_vulnerability(self, vuln: dict):
        """Add a discovered vulnerability."""
        async with self._lock:
            if not hasattr(self, 'pentest_vulnerabilities'):
                self.pentest_vulnerabilities = []
            vuln["timestamp"] = datetime.now(timezone.utc).isoformat()
            self.pentest_vulnerabilities.append(vuln)
        await manager.broadcast({
            "type": "pentest_vulnerability",
            "data": vuln,
        })
    
    async def add_pentest_log(self, level: str, message: str):
        """Add a pentest log entry."""
        await manager.broadcast({
            "type": "pentest_log",
            "data": {
                "level": level,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        })
    
    def get_full_state(self) -> dict:
        """Get complete state snapshot."""
        return {
            "devices": self.devices,
            "connections": self.connections[-100:],  # Last 100
            "threats": self.threats[:20],  # Last 20
            "ai_analyses": self.ai_analyses[:10],  # Last 10
            "traffic_stats": self.traffic_stats,
            "network_topology": self.network_topology,
            "agent_status": self.agent_status,
            "pentest_state": getattr(self, 'pentest_state', None),
            "pentest_vulnerabilities": getattr(self, 'pentest_vulnerabilities', []),
        }


# Global state
state = SecurityState()


@router.websocket("/live")
async def websocket_endpoint(websocket: WebSocket):
    """Main WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    
    try:
        # Send initial state
        await manager.send_to(websocket, {
            "type": "initial_state",
            "data": state.get_full_state(),
        })
        
        # Keep connection alive and handle client messages
        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                
                # Handle client commands
                msg = json.loads(data)
                cmd = msg.get("command")
                
                if cmd == "ping":
                    await manager.send_to(websocket, {"type": "pong"})
                elif cmd == "get_state":
                    await manager.send_to(websocket, {
                        "type": "state",
                        "data": state.get_full_state(),
                    })
                elif cmd == "get_device":
                    device_id = msg.get("device_id")
                    if device_id and device_id in state.devices:
                        await manager.send_to(websocket, {
                            "type": "device_detail",
                            "data": state.devices[device_id],
                        })
                        
            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_to(websocket, {"type": "heartbeat"})
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)


# REST endpoints for state access
@router.get("/state")
async def get_state():
    """Get current security state."""
    return state.get_full_state()


@router.get("/devices")
async def get_devices():
    """Get all discovered devices."""
    return {"devices": list(state.devices.values())}


@router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Get specific device details."""
    device = state.devices.get(device_id)
    if not device:
        return {"error": "Device not found"}
    return device


@router.get("/devices/{device_id}/connections")
async def get_device_connections(device_id: str):
    """Get connections for a specific device."""
    device = state.devices.get(device_id)
    if not device:
        return {"connections": []}
    
    device_ip = device.get("ip")
    conns = [
        c for c in state.connections
        if c.get("local_addr") == device_ip or c.get("remote_addr") == device_ip
    ]
    return {"connections": conns}


@router.get("/threats")
async def get_threats():
    """Get recent threats."""
    return {"threats": state.threats}


@router.get("/traffic")
async def get_traffic():
    """Get traffic statistics."""
    return state.traffic_stats


@router.get("/topology")
async def get_topology():
    """Get network topology."""
    return state.network_topology


@router.get("/telemetry")
async def get_telemetry():
    """Get endpoint telemetry (host machine)."""
    return {
        "available": True,
        "note": "Telemetry collection active on host",
    }


@router.get("/scan/status")
async def get_scan_status():
    """Get file scanner status."""
    return {
        "running": False,
        "last_scan": None,
        "files_scanned": 0,
        "threats_found": 0,
    }


@router.post("/scan/start")
async def start_scan(paths: list[str] = None):
    """Start file scan."""
    return {"status": "scan_queued", "paths": paths or ["default"]}


@router.get("/remediation/pending")
async def get_pending_remediations():
    """Get pending remediation actions."""
    return {"pending": []}


@router.post("/remediation/{action_id}/approve")
async def approve_remediation(action_id: str):
    """Approve a remediation action."""
    return {"status": "approved", "action_id": action_id}


@router.post("/remediation/{action_id}/execute")
async def execute_remediation(action_id: str):
    """Execute a remediation action."""
    return {"status": "executed", "action_id": action_id}


@router.get("/integrity")
async def get_integrity_report():
    """Get integrity validation report."""
    return {
        "checks": [],
        "false_positives_prevented": 0,
        "hallucinations_caught": 0,
    }
