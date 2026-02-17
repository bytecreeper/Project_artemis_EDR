"""
Deep Endpoint Telemetry - Full system visibility.
Keyboard, mouse, processes, files, registry, services.
"""

import asyncio
import ctypes
import hashlib
import logging
import os
import platform
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger("artemis.agent.telemetry")


@dataclass
class KeystrokeEvent:
    """Keystroke event."""
    timestamp: str
    key: str
    event_type: str  # keydown, keyup
    window_title: str = ""
    process_name: str = ""


@dataclass
class MouseEvent:
    """Mouse movement/click event."""
    timestamp: str
    x: int
    y: int
    event_type: str  # move, click, scroll
    button: str = ""
    window_title: str = ""


@dataclass
class ProcessEvent:
    """Process start/stop event."""
    timestamp: str
    pid: int
    name: str
    exe: str
    cmdline: str
    username: str
    event_type: str  # start, stop
    parent_pid: int = 0
    parent_name: str = ""


@dataclass
class FileEvent:
    """File system event."""
    timestamp: str
    path: str
    event_type: str  # create, modify, delete, rename
    size: int = 0
    hash_md5: str = ""
    process_pid: int = 0
    process_name: str = ""


@dataclass
class ServiceEvent:
    """Service state change."""
    timestamp: str
    name: str
    display_name: str
    state: str  # running, stopped, starting, stopping
    previous_state: str = ""


@dataclass
class RegistryEvent:
    """Registry modification (Windows)."""
    timestamp: str
    key: str
    value_name: str
    value_data: Any
    event_type: str  # create, modify, delete


class EndpointTelemetry:
    """
    Comprehensive endpoint telemetry collection.
    
    Captures:
    - Keyboard input (for security monitoring)
    - Mouse activity
    - Process lifecycle
    - File system changes
    - Service states
    - Registry modifications
    """
    
    def __init__(
        self,
        enable_keyboard: bool = True,
        enable_mouse: bool = True,
        enable_processes: bool = True,
        enable_files: bool = True,
        enable_services: bool = True,
        enable_registry: bool = True,
        keyboard_buffer_size: int = 1000,
        mouse_sample_rate: float = 0.1,  # Seconds between mouse samples
    ):
        self.enable_keyboard = enable_keyboard
        self.enable_mouse = enable_mouse
        self.enable_processes = enable_processes
        self.enable_files = enable_files
        self.enable_services = enable_services
        self.enable_registry = enable_registry
        
        self._running = False
        
        # Event buffers
        self.keystrokes: deque = deque(maxlen=keyboard_buffer_size)
        self.mouse_events: deque = deque(maxlen=500)
        self.process_events: deque = deque(maxlen=500)
        self.file_events: deque = deque(maxlen=500)
        self.service_events: deque = deque(maxlen=100)
        self.registry_events: deque = deque(maxlen=100)
        
        # State tracking
        self._known_pids: set = set()
        self._service_states: dict = {}
        self._mouse_sample_rate = mouse_sample_rate
        self._last_mouse_sample = 0
        
        # Callbacks
        self._callbacks: dict[str, list[Callable]] = {
            "keystroke": [],
            "mouse": [],
            "process": [],
            "file": [],
            "service": [],
            "registry": [],
        }
        
        # Keyboard hook (Windows)
        self._keyboard_hook = None
        self._mouse_hook = None
    
    async def start(self):
        """Start telemetry collection."""
        if self._running:
            return
        
        self._running = True
        logger.info("Starting endpoint telemetry collection")
        
        # Initialize known processes
        self._known_pids = set(psutil.pids())
        
        # Initialize service states
        if platform.system() == "Windows" and self.enable_services:
            await self._init_service_states()
        
        # Start monitoring tasks
        if self.enable_processes:
            asyncio.create_task(self._process_monitor_loop())
        
        if self.enable_services:
            asyncio.create_task(self._service_monitor_loop())
        
        # Start input hooks (in separate thread for Windows)
        if platform.system() == "Windows":
            if self.enable_keyboard or self.enable_mouse:
                threading.Thread(target=self._start_input_hooks, daemon=True).start()
        
        logger.info("Telemetry collection started")
    
    async def stop(self):
        """Stop telemetry collection."""
        self._running = False
        self._stop_input_hooks()
        logger.info("Telemetry collection stopped")
    
    # =========================================================================
    # KEYBOARD MONITORING
    # =========================================================================
    
    def _start_input_hooks(self):
        """Start keyboard/mouse hooks (Windows, runs in thread)."""
        if platform.system() != "Windows":
            return
        
        try:
            import ctypes
            from ctypes import wintypes
            
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            
            # Hook types
            WH_KEYBOARD_LL = 13
            WH_MOUSE_LL = 14
            
            # Callback type
            HOOKPROC = ctypes.CFUNCTYPE(
                ctypes.c_int,
                ctypes.c_int,
                wintypes.WPARAM,
                wintypes.LPARAM
            )
            
            def keyboard_callback(nCode, wParam, lParam):
                if nCode >= 0 and self._running:
                    try:
                        # Get key info
                        kb = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong * 5))
                        vk_code = kb.contents[0]
                        
                        event_type = "keydown" if wParam == 0x100 else "keyup"
                        
                        # Get key name
                        key_name = self._vk_to_name(vk_code)
                        
                        # Get active window
                        window_title = self._get_active_window_title()
                        process_name = self._get_active_process_name()
                        
                        event = KeystrokeEvent(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            key=key_name,
                            event_type=event_type,
                            window_title=window_title,
                            process_name=process_name,
                        )
                        
                        self.keystrokes.append(event)
                        
                        # Notify callbacks
                        for cb in self._callbacks["keystroke"]:
                            try:
                                asyncio.get_event_loop().call_soon_threadsafe(
                                    lambda: asyncio.create_task(cb(event))
                                )
                            except Exception:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"Keyboard hook error: {e}")
                
                return user32.CallNextHookEx(self._keyboard_hook, nCode, wParam, lParam)
            
            def mouse_callback(nCode, wParam, lParam):
                if nCode >= 0 and self._running:
                    try:
                        # Rate limit mouse events
                        now = time.time()
                        if now - self._last_mouse_sample < self._mouse_sample_rate:
                            return user32.CallNextHookEx(self._mouse_hook, nCode, wParam, lParam)
                        self._last_mouse_sample = now
                        
                        # Get mouse info
                        ms = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_long * 5))
                        x, y = ms.contents[0], ms.contents[1]
                        
                        # Determine event type
                        event_map = {
                            0x200: "move",
                            0x201: "click",  # left down
                            0x204: "click",  # right down
                            0x207: "click",  # middle down
                            0x20A: "scroll",
                        }
                        event_type = event_map.get(wParam, "move")
                        
                        event = MouseEvent(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            x=x,
                            y=y,
                            event_type=event_type,
                            window_title=self._get_active_window_title(),
                        )
                        
                        self.mouse_events.append(event)
                        
                    except Exception as e:
                        logger.debug(f"Mouse hook error: {e}")
                
                return user32.CallNextHookEx(self._mouse_hook, nCode, wParam, lParam)
            
            # Keep references to prevent GC
            self._kb_callback = HOOKPROC(keyboard_callback)
            self._mouse_callback = HOOKPROC(mouse_callback)
            
            # Install hooks
            if self.enable_keyboard:
                self._keyboard_hook = user32.SetWindowsHookExA(
                    WH_KEYBOARD_LL,
                    self._kb_callback,
                    kernel32.GetModuleHandleW(None),
                    0
                )
            
            if self.enable_mouse:
                self._mouse_hook = user32.SetWindowsHookExA(
                    WH_MOUSE_LL,
                    self._mouse_callback,
                    kernel32.GetModuleHandleW(None),
                    0
                )
            
            # Message loop
            msg = ctypes.wintypes.MSG()
            while self._running:
                if user32.PeekMessageA(ctypes.byref(msg), None, 0, 0, 1):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageA(ctypes.byref(msg))
                else:
                    time.sleep(0.01)
                    
        except Exception as e:
            logger.error(f"Failed to start input hooks: {e}")
    
    def _stop_input_hooks(self):
        """Stop input hooks."""
        if platform.system() != "Windows":
            return
        
        try:
            import ctypes
            user32 = ctypes.windll.user32
            
            if self._keyboard_hook:
                user32.UnhookWindowsHookEx(self._keyboard_hook)
            if self._mouse_hook:
                user32.UnhookWindowsHookEx(self._mouse_hook)
        except Exception:
            pass
    
    def _vk_to_name(self, vk_code: int) -> str:
        """Convert virtual key code to name."""
        special_keys = {
            8: "BACKSPACE", 9: "TAB", 13: "ENTER", 16: "SHIFT",
            17: "CTRL", 18: "ALT", 20: "CAPSLOCK", 27: "ESC",
            32: "SPACE", 33: "PAGEUP", 34: "PAGEDOWN", 35: "END",
            36: "HOME", 37: "LEFT", 38: "UP", 39: "RIGHT", 40: "DOWN",
            45: "INSERT", 46: "DELETE", 91: "WIN",
        }
        
        if vk_code in special_keys:
            return special_keys[vk_code]
        elif 48 <= vk_code <= 57:  # 0-9
            return chr(vk_code)
        elif 65 <= vk_code <= 90:  # A-Z
            return chr(vk_code)
        elif 112 <= vk_code <= 123:  # F1-F12
            return f"F{vk_code - 111}"
        else:
            return f"VK_{vk_code}"
    
    def _get_active_window_title(self) -> str:
        """Get active window title."""
        if platform.system() != "Windows":
            return ""
        
        try:
            import ctypes
            user32 = ctypes.windll.user32
            
            hwnd = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            return buf.value
        except Exception:
            return ""
    
    def _get_active_process_name(self) -> str:
        """Get active window's process name."""
        if platform.system() != "Windows":
            return ""
        
        try:
            import ctypes
            from ctypes import wintypes
            
            user32 = ctypes.windll.user32
            
            hwnd = user32.GetForegroundWindow()
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            
            proc = psutil.Process(pid.value)
            return proc.name()
        except Exception:
            return ""
    
    # =========================================================================
    # PROCESS MONITORING
    # =========================================================================
    
    async def _process_monitor_loop(self):
        """Monitor process creation/termination."""
        while self._running:
            try:
                current_pids = set(psutil.pids())
                
                # New processes
                new_pids = current_pids - self._known_pids
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        event = ProcessEvent(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            pid=pid,
                            name=proc.name(),
                            exe=proc.exe() or "",
                            cmdline=" ".join(proc.cmdline() or []),
                            username=proc.username() or "",
                            event_type="start",
                            parent_pid=proc.ppid() or 0,
                        )
                        
                        # Get parent name
                        try:
                            parent = psutil.Process(event.parent_pid)
                            event.parent_name = parent.name()
                        except Exception:
                            pass
                        
                        self.process_events.append(event)
                        
                        for cb in self._callbacks["process"]:
                            try:
                                await cb(event)
                            except Exception:
                                pass
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Terminated processes
                terminated = self._known_pids - current_pids
                for pid in terminated:
                    event = ProcessEvent(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        pid=pid,
                        name="",
                        exe="",
                        cmdline="",
                        username="",
                        event_type="stop",
                    )
                    self.process_events.append(event)
                
                self._known_pids = current_pids
                
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            
            await asyncio.sleep(1.0)
    
    # =========================================================================
    # SERVICE MONITORING
    # =========================================================================
    
    async def _init_service_states(self):
        """Initialize service state tracking."""
        if platform.system() != "Windows":
            return
        
        try:
            import wmi
            c = wmi.WMI()
            
            for svc in c.Win32_Service():
                self._service_states[svc.Name] = svc.State
        except Exception as e:
            logger.error(f"Failed to init services: {e}")
    
    async def _service_monitor_loop(self):
        """Monitor service state changes."""
        if platform.system() != "Windows":
            return
        
        while self._running:
            try:
                import wmi
                c = wmi.WMI()
                
                for svc in c.Win32_Service():
                    prev_state = self._service_states.get(svc.Name)
                    current_state = svc.State
                    
                    if prev_state and prev_state != current_state:
                        event = ServiceEvent(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            name=svc.Name,
                            display_name=svc.DisplayName or svc.Name,
                            state=current_state,
                            previous_state=prev_state,
                        )
                        
                        self.service_events.append(event)
                        
                        for cb in self._callbacks["service"]:
                            try:
                                await cb(event)
                            except Exception:
                                pass
                    
                    self._service_states[svc.Name] = current_state
                    
            except Exception as e:
                logger.error(f"Service monitor error: {e}")
            
            await asyncio.sleep(5.0)
    
    # =========================================================================
    # CALLBACKS
    # =========================================================================
    
    def on_keystroke(self, callback: Callable):
        self._callbacks["keystroke"].append(callback)
    
    def on_mouse(self, callback: Callable):
        self._callbacks["mouse"].append(callback)
    
    def on_process(self, callback: Callable):
        self._callbacks["process"].append(callback)
    
    def on_file(self, callback: Callable):
        self._callbacks["file"].append(callback)
    
    def on_service(self, callback: Callable):
        self._callbacks["service"].append(callback)
    
    # =========================================================================
    # DATA ACCESS
    # =========================================================================
    
    def get_recent_keystrokes(self, limit: int = 100) -> list[dict]:
        """Get recent keystrokes."""
        events = list(self.keystrokes)[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "key": e.key,
                "event_type": e.event_type,
                "window": e.window_title,
                "process": e.process_name,
            }
            for e in events
        ]
    
    def get_recent_mouse(self, limit: int = 100) -> list[dict]:
        """Get recent mouse events."""
        events = list(self.mouse_events)[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "x": e.x,
                "y": e.y,
                "type": e.event_type,
            }
            for e in events
        ]
    
    def get_recent_processes(self, limit: int = 50) -> list[dict]:
        """Get recent process events."""
        events = list(self.process_events)[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "pid": e.pid,
                "name": e.name,
                "exe": e.exe,
                "cmdline": e.cmdline,
                "type": e.event_type,
                "parent": e.parent_name,
            }
            for e in events
        ]
    
    def get_recent_services(self, limit: int = 20) -> list[dict]:
        """Get recent service events."""
        events = list(self.service_events)[-limit:]
        return [
            {
                "timestamp": e.timestamp,
                "name": e.name,
                "display_name": e.display_name,
                "state": e.state,
                "previous": e.previous_state,
            }
            for e in events
        ]
    
    def get_activity_summary(self) -> dict:
        """Get activity summary for this endpoint."""
        return {
            "keystrokes_captured": len(self.keystrokes),
            "mouse_events": len(self.mouse_events),
            "process_events": len(self.process_events),
            "service_events": len(self.service_events),
            "recent_processes": self.get_recent_processes(10),
            "recent_services": self.get_recent_services(5),
        }
