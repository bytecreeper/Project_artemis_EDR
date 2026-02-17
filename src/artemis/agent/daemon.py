# Artemis Agent - Main Daemon
"""
The Artemis Daemon orchestrates event monitoring, AI analysis, and response actions.
This is the main entry point for the autonomous security agent.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import ThreatAnalyzer
from .events import EventSeverity, NormalizedEvent, ThreatAssessment
from .monitor import EventMonitor
from .responder import ActionResponder, DefensiveAction

logger = logging.getLogger("artemis.agent.daemon")


class ArtemisDaemon:
    """
    Main Artemis agent daemon.
    Coordinates monitoring, analysis, and response in a continuous loop.
    """
    
    def __init__(
        self,
        # Monitor settings
        channels: list[str] | None = None,
        priority_only: bool = False,
        batch_size: int = 20,
        batch_timeout: float = 10.0,
        
        # Analyzer settings
        provider: str = "ollama",
        model: str = "deepseek-r1:70b",
        api_key: str | None = None,
        confidence_threshold: float = 0.5,
        
        # Responder settings
        auto_actions: bool = False,
        notify_enabled: bool = True,
        log_dir: Path | None = None,
        rules_dir: Path | None = None,
        
        # Daemon settings
        analysis_interval: float = 5.0,  # Min seconds between analyses
    ):
        """
        Initialize the Artemis daemon.
        
        Args:
            channels: Event log channels to monitor
            priority_only: Only monitor high-value event IDs
            batch_size: Events per analysis batch
            batch_timeout: Max wait time for batch
            provider: LLM provider (ollama, anthropic, openai)
            model: LLM model name
            api_key: API key if required
            confidence_threshold: Min confidence to report threats
            auto_actions: Allow automatic defensive actions
            notify_enabled: Enable desktop notifications
            log_dir: Directory for threat logs
            rules_dir: Directory for generated rules
            analysis_interval: Minimum time between analyses
        """
        self.monitor = EventMonitor(
            channels=channels,
            batch_size=batch_size,
            batch_timeout=batch_timeout,
            priority_only=priority_only,
        )
        
        self.analyzer = ThreatAnalyzer(
            provider=provider,
            model=model,
            api_key=api_key,
            confidence_threshold=confidence_threshold,
        )
        
        self.responder = ActionResponder(
            log_dir=log_dir,
            rules_dir=rules_dir,
            auto_actions=auto_actions,
            notify_enabled=notify_enabled,
        )
        
        self.analysis_interval = analysis_interval
        self._running = False
        self._last_analysis = 0.0
        self._start_time: datetime | None = None
        
        # Statistics
        self._events_processed = 0
        self._batches_analyzed = 0
        self._threats_detected = 0
        
        # Event callbacks for UI integration
        self._on_event: list[callable] = []
        self._on_threat: list[callable] = []
        self._on_action: list[callable] = []
        
    async def start(self) -> None:
        """Start the Artemis daemon."""
        if self._running:
            logger.warning("Daemon already running")
            return
            
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        
        logger.info("=" * 60)
        logger.info("ARTEMIS DAEMON STARTING")
        logger.info(f"Model: {self.analyzer.provider_name}/{self.analyzer.model}")
        logger.info(f"Channels: {self.monitor.channels}")
        logger.info(f"Auto-actions: {self.responder.auto_actions}")
        logger.info("=" * 60)
        
        # Initialize components
        await self.analyzer.initialize()
        await self.monitor.start()
        
        # Set up signal handlers
        self._setup_signals()
        
        # Main analysis loop
        try:
            await self._analysis_loop()
        except asyncio.CancelledError:
            logger.info("Daemon cancelled")
        finally:
            await self.stop()
            
    async def stop(self) -> None:
        """Stop the Artemis daemon."""
        if not self._running:
            return
            
        self._running = False
        await self.monitor.stop()
        
        logger.info("=" * 60)
        logger.info("ARTEMIS DAEMON STOPPED")
        logger.info(f"Runtime: {self._get_runtime()}")
        logger.info(f"Events processed: {self._events_processed}")
        logger.info(f"Batches analyzed: {self._batches_analyzed}")
        logger.info(f"Threats detected: {self._threats_detected}")
        logger.info("=" * 60)
        
    async def _analysis_loop(self) -> None:
        """Main loop: receive events, analyze, respond."""
        async for batch in self.monitor.events():
            if not self._running:
                break
                
            self._events_processed += len(batch)
            
            # Notify event callbacks
            for callback in self._on_event:
                try:
                    await callback(batch)
                except Exception as e:
                    logger.debug(f"Event callback error: {e}")
                    
            # Rate limit analysis
            now = asyncio.get_event_loop().time()
            if now - self._last_analysis < self.analysis_interval:
                continue
                
            self._last_analysis = now
            self._batches_analyzed += 1
            
            # Log batch info
            logger.debug(f"Analyzing batch of {len(batch)} events")
            
            # Analyze with AI
            assessment = await self.analyzer.analyze(batch)
            
            if assessment and assessment.is_threat:
                self._threats_detected += 1
                
                # Log threat
                self._log_threat(assessment, batch)
                
                # Notify threat callbacks
                for callback in self._on_threat:
                    try:
                        await callback(assessment)
                    except Exception as e:
                        logger.debug(f"Threat callback error: {e}")
                        
                # Take response actions
                actions = await self.responder.respond(assessment)
                
                # Notify action callbacks
                for callback in self._on_action:
                    try:
                        await callback(actions)
                    except Exception as e:
                        logger.debug(f"Action callback error: {e}")
                        
    def _log_threat(self, assessment: ThreatAssessment, events: list[NormalizedEvent]) -> None:
        """Log a detected threat."""
        severity_colors = {
            EventSeverity.CRITICAL: "\033[91m",  # Red
            EventSeverity.HIGH: "\033[93m",      # Yellow
            EventSeverity.MEDIUM: "\033[94m",    # Blue
            EventSeverity.LOW: "\033[90m",       # Gray
        }
        reset = "\033[0m"
        color = severity_colors.get(assessment.severity, "")
        
        logger.warning(
            f"{color}[{assessment.severity.name}]{reset} "
            f"Threat: {assessment.threat_type} "
            f"(confidence: {assessment.confidence:.0%})"
        )
        logger.info(f"  Description: {assessment.description[:200]}")
        
        if assessment.mitre_techniques:
            logger.info(f"  MITRE: {', '.join(assessment.mitre_techniques)}")
            
        if assessment.recommended_actions:
            logger.info(f"  Actions: {', '.join(assessment.recommended_actions[:3])}")
            
        # Log triggering events
        for event in events[:3]:
            logger.debug(f"  Event: {event.summary()}")
            
    def _setup_signals(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if sys.platform != "win32":
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))
                
    def _get_runtime(self) -> str:
        """Get formatted runtime string."""
        if not self._start_time:
            return "0s"
            
        delta = datetime.now(timezone.utc) - self._start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
        
    # Event subscription methods for UI integration
    
    def on_event(self, callback: callable) -> None:
        """Register callback for new events."""
        self._on_event.append(callback)
        
    def on_threat(self, callback: callable) -> None:
        """Register callback for detected threats."""
        self._on_threat.append(callback)
        
    def on_action(self, callback: callable) -> None:
        """Register callback for defensive actions."""
        self._on_action.append(callback)
        
    # Control methods
    
    async def approve_action(self, action_id: str) -> bool:
        """Approve a pending action."""
        return await self.responder.approve_action(action_id)
        
    async def reject_action(self, action_id: str) -> bool:
        """Reject a pending action."""
        return await self.responder.reject_action(action_id)
        
    @property
    def pending_actions(self) -> list[DefensiveAction]:
        """Get pending actions requiring approval."""
        return self.responder.pending_actions
        
    @property
    def stats(self) -> dict[str, Any]:
        """Get daemon statistics."""
        return {
            "running": self._running,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "runtime": self._get_runtime(),
            "events_processed": self._events_processed,
            "batches_analyzed": self._batches_analyzed,
            "threats_detected": self._threats_detected,
            "analyzer": self.analyzer.stats,
            "responder": self.responder.stats,
        }
        
    @property
    def is_running(self) -> bool:
        """Check if daemon is running."""
        return self._running


async def run_daemon(
    provider: str = "ollama",
    model: str = "qwen3:32b",
    channels: list[str] | None = None,
    priority_only: bool = False,
    auto_actions: bool = False,
    verbose: bool = False,
) -> None:
    """
    Convenience function to run the Artemis daemon.
    
    Args:
        provider: LLM provider
        model: LLM model
        channels: Event channels to monitor
        priority_only: Only monitor high-value events
        auto_actions: Enable auto-response
        verbose: Enable verbose logging
    """
    # Configure logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    daemon = ArtemisDaemon(
        provider=provider,
        model=model,
        channels=channels,
        priority_only=priority_only,
        auto_actions=auto_actions,
    )
    
    await daemon.start()


if __name__ == "__main__":
    asyncio.run(run_daemon(verbose=True))
