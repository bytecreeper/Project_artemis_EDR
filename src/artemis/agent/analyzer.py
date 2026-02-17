# Artemis Agent - AI Threat Analyzer
"""
LLM-powered threat analysis engine.
Analyzes event batches and produces threat assessments.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from ..llm import LLMProvider, get_provider
from .events import EventSeverity, NormalizedEvent, ThreatAssessment

logger = logging.getLogger("artemis.agent.analyzer")

ANALYSIS_SYSTEM_PROMPT = """You are Artemis, an AI-powered security analyst monitoring a Windows system in real-time.

Your role is to analyze batches of Windows events and identify potential security threats.

ANALYSIS GUIDELINES:
1. Look for suspicious patterns across events, not just individual events
2. Consider attack chains and lateral movement
3. Be alert to privilege escalation, credential access, persistence mechanisms
4. PowerShell and cmd with encoded commands or download cradles are high priority
5. Unusual parent-child process relationships are suspicious
6. Network connections from unexpected processes should be flagged
7. Registry modifications for persistence (Run keys, services) are critical

KNOWN BENIGN PATTERNS (lower priority):
- Windows Update processes
- Antivirus/EDR normal operations
- Standard service startups during boot
- User-initiated application launches

THREAT SEVERITY SCALE:
- CRITICAL: Active attack in progress, immediate action required (ransomware, active C2, credential dumping)
- HIGH: Strong indicators of compromise, urgent investigation needed
- MEDIUM: Suspicious activity requiring attention, possible threat
- LOW: Anomaly detected, worth logging but likely benign
- INFO: Normal activity, no action needed

OUTPUT FORMAT:
You must respond with a valid JSON object. No markdown, no explanation outside the JSON.
{
    "is_threat": true/false,
    "confidence": 0.0-1.0,
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "threat_type": "string describing the threat category",
    "description": "Detailed explanation of what you found and why it's suspicious",
    "mitre_tactics": ["list", "of", "tactics"],
    "mitre_techniques": ["T1059.001", "etc"],
    "recommended_actions": ["action1", "action2"],
    "auto_action_eligible": true/false,
    "key_indicators": ["specific things that triggered this assessment"]
}

auto_action_eligible should only be true for HIGH or CRITICAL threats with confidence >= 0.85.

If the events are normal/benign, respond with:
{
    "is_threat": false,
    "confidence": 0.95,
    "severity": "INFO",
    "threat_type": "normal_activity",
    "description": "Brief description of normal activity observed",
    "mitre_tactics": [],
    "mitre_techniques": [],
    "recommended_actions": [],
    "auto_action_eligible": false,
    "key_indicators": []
}
"""


class ThreatAnalyzer:
    """
    AI-powered threat analyzer using local or cloud LLMs.
    Processes event batches and produces threat assessments.
    """
    
    def __init__(
        self,
        provider: str = "ollama",
        model: str = "deepseek-r1:70b",
        api_key: str | None = None,
        base_url: str | None = None,
        confidence_threshold: float = 0.5,
        auto_action_threshold: float = 0.85,
    ):
        """
        Initialize the threat analyzer.
        
        Args:
            provider: LLM provider (ollama, anthropic, openai)
            model: Model name
            api_key: API key if required
            base_url: Custom API endpoint
            confidence_threshold: Minimum confidence to report threats
            auto_action_threshold: Minimum confidence for auto-actions
        """
        self.provider_name = provider
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.confidence_threshold = confidence_threshold
        self.auto_action_threshold = auto_action_threshold
        
        self._provider: LLMProvider | None = None
        self._analysis_count = 0
        self._threat_count = 0
        
    async def initialize(self) -> None:
        """Initialize the LLM provider."""
        self._provider = get_provider(
            self.provider_name,
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
        )
        logger.info(f"Analyzer initialized with {self.provider_name}/{self.model}")
        
    async def analyze(self, events: list[NormalizedEvent]) -> ThreatAssessment | None:
        """
        Analyze a batch of events and return a threat assessment.
        
        Args:
            events: List of normalized events to analyze
            
        Returns:
            ThreatAssessment if threats detected, None if all clear
        """
        if not events:
            return None
            
        if not self._provider:
            await self.initialize()
            
        self._analysis_count += 1
        
        # Format events for the LLM
        events_text = self._format_events(events)
        
        prompt = f"""Analyze the following {len(events)} Windows events for security threats:

{events_text}

Provide your threat assessment as JSON."""

        try:
            # Call the LLM
            response = await self._provider.generate(
                prompt=prompt,
                system=ANALYSIS_SYSTEM_PROMPT,
                model=self.model,
                temperature=0.1,  # Low temperature for consistent analysis
                max_tokens=2000,
            )
            
            # Parse the response
            assessment = self._parse_response(response, events)
            
            if assessment and assessment.is_threat:
                self._threat_count += 1
                logger.warning(
                    f"Threat detected: {assessment.threat_type} "
                    f"(severity={assessment.severity.name}, confidence={assessment.confidence:.2f})"
                )
                
            return assessment
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return None
            
    def _format_events(self, events: list[NormalizedEvent]) -> str:
        """Format events for LLM analysis."""
        lines = []
        
        for i, event in enumerate(events, 1):
            lines.append(f"--- Event {i} ---")
            lines.append(f"Time: {event.timestamp.isoformat()}")
            lines.append(f"Source: {event.source.value}")
            lines.append(f"EventID: {event.event_code}")
            lines.append(f"Type: {event.event_type}")
            
            if event.hostname:
                lines.append(f"Host: {event.hostname}")
            if event.username:
                lines.append(f"User: {event.username}")
            if event.process_name:
                lines.append(f"Process: {event.process_name}")
            if event.process_id:
                lines.append(f"PID: {event.process_id}")
            if event.parent_process:
                lines.append(f"Parent: {event.parent_process}")
            if event.command_line:
                lines.append(f"CommandLine: {event.command_line}")
            if event.source_ip:
                lines.append(f"SourceIP: {event.source_ip}")
            if event.dest_ip:
                lines.append(f"DestIP: {event.dest_ip}:{event.dest_port}")
            if event.file_path:
                lines.append(f"FilePath: {event.file_path}")
            if event.message:
                # Truncate long messages
                msg = event.message[:500] + "..." if len(event.message) > 500 else event.message
                lines.append(f"Message: {msg}")
                
            lines.append("")
            
        return "\n".join(lines)
        
    def _parse_response(
        self,
        response: str,
        events: list[NormalizedEvent]
    ) -> ThreatAssessment | None:
        """Parse LLM response into ThreatAssessment."""
        try:
            # Clean up response - find JSON object
            response = response.strip()
            
            # Handle potential markdown code blocks
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                response = response[start:end].strip()
                
            # Find JSON object bounds
            start = response.find("{")
            end = response.rfind("}") + 1
            if start == -1 or end == 0:
                logger.warning("No JSON found in response")
                return None
                
            json_str = response[start:end]
            data = json.loads(json_str)
            
            # Map severity string to enum
            severity_map = {
                "CRITICAL": EventSeverity.CRITICAL,
                "HIGH": EventSeverity.HIGH,
                "MEDIUM": EventSeverity.MEDIUM,
                "LOW": EventSeverity.LOW,
                "INFO": EventSeverity.INFO,
            }
            severity = severity_map.get(data.get("severity", "INFO").upper(), EventSeverity.INFO)
            
            # Check confidence threshold
            confidence = float(data.get("confidence", 0))
            is_threat = data.get("is_threat", False)
            
            if is_threat and confidence < self.confidence_threshold:
                logger.debug(f"Threat below confidence threshold: {confidence}")
                is_threat = False
                
            # Determine auto-action eligibility
            auto_eligible = (
                data.get("auto_action_eligible", False) and
                confidence >= self.auto_action_threshold and
                severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
            )
            
            return ThreatAssessment(
                assessment_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                event_ids=[e.event_id for e in events],
                is_threat=is_threat,
                confidence=confidence,
                severity=severity,
                threat_type=data.get("threat_type", "unknown"),
                description=data.get("description", ""),
                mitre_tactics=data.get("mitre_tactics", []),
                mitre_techniques=data.get("mitre_techniques", []),
                recommended_actions=data.get("recommended_actions", []),
                auto_action_eligible=auto_eligible,
                requires_approval=not auto_eligible,
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return None
        except Exception as e:
            logger.error(f"Error parsing assessment: {e}")
            return None
            
    @property
    def stats(self) -> dict:
        """Get analyzer statistics."""
        return {
            "analyses_performed": self._analysis_count,
            "threats_detected": self._threat_count,
            "threat_rate": self._threat_count / max(1, self._analysis_count),
            "provider": self.provider_name,
            "model": self.model,
        }
