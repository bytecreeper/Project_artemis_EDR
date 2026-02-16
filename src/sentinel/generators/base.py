"""Base generator class for detection rules."""

import re
import time
import uuid
from abc import ABC, abstractmethod
from datetime import date
from typing import Optional

from sentinel.models import (
    ThreatDescription,
    DetectionRule,
    GenerationResult,
    RuleFormat,
    Severity,
    MitreMapping,
)
from sentinel.llm import LLMProvider


class BaseGenerator(ABC):
    """Abstract base class for detection rule generators."""
    
    format: RuleFormat = NotImplemented
    
    def __init__(self, llm: LLMProvider):
        self.llm = llm
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this generator."""
        pass
    
    @abstractmethod
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        """Build the generation prompt for a threat description."""
        pass
    
    @abstractmethod
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a DetectionRule."""
        pass
    
    @abstractmethod
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """
        Validate the generated rule.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        pass
    
    async def generate(self, threat: ThreatDescription) -> GenerationResult:
        """
        Generate a detection rule from a threat description.
        
        Args:
            threat: The threat description to generate a rule for
            
        Returns:
            GenerationResult with the rule or error information
        """
        start_time = time.time()
        
        try:
            # Build prompts
            system_prompt = self.get_system_prompt()
            generation_prompt = self.get_generation_prompt(threat)
            
            # Call LLM
            response_text, metadata = await self.llm.generate(
                prompt=generation_prompt,
                system=system_prompt,
            )
            
            # Parse response
            rule = self.parse_response(response_text, threat)
            
            # Validate
            is_valid, errors = self.validate_rule(rule)
            rule.is_valid = is_valid
            rule.validation_errors = errors
            
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            return GenerationResult(
                success=True,
                rule=rule,
                model_used=self.llm.get_model_name(),
                tokens_used=metadata.get("input_tokens", 0) + metadata.get("output_tokens", 0),
                generation_time_ms=elapsed_ms,
            )
            
        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            return GenerationResult(
                success=False,
                error=str(e),
                model_used=self.llm.get_model_name(),
                generation_time_ms=elapsed_ms,
            )
    
    def generate_rule_id(self) -> str:
        """Generate a unique rule ID."""
        return str(uuid.uuid4())
    
    def get_current_date(self) -> str:
        """Get current date in YYYY/MM/DD format."""
        return date.today().strftime("%Y/%m/%d")
    
    def extract_json_block(self, text: str) -> Optional[str]:
        """Extract JSON from markdown code block."""
        # Try to find ```json ... ``` block
        json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', text, re.DOTALL)
        if json_match:
            return json_match.group(1).strip()
        
        # Try to find raw JSON object
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            return json_match.group(0)
        
        return None
    
    def extract_yaml_block(self, text: str) -> Optional[str]:
        """Extract YAML from markdown code block."""
        # Try to find ```yaml ... ``` block
        yaml_match = re.search(r'```(?:yaml|yml)?\s*\n(.*?)\n```', text, re.DOTALL)
        if yaml_match:
            return yaml_match.group(1).strip()
        
        # If no code block, assume entire response is YAML
        # (strip any leading/trailing prose)
        lines = text.strip().split('\n')
        yaml_lines = []
        in_yaml = False
        
        for line in lines:
            # YAML typically starts with a key: or ---
            if not in_yaml and (line.startswith('title:') or line.startswith('---') or line.startswith('id:')):
                in_yaml = True
            if in_yaml:
                # Stop if we hit obvious prose
                if line.strip() and not line.startswith(' ') and ':' not in line and not line.startswith('-'):
                    break
                yaml_lines.append(line)
        
        if yaml_lines:
            return '\n'.join(yaml_lines)
        
        return None
    
    def infer_severity(self, threat: ThreatDescription) -> Severity:
        """Infer severity from threat description if not provided."""
        if threat.severity_hint:
            return threat.severity_hint
        
        desc_lower = threat.description.lower()
        
        # Critical indicators
        critical_keywords = [
            'ransomware', 'zero-day', '0-day', 'critical', 'rce', 'remote code execution',
            'rootkit', 'bootkit', 'nation-state', 'apt', 'supply chain',
        ]
        if any(kw in desc_lower for kw in critical_keywords):
            return Severity.CRITICAL
        
        # High indicators
        high_keywords = [
            'credential', 'password', 'privilege escalation', 'lateral movement',
            'exfiltration', 'backdoor', 'c2', 'command and control', 'mimikatz',
            'cobalt strike', 'persistence', 'defense evasion',
        ]
        if any(kw in desc_lower for kw in high_keywords):
            return Severity.HIGH
        
        # Medium indicators
        medium_keywords = [
            'suspicious', 'unusual', 'anomaly', 'reconnaissance', 'scanning',
            'brute force', 'phishing', 'malware',
        ]
        if any(kw in desc_lower for kw in medium_keywords):
            return Severity.MEDIUM
        
        return Severity.LOW
