"""Sigma rule generator."""

import json
import re
from typing import Optional

import yaml

from artemis.generators.base import BaseGenerator
from artemis.models import (
    ThreatDescription,
    DetectionRule,
    RuleFormat,
    Severity,
    MitreMapping,
)


SIGMA_SYSTEM_PROMPT = """You are an expert detection engineer specializing in Sigma rules.

Your task is to generate high-quality Sigma rules from threat descriptions. Your rules must:
1. Follow the official Sigma specification exactly
2. Use appropriate log sources (sysmon, windows, linux, etc.)
3. Include accurate MITRE ATT&CK mappings
4. Have clear, specific detection logic
5. Document known false positives
6. Be immediately deployable in production environments

Output ONLY valid YAML - no explanations, no markdown outside the rule itself.

Key Sigma fields to always include:
- title: Clear, concise rule name
- id: UUID format
- status: experimental/test/stable
- level: informational/low/medium/high/critical
- description: What the rule detects
- author: Artemis
- date: YYYY/MM/DD
- references: Related URLs
- tags: MITRE ATT&CK tags (attack.tactic, attack.t1xxx)
- logsource: category, product, service
- detection: selection, filter, condition
- falsepositives: List of FP scenarios

Common logsource categories:
- process_creation (Sysmon EventID 1)
- network_connection (Sysmon EventID 3)
- file_event (Sysmon EventID 11)
- registry_event (Sysmon EventID 12-14)
- dns_query (Sysmon EventID 22)
- image_load (Sysmon EventID 7)
- windows (Windows Security/System logs)
- linux (Linux audit logs)
- webserver (Apache, nginx, IIS)"""


class SigmaGenerator(BaseGenerator):
    """Generator for Sigma detection rules."""
    
    format = RuleFormat.SIGMA
    
    def get_system_prompt(self) -> str:
        return SIGMA_SYSTEM_PROMPT
    
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        prompt_parts = [
            f"Generate a Sigma rule to detect the following threat:\n\n{threat.description}"
        ]
        
        if threat.context:
            prompt_parts.append(f"\nAdditional context:\n{threat.context}")
        
        if threat.indicators:
            prompt_parts.append(f"\nKnown indicators:\n- " + "\n- ".join(threat.indicators))
        
        severity = self.infer_severity(threat)
        prompt_parts.append(f"\nSuggested severity level: {severity.value}")
        
        prompt_parts.append(f"\nRule ID to use: {self.generate_rule_id()}")
        prompt_parts.append(f"Date: {self.get_current_date()}")
        
        prompt_parts.append("\nOutput only the YAML rule, no additional text.")
        
        return "\n".join(prompt_parts)
    
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a Sigma DetectionRule."""
        
        # Extract YAML content
        yaml_content = self.extract_yaml_block(response)
        if not yaml_content:
            yaml_content = response.strip()
        
        # Parse YAML
        try:
            rule_data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in response: {e}")
        
        if not isinstance(rule_data, dict):
            raise ValueError("Response did not contain a valid Sigma rule structure")
        
        # Extract MITRE mappings from tags
        mitre_mappings = self._extract_mitre_from_tags(rule_data.get("tags", []))
        
        # Map severity
        level = rule_data.get("level", "medium")
        severity_map = {
            "informational": Severity.LOW,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        severity = severity_map.get(level.lower(), Severity.MEDIUM)
        
        # Build DetectionRule
        return DetectionRule(
            id=rule_data.get("id", self.generate_rule_id()),
            name=rule_data.get("title", "Untitled Rule"),
            description=rule_data.get("description", threat.description),
            format=RuleFormat.SIGMA,
            content=yaml_content,
            severity=severity,
            mitre=mitre_mappings,
            tags=rule_data.get("tags", []),
            references=rule_data.get("references", []),
            false_positives=rule_data.get("falsepositives", []),
            author=rule_data.get("author", "Artemis"),
            date_created=rule_data.get("date"),
        )
    
    def _extract_mitre_from_tags(self, tags: list[str]) -> list[MitreMapping]:
        """Extract MITRE ATT&CK mappings from Sigma tags."""
        mappings = []
        current_tactic = None
        
        # MITRE tactics in order
        tactics = {
            "reconnaissance": "Reconnaissance",
            "resource_development": "Resource Development", 
            "initial_access": "Initial Access",
            "execution": "Execution",
            "persistence": "Persistence",
            "privilege_escalation": "Privilege Escalation",
            "defense_evasion": "Defense Evasion",
            "credential_access": "Credential Access",
            "discovery": "Discovery",
            "lateral_movement": "Lateral Movement",
            "collection": "Collection",
            "command_and_control": "Command and Control",
            "exfiltration": "Exfiltration",
            "impact": "Impact",
        }
        
        for tag in tags:
            tag_lower = tag.lower()
            
            # Check for tactic
            if tag_lower.startswith("attack."):
                tag_value = tag_lower.replace("attack.", "")
                
                if tag_value in tactics:
                    current_tactic = tactics[tag_value]
                
                # Check for technique ID (t1xxx or t1xxx.xxx)
                elif re.match(r't\d{4}(\.\d{3})?', tag_value):
                    technique_id = tag_value.upper()
                    
                    # Split main technique and subtechnique
                    if '.' in technique_id:
                        main_id, sub_id = technique_id.split('.', 1)
                        mappings.append(MitreMapping(
                            tactic=current_tactic or "Unknown",
                            technique_id=main_id,
                            technique_name=f"Technique {main_id}",
                            subtechnique_id=technique_id,
                            subtechnique_name=f"Sub-technique {technique_id}",
                        ))
                    else:
                        mappings.append(MitreMapping(
                            tactic=current_tactic or "Unknown",
                            technique_id=technique_id,
                            technique_name=f"Technique {technique_id}",
                        ))
        
        return mappings
    
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """Validate a Sigma rule."""
        errors = []
        
        try:
            rule_data = yaml.safe_load(rule.content)
        except yaml.YAMLError as e:
            return False, [f"Invalid YAML: {e}"]
        
        if not isinstance(rule_data, dict):
            return False, ["Rule must be a YAML mapping"]
        
        # Required fields
        required_fields = ["title", "logsource", "detection"]
        for field in required_fields:
            if field not in rule_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate logsource
        if "logsource" in rule_data:
            logsource = rule_data["logsource"]
            if not isinstance(logsource, dict):
                errors.append("logsource must be a mapping")
            elif not any(k in logsource for k in ["category", "product", "service"]):
                errors.append("logsource must have at least one of: category, product, service")
        
        # Validate detection
        if "detection" in rule_data:
            detection = rule_data["detection"]
            if not isinstance(detection, dict):
                errors.append("detection must be a mapping")
            elif "condition" not in detection:
                errors.append("detection must have a 'condition' field")
            elif len(detection) < 2:
                errors.append("detection must have at least one selection/filter plus condition")
        
        # Validate level if present
        if "level" in rule_data:
            valid_levels = ["informational", "low", "medium", "high", "critical"]
            if rule_data["level"].lower() not in valid_levels:
                errors.append(f"Invalid level: {rule_data['level']}. Must be one of: {valid_levels}")
        
        # Validate status if present
        if "status" in rule_data:
            valid_statuses = ["experimental", "test", "stable", "deprecated", "unsupported"]
            if rule_data["status"].lower() not in valid_statuses:
                errors.append(f"Invalid status: {rule_data['status']}")
        
        # Check for common mistakes
        if "detection" in rule_data:
            detection = rule_data["detection"]
            condition = detection.get("condition", "")
            
            # Check that referenced selections exist
            # Simple regex to find selection references
            refs = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', condition)
            keywords = {"and", "or", "not", "all", "of", "them", "1"}
            for ref in refs:
                if ref.lower() not in keywords and ref not in detection:
                    errors.append(f"Condition references undefined selection: {ref}")
        
        return len(errors) == 0, errors
