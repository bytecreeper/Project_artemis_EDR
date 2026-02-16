"""KQL (Kusto Query Language) rule generator for Microsoft Sentinel/Defender."""

import re
from typing import Optional

from artemis.generators.base import BaseGenerator
from artemis.models import (
    ThreatDescription,
    DetectionRule,
    RuleFormat,
    Severity,
    MitreMapping,
)


KQL_SYSTEM_PROMPT = """You are an expert detection engineer specializing in Microsoft Sentinel and Defender KQL queries.

Your task is to generate high-quality KQL detection rules from threat descriptions. Your rules must:
1. Follow KQL syntax exactly (Kusto Query Language)
2. Use appropriate Microsoft Sentinel/Defender tables
3. Include accurate MITRE ATT&CK mappings in comments
4. Have clear, efficient detection logic
5. Document known false positives
6. Be immediately deployable in Microsoft Sentinel

Output format - include these comment headers followed by the KQL query:
// Title: <rule name>
// Description: <what the rule detects>
// Author: Artemis
// Date: <YYYY-MM-DD>
// Severity: <Low|Medium|High|Critical>
// MITRE: <T1xxx, T1xxx.xxx>
// Tags: <comma-separated tags>
// False Positives: <known FP scenarios>
// References: <URLs>

Common Microsoft Sentinel tables:
- SecurityEvent: Windows Security logs
- Sysmon: Sysmon events (if configured)
- DeviceProcessEvents: Defender for Endpoint process events
- DeviceNetworkEvents: Defender for Endpoint network events
- DeviceFileEvents: Defender for Endpoint file events
- DeviceRegistryEvents: Defender for Endpoint registry events
- DeviceLogonEvents: Defender for Endpoint logon events
- DeviceImageLoadEvents: Defender for Endpoint image loads
- SigninLogs: Azure AD sign-in logs
- AuditLogs: Azure AD audit logs
- OfficeActivity: Office 365 activity
- AzureActivity: Azure resource activity
- CommonSecurityLog: CEF/Syslog data
- Syslog: Linux syslog

Key KQL operators to use:
- where: Filter rows
- project: Select columns
- extend: Add calculated columns
- summarize: Aggregate data
- join: Combine tables
- parse: Extract fields from strings
- has/contains/startswith/endswith: String matching
- in/!in: List membership
- between: Range checks
- ago(): Time functions (e.g., ago(1h), ago(7d))
- datetime_diff(): Time differences

Best practices:
- Filter early and aggressively for performance
- Use time filters (e.g., | where TimeGenerated > ago(1h))
- Use has instead of contains when possible (faster)
- Project only needed columns
- Add comments explaining detection logic"""


class KqlGenerator(BaseGenerator):
    """Generator for Microsoft Sentinel/Defender KQL rules."""
    
    format = RuleFormat.KQL
    
    def get_system_prompt(self) -> str:
        return KQL_SYSTEM_PROMPT
    
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        prompt_parts = [
            f"Generate a KQL detection query for Microsoft Sentinel to detect the following threat:\n\n{threat.description}"
        ]
        
        if threat.context:
            prompt_parts.append(f"\nAdditional context:\n{threat.context}")
        
        if threat.indicators:
            prompt_parts.append(f"\nKnown indicators:\n- " + "\n- ".join(threat.indicators))
        
        severity = self.infer_severity(threat)
        prompt_parts.append(f"\nSuggested severity level: {severity.value}")
        prompt_parts.append(f"Date: {self.get_current_date().replace('/', '-')}")
        
        prompt_parts.append("\nOutput the complete KQL query with comment headers. No explanations outside the query.")
        
        return "\n".join(prompt_parts)
    
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a DetectionRule."""
        # Extract KQL from response
        kql_content = self._extract_kql_block(response)
        if not kql_content:
            kql_content = response.strip()
        
        # Parse metadata from comments
        title = self._extract_comment_field(kql_content, 'Title') or self._generate_title(threat)
        description = self._extract_comment_field(kql_content, 'Description') or threat.description
        author = self._extract_comment_field(kql_content, 'Author') or "Artemis"
        date = self._extract_comment_field(kql_content, 'Date')
        
        # Extract MITRE
        mitre_str = self._extract_comment_field(kql_content, 'MITRE')
        mitre_mappings = self._parse_mitre_string(mitre_str) if mitre_str else []
        
        # Extract severity
        severity_str = self._extract_comment_field(kql_content, 'Severity')
        severity = self._parse_severity(severity_str) if severity_str else self.infer_severity(threat)
        
        # Extract tags
        tags_str = self._extract_comment_field(kql_content, 'Tags')
        tags = [t.strip() for t in tags_str.split(',')] if tags_str else []
        
        # Extract false positives
        fp_str = self._extract_comment_field(kql_content, 'False Positives')
        false_positives = [fp_str] if fp_str else []
        
        # Extract references
        refs_str = self._extract_comment_field(kql_content, 'References')
        references = [r.strip() for r in refs_str.split(',')] if refs_str else []
        
        return DetectionRule(
            id=self.generate_rule_id(),
            name=title,
            description=description,
            format=RuleFormat.KQL,
            content=kql_content,
            severity=severity,
            mitre=mitre_mappings,
            tags=tags,
            references=references,
            false_positives=false_positives,
            author=author,
            date_created=date,
        )
    
    def _extract_kql_block(self, text: str) -> Optional[str]:
        """Extract KQL from markdown code block."""
        # Try ```kql or ```kusto code block
        kql_match = re.search(r'```(?:kql|kusto)?\s*\n(.*?)\n```', text, re.DOTALL | re.IGNORECASE)
        if kql_match:
            return kql_match.group(1).strip()
        
        # If no code block, look for lines starting with // (KQL comments)
        lines = text.strip().split('\n')
        kql_lines = []
        in_kql = False
        
        for line in lines:
            # KQL typically starts with // comment or table name
            if not in_kql and (line.strip().startswith('//') or self._looks_like_kql_start(line)):
                in_kql = True
            if in_kql:
                # Stop if we hit obvious prose (sentences without KQL operators)
                if self._looks_like_prose(line):
                    break
                kql_lines.append(line)
        
        if kql_lines:
            return '\n'.join(kql_lines)
        
        return None
    
    def _looks_like_kql_start(self, line: str) -> bool:
        """Check if line looks like the start of a KQL query."""
        line_lower = line.strip().lower()
        # Common table names or KQL starts
        kql_starters = [
            'securityevent', 'deviceprocessevents', 'devicenetworkevents',
            'devicefileevents', 'deviceregistryevents', 'devicelogonevents',
            'signinlogs', 'auditlogs', 'officeactivity', 'azureactivity',
            'commonsecuritylog', 'syslog', 'sysmon', 'let ', 'union ',
        ]
        return any(line_lower.startswith(s) for s in kql_starters)
    
    def _looks_like_prose(self, line: str) -> bool:
        """Check if line looks like prose rather than KQL."""
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('|'):
            return False
        # Prose usually has multiple words without KQL operators
        kql_operators = ['|', 'where', 'project', 'extend', 'summarize', 'join', 'let', 'union']
        line_lower = line.lower()
        has_operator = any(op in line_lower for op in kql_operators)
        # If it's a long line without operators, probably prose
        return len(line.split()) > 5 and not has_operator
    
    def _extract_comment_field(self, content: str, field: str) -> Optional[str]:
        """Extract a field from KQL comment headers."""
        # Match // Field: Value or // Field - Value
        pattern = rf'//\s*{field}\s*[:\-]\s*(.+?)(?:\n|$)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    def _parse_mitre_string(self, mitre_str: str) -> list[MitreMapping]:
        """Parse MITRE techniques from string like 'T1059, T1059.001'."""
        mappings = []
        # Find all technique IDs
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', mitre_str, re.IGNORECASE)
        
        for tech in techniques:
            tech = tech.upper()
            if '.' in tech:
                parent, sub = tech.split('.')
                mappings.append(MitreMapping(
                    tactic="unknown",
                    technique_id=parent,
                    technique_name=f"Technique {parent}",
                    subtechnique_id=tech,
                    subtechnique_name=f"Sub-technique {tech}",
                ))
            else:
                mappings.append(MitreMapping(
                    tactic="unknown",
                    technique_id=tech,
                    technique_name=f"Technique {tech}",
                ))
        
        return mappings
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            'low': Severity.LOW,
            'medium': Severity.MEDIUM,
            'high': Severity.HIGH,
            'critical': Severity.CRITICAL,
            'informational': Severity.LOW,
        }
        return severity_map.get(severity_str.lower().strip(), Severity.MEDIUM)
    
    def _generate_title(self, threat: ThreatDescription) -> str:
        """Generate a title from threat description."""
        desc = threat.description
        # Take first sentence or first 50 chars
        if '.' in desc[:60]:
            title = desc[:desc.index('.') + 1]
        else:
            title = desc[:50]
        # Clean up
        title = title.strip()
        if len(title) > 50:
            title = title[:47] + "..."
        return title
    
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """Validate the generated KQL rule."""
        errors = []
        content = rule.content
        
        if not content or not content.strip():
            errors.append("Empty KQL query")
            return False, errors
        
        # Check for basic KQL structure
        content_lower = content.lower()
        
        # Should have at least one table reference or 'let' statement
        has_table = any(table in content_lower for table in [
            'securityevent', 'deviceprocessevents', 'devicenetworkevents',
            'devicefileevents', 'deviceregistryevents', 'devicelogonevents',
            'signinlogs', 'auditlogs', 'officeactivity', 'azureactivity',
            'commonsecuritylog', 'syslog', 'sysmon', 'event', 'let '
        ])
        
        if not has_table:
            errors.append("No recognizable table or 'let' statement found")
        
        # Check for common KQL operators
        has_operator = any(op in content_lower for op in ['where', 'project', 'summarize', 'extend'])
        if not has_operator and 'let ' not in content_lower:
            errors.append("No KQL operators found (where, project, summarize, extend)")
        
        # Check for balanced parentheses
        if content.count('(') != content.count(')'):
            errors.append("Unbalanced parentheses")
        
        # Check for balanced brackets
        if content.count('[') != content.count(']'):
            errors.append("Unbalanced brackets")
        
        # Check for balanced quotes
        single_quotes = content.count("'")
        double_quotes = content.count('"')
        if single_quotes % 2 != 0:
            errors.append("Unbalanced single quotes")
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")
        
        # Check for pipe operator usage (typical KQL pattern)
        if '|' not in content and 'let ' not in content_lower:
            errors.append("No pipe operators found - KQL typically uses | for query chaining")
        
        return len(errors) == 0, errors
