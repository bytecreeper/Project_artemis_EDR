"""Snort/Suricata IDS rule generator."""

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


SNORT_SYSTEM_PROMPT = """You are an expert detection engineer specializing in Snort and Suricata IDS rules.

Your task is to generate high-quality network intrusion detection rules from threat descriptions. Your rules must:
1. Follow Snort 3 / Suricata syntax exactly
2. Use appropriate protocol and port specifications
3. Include accurate MITRE ATT&CK mappings in metadata
4. Have efficient, specific detection logic
5. Minimize false positives
6. Be immediately deployable

Output format - a complete Snort/Suricata rule with metadata:

# Rule metadata as comments:
# Title: <rule name>
# Description: <what the rule detects>  
# Author: Artemis
# Date: <YYYY-MM-DD>
# Severity: <low|medium|high|critical>
# MITRE: <T1xxx, T1xxx.xxx>
# References: <URLs>
# False Positives: <known FP scenarios>

<actual rule>

Rule structure:
action protocol src_ip src_port -> dst_ip dst_port (options)

Common actions:
- alert: Generate alert
- drop: Drop packet (inline mode)
- reject: Drop and send reset

Common protocols:
- tcp, udp, icmp, ip, http, dns, tls, ssh, ftp, smtp

Key rule options:
- msg: Alert message
- sid: Unique rule ID (use 1000001+ for custom rules)
- rev: Rule revision
- classtype: Attack classification
- reference: External references
- metadata: Key-value pairs (mitre_technique, severity, etc.)

Content matching:
- content: Exact byte match
- nocase: Case-insensitive
- depth: Search depth from start
- offset: Search offset
- distance: Bytes after previous match
- within: Max bytes for next match
- pcre: Perl-compatible regex

HTTP-specific (Suricata):
- http.uri, http.host, http.header, http.method
- http.request_body, http.response_body
- http.user_agent, http.cookie

Flow options:
- flow: to_server/to_client, established
- flowbits: Set/check state

Best practices:
- Be specific with content matches
- Use fast_pattern for primary content
- Anchor matches with depth/offset when possible
- Include flow direction
- Use classtype for categorization
- Add meaningful reference URLs"""


class SnortGenerator(BaseGenerator):
    """Generator for Snort/Suricata IDS rules."""
    
    format = RuleFormat.SNORT
    
    def get_system_prompt(self) -> str:
        return SNORT_SYSTEM_PROMPT
    
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        prompt_parts = [
            f"Generate a Snort/Suricata IDS rule to detect the following network threat:\n\n{threat.description}"
        ]
        
        if threat.context:
            prompt_parts.append(f"\nAdditional context:\n{threat.context}")
        
        if threat.indicators:
            prompt_parts.append(f"\nKnown indicators (IPs, domains, patterns):\n- " + "\n- ".join(threat.indicators))
        
        severity = self.infer_severity(threat)
        prompt_parts.append(f"\nSuggested severity level: {severity.value}")
        
        # Generate a SID in the custom range
        import random
        sid = random.randint(1000001, 9999999)
        prompt_parts.append(f"\nUse SID: {sid}")
        prompt_parts.append(f"Date: {self.get_current_date().replace('/', '-')}")
        
        prompt_parts.append("\nOutput the complete rule with comment metadata. No explanations outside the rule.")
        
        return "\n".join(prompt_parts)
    
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a DetectionRule."""
        # Extract the rule content
        rule_content = self._extract_rule_block(response)
        if not rule_content:
            rule_content = response.strip()
        
        # Parse metadata from comments
        title = self._extract_comment_field(rule_content, 'Title') or self._generate_title(threat)
        description = self._extract_comment_field(rule_content, 'Description') or threat.description
        author = self._extract_comment_field(rule_content, 'Author') or "Artemis"
        date = self._extract_comment_field(rule_content, 'Date')
        
        # Extract MITRE
        mitre_str = self._extract_comment_field(rule_content, 'MITRE')
        mitre_mappings = self._parse_mitre_string(mitre_str) if mitre_str else []
        
        # Extract severity
        severity_str = self._extract_comment_field(rule_content, 'Severity')
        severity = self._parse_severity(severity_str) if severity_str else self.infer_severity(threat)
        
        # Extract SID from rule if present
        rule_id = self._extract_sid(rule_content) or self.generate_rule_id()
        
        # Extract references
        refs_str = self._extract_comment_field(rule_content, 'References')
        references = [r.strip() for r in refs_str.split(',')] if refs_str else []
        
        # Extract false positives
        fp_str = self._extract_comment_field(rule_content, 'False Positives')
        false_positives = [fp_str] if fp_str else []
        
        # Extract classtype as tag
        classtype = self._extract_classtype(rule_content)
        tags = [classtype] if classtype else []
        
        return DetectionRule(
            id=rule_id,
            name=title,
            description=description,
            format=RuleFormat.SNORT,
            content=rule_content,
            severity=severity,
            mitre=mitre_mappings,
            tags=tags,
            references=references,
            false_positives=false_positives,
            author=author,
            date_created=date,
        )
    
    def _extract_rule_block(self, text: str) -> Optional[str]:
        """Extract Snort rule from response."""
        # Try markdown code block
        code_match = re.search(r'```(?:snort|suricata)?\s*\n(.*?)\n```', text, re.DOTALL | re.IGNORECASE)
        if code_match:
            return code_match.group(1).strip()
        
        # Look for lines that are comments or rules
        lines = text.strip().split('\n')
        rule_lines = []
        in_rule = False
        
        for line in lines:
            stripped = line.strip()
            # Start capturing at comments or rule actions
            if not in_rule and (stripped.startswith('#') or self._is_rule_start(stripped)):
                in_rule = True
            if in_rule:
                # Stop if we hit obvious prose
                if self._looks_like_prose(stripped):
                    break
                rule_lines.append(line)
        
        if rule_lines:
            return '\n'.join(rule_lines)
        
        return None
    
    def _is_rule_start(self, line: str) -> bool:
        """Check if line looks like a Snort rule start."""
        actions = ['alert', 'drop', 'reject', 'pass', 'log', 'activate', 'dynamic']
        line_lower = line.lower()
        return any(line_lower.startswith(action + ' ') for action in actions)
    
    def _looks_like_prose(self, line: str) -> bool:
        """Check if line looks like prose rather than a rule."""
        if not line or line.startswith('#') or line.startswith('alert') or line.startswith('drop'):
            return False
        # Prose usually has multiple words without rule syntax
        if len(line.split()) > 8 and '(' not in line and '->' not in line:
            return True
        return False
    
    def _extract_comment_field(self, content: str, field: str) -> Optional[str]:
        """Extract a field from comment metadata."""
        pattern = rf'#\s*{field}\s*[:\-]\s*(.+?)(?:\n|$)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_sid(self, content: str) -> Optional[str]:
        """Extract SID from rule."""
        match = re.search(r'sid\s*:\s*(\d+)', content)
        if match:
            return match.group(1)
        return None
    
    def _extract_classtype(self, content: str) -> Optional[str]:
        """Extract classtype from rule."""
        match = re.search(r'classtype\s*:\s*([^;]+)', content)
        if match:
            return match.group(1).strip()
        return None
    
    def _parse_mitre_string(self, mitre_str: str) -> list[MitreMapping]:
        """Parse MITRE techniques from string."""
        mappings = []
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
        }
        return severity_map.get(severity_str.lower().strip(), Severity.MEDIUM)
    
    def _generate_title(self, threat: ThreatDescription) -> str:
        """Generate a title from threat description."""
        desc = threat.description
        if '.' in desc[:60]:
            title = desc[:desc.index('.') + 1]
        else:
            title = desc[:50]
        title = title.strip()
        if len(title) > 50:
            title = title[:47] + "..."
        return title
    
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """Validate the generated Snort rule."""
        errors = []
        content = rule.content
        
        if not content or not content.strip():
            errors.append("Empty rule")
            return False, errors
        
        # Remove comments for validation
        rule_lines = [l for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        if not rule_lines:
            errors.append("No rule found (only comments)")
            return False, errors
        
        # Find the actual rule line(s)
        rule_text = ' '.join(rule_lines)
        
        # Check for action
        actions = ['alert', 'drop', 'reject', 'pass', 'log', 'activate', 'dynamic']
        has_action = any(rule_text.lower().startswith(a + ' ') for a in actions)
        if not has_action:
            errors.append("Rule must start with an action (alert, drop, reject, etc.)")
        
        # Check for protocol (must follow action)
        protocols = ['tcp', 'udp', 'icmp', 'ip', 'http', 'dns', 'tls', 'ssh', 'ftp', 'smtp', 'any']
        # Protocol should appear after action keyword
        rule_lower = rule_text.lower()
        has_protocol = False
        for action in actions:
            if rule_lower.startswith(action + ' '):
                # Check what follows the action
                after_action = rule_lower[len(action):].strip()
                has_protocol = any(after_action.startswith(p + ' ') for p in protocols)
                break
        if not has_protocol:
            errors.append("No protocol specified (tcp, udp, icmp, http, etc.)")
        
        # Check for direction operator
        if '->' not in rule_text and '<>' not in rule_text:
            errors.append("Missing direction operator (-> or <>)")
        
        # Check for rule options (parentheses)
        if '(' not in rule_text or ')' not in rule_text:
            errors.append("Missing rule options (content in parentheses)")
        
        # Check balanced parentheses
        if rule_text.count('(') != rule_text.count(')'):
            errors.append("Unbalanced parentheses")
        
        # Check for required options
        if 'msg:' not in rule_text.lower() and 'msg :' not in rule_text.lower():
            errors.append("Missing msg option (alert message)")
        
        if 'sid:' not in rule_text.lower() and 'sid :' not in rule_text.lower():
            errors.append("Missing sid option (rule ID)")
        
        # Check for balanced quotes
        double_quotes = rule_text.count('"')
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")
        
        # Check semicolon termination of options
        if '(' in rule_text:
            options_section = rule_text[rule_text.index('('):]
            if not options_section.rstrip().endswith(')'):
                errors.append("Rule options not properly closed")
        
        return len(errors) == 0, errors
