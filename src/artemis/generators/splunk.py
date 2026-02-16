"""Splunk SPL query generator."""

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


SPLUNK_SYSTEM_PROMPT = """You are an expert Splunk security analyst specializing in SPL (Search Processing Language).

Your task is to generate high-quality Splunk detection queries from threat descriptions. Your queries must:
1. Follow SPL syntax exactly
2. Use appropriate sourcetypes and indexes
3. Include efficient search patterns (time-bound, indexed fields first)
4. Use relevant Splunk commands (stats, eval, where, rex, lookup)
5. Be optimized for performance
6. Include comments explaining the detection logic

Output format - a complete Splunk alert query with metadata as comments:

```spl
`comment("Title: Detection Name")`
`comment("Description: What this detects")`
`comment("Author: Artemis")`
`comment("MITRE: T1059.001")`
`comment("Severity: high")`

index=windows sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Security
| search EventCode=4688
| where match(CommandLine, "(?i)powershell.*-enc")
| stats count by Computer, User, CommandLine, ParentCommandLine
| where count > 0
| table _time, Computer, User, CommandLine, ParentCommandLine
```

Common sourcetypes:
- WinEventLog:Security, WinEventLog:System (Windows)
- XmlWinEventLog:* (XML format Windows logs)  
- sysmon (Sysmon logs)
- linux_secure, linux_audit (Linux)
- stream:* (Network traffic)
- aws:cloudtrail, azure:* (Cloud)

Best practices:
- Always specify index when possible
- Put indexed fields (sourcetype, EventCode) early in search
- Use | tstats for large datasets
- Use | where instead of | search for post-filter
- Include | table or | stats for output
- Add time constraints: earliest=-24h latest=now"""


class SplunkGenerator(BaseGenerator):
    """Generator for Splunk SPL detection queries."""
    
    format = RuleFormat.SPLUNK
    
    def get_system_prompt(self) -> str:
        return SPLUNK_SYSTEM_PROMPT
    
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        prompt_parts = [
            f"Generate a Splunk SPL detection query for the following threat:\n\n{threat.description}"
        ]
        
        if threat.context:
            prompt_parts.append(f"\nEnvironment/log source context:\n{threat.context}")
        
        if threat.indicators:
            prompt_parts.append(f"\nKnown indicators to detect:\n- " + "\n- ".join(threat.indicators))
        
        severity = self.infer_severity(threat)
        prompt_parts.append(f"\nSuggested severity level: {severity.value}")
        prompt_parts.append(f"Date: {self.get_current_date()}")
        
        prompt_parts.append("\nOutput the SPL query with metadata comments. No additional explanation.")
        
        return "\n".join(prompt_parts)
    
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a Splunk DetectionRule."""
        
        # Extract SPL content
        spl_content = self._extract_spl_block(response)
        if not spl_content:
            spl_content = response.strip()
        
        # Parse metadata from comments
        title = self._extract_comment_field(spl_content, 'Title') or self._generate_title(threat)
        description = self._extract_comment_field(spl_content, 'Description') or threat.description
        author = self._extract_comment_field(spl_content, 'Author') or "Artemis"
        
        # Extract MITRE
        mitre_str = self._extract_comment_field(spl_content, 'MITRE')
        mitre_mappings = self._parse_mitre_string(mitre_str) if mitre_str else []
        
        # Extract severity from comments or infer
        severity_str = self._extract_comment_field(spl_content, 'Severity')
        if severity_str:
            severity_map = {
                'low': Severity.LOW,
                'medium': Severity.MEDIUM,
                'high': Severity.HIGH,
                'critical': Severity.CRITICAL,
            }
            severity = severity_map.get(severity_str.lower(), self.infer_severity(threat))
        else:
            severity = self.infer_severity(threat)
        
        return DetectionRule(
            id=self.generate_rule_id(),
            name=title,
            description=description,
            format=RuleFormat.SPLUNK,
            content=spl_content,
            severity=severity,
            mitre=mitre_mappings,
            tags=self._extract_tags_from_query(spl_content),
            references=[],
            false_positives=[],
            author=author,
            date_created=self.get_current_date(),
        )
    
    def _extract_spl_block(self, text: str) -> Optional[str]:
        """Extract SPL query from response."""
        # Try markdown code block
        match = re.search(r'```(?:spl|splunk)?\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Look for query starting with common patterns
        lines = text.strip().split('\n')
        spl_lines = []
        in_query = False
        
        for line in lines:
            # Start capturing at index=, sourcetype=, or | 
            if not in_query:
                if re.match(r'^(index\s*=|sourcetype\s*=|\||`comment)', line.strip(), re.IGNORECASE):
                    in_query = True
            
            if in_query:
                # Stop at obvious prose
                if line.strip() and not any([
                    line.strip().startswith('|'),
                    line.strip().startswith('`'),
                    '=' in line,
                    line.strip().startswith('//'),
                    line.strip().startswith('/*'),
                    re.match(r'^\s*(AND|OR|NOT|where|search|stats|eval|table|rex|lookup)', line.strip(), re.IGNORECASE),
                ]):
                    # Check if it looks like prose
                    words = line.split()
                    if len(words) > 10 and not any(c in line for c in ['=', '|', '(', ')']):
                        break
                
                spl_lines.append(line)
        
        if spl_lines:
            return '\n'.join(spl_lines).strip()
        
        return None
    
    def _extract_comment_field(self, content: str, field: str) -> Optional[str]:
        """Extract a field from comment metadata."""
        # Pattern: `comment("Field: value")`
        pattern = rf'`comment\("{field}:\s*([^"]+)"\)`'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        # Also try // Field: value style
        pattern = rf'//\s*{field}:\s*(.+?)(?:\n|$)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        return None
    
    def _generate_title(self, threat: ThreatDescription) -> str:
        """Generate a title from threat description."""
        words = threat.description.split()[:8]
        return ' '.join(words).rstrip('.,;:')
    
    def _parse_mitre_string(self, mitre_str: str) -> list[MitreMapping]:
        """Parse MITRE technique IDs from string."""
        mappings = []
        tech_ids = re.findall(r'T\d{4}(?:\.\d{3})?', mitre_str, re.IGNORECASE)
        
        for tid in tech_ids:
            tid = tid.upper()
            if '.' in tid:
                main_id, sub = tid.split('.', 1)
                mappings.append(MitreMapping(
                    tactic="Unknown",
                    technique_id=main_id,
                    technique_name=f"Technique {main_id}",
                    subtechnique_id=tid,
                    subtechnique_name=f"Sub-technique {tid}",
                ))
            else:
                mappings.append(MitreMapping(
                    tactic="Unknown",
                    technique_id=tid,
                    technique_name=f"Technique {tid}",
                ))
        
        return mappings
    
    def _extract_tags_from_query(self, content: str) -> list[str]:
        """Extract relevant tags from query content."""
        tags = []
        content_lower = content.lower()
        
        tag_patterns = {
            'windows': r'wineventlog|xmlwineventlog|sysmon|eventcode',
            'linux': r'linux_secure|linux_audit|/var/log',
            'network': r'stream:|firewall|netflow',
            'cloud': r'cloudtrail|azure:|gcp\.',
            'authentication': r'eventcode\s*=\s*(4624|4625|4648)',
            'process': r'eventcode\s*=\s*(4688|1\b)|process_creation',
            'powershell': r'powershell|scriptblock',
        }
        
        for tag, pattern in tag_patterns.items():
            if re.search(pattern, content_lower):
                tags.append(tag)
        
        return tags
    
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """Validate a Splunk SPL query."""
        errors = []
        content = rule.content
        
        # Remove comments for validation
        clean_content = re.sub(r'`comment\([^)]+\)`', '', content)
        clean_content = re.sub(r'//.*$', '', clean_content, flags=re.MULTILINE)
        clean_content = clean_content.strip()
        
        if not clean_content:
            errors.append("Query is empty (only comments)")
            return False, errors
        
        # Check for basic search structure
        if not re.search(r'\b(index\s*=|sourcetype\s*=|\bsearch\b|\|)', clean_content, re.IGNORECASE):
            errors.append("Query should start with index=, sourcetype=, search, or a pipe command")
        
        # Check for balanced parentheses
        if clean_content.count('(') != clean_content.count(')'):
            errors.append("Unbalanced parentheses")
        
        # Check for balanced brackets
        if clean_content.count('[') != clean_content.count(']'):
            errors.append("Unbalanced brackets")
        
        # Check for balanced quotes
        single_quotes = len(re.findall(r"(?<![\\])'", clean_content))
        double_quotes = len(re.findall(r'(?<![\\])"', clean_content))
        if single_quotes % 2 != 0:
            errors.append("Unbalanced single quotes")
        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")
        
        # Check for common SPL syntax errors
        if re.search(r'\|\s*\|', clean_content):
            errors.append("Empty pipe command (||)")
        
        # Check for output command
        output_commands = ['table', 'stats', 'chart', 'timechart', 'top', 'rare', 'outputlookup', 'collect']
        has_output = any(re.search(rf'\|\s*{cmd}\b', clean_content, re.IGNORECASE) for cmd in output_commands)
        if not has_output:
            # Not an error, just a warning - detection can work without output formatting
            pass
        
        # Validate common command syntax
        # Check eval syntax
        eval_matches = re.findall(r'\|\s*eval\s+(\w+)\s*=', clean_content, re.IGNORECASE)
        if not eval_matches and '| eval' in clean_content.lower():
            # Has eval but no valid assignment
            if not re.search(r'\|\s*eval\s+\w+\s*=', clean_content, re.IGNORECASE):
                errors.append("Invalid eval syntax - should be: | eval field=expression")
        
        return len(errors) == 0, errors
