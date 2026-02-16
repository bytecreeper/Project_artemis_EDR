"""YARA rule generator."""

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


YARA_SYSTEM_PROMPT = """You are an expert malware analyst specializing in YARA rules.

Your task is to generate high-quality YARA rules from threat descriptions. Your rules must:
1. Follow YARA syntax exactly
2. Use appropriate string types ($s for text, $h for hex, $r for regex)
3. Include meaningful metadata (author, description, reference, date, hash if known)
4. Have efficient and accurate detection logic
5. Minimize false positives through specific conditions
6. Be immediately deployable for file scanning

Output ONLY valid YARA syntax - no explanations, no markdown outside the rule.

YARA rule structure:
```
rule RuleName : tag1 tag2 {
    meta:
        author = "Artemis"
        description = "Description here"
        date = "2026-02-16"
        reference = "URL"
        mitre_attack = "T1059"
        
    strings:
        $s1 = "string pattern" ascii wide
        $h1 = { 4D 5A 90 00 }  // hex pattern
        $r1 = /regex[0-9]+pattern/i
        
    condition:
        uint16(0) == 0x5A4D and  // MZ header check
        filesize < 5MB and
        2 of ($s*) or
        all of ($h*)
}
```

Common techniques:
- PE file checks: uint16(0) == 0x5A4D
- ELF checks: uint32(0) == 0x464C457F  
- File size limits: filesize < 10MB
- String counting: #string_name > 5
- Offset checks: $s1 at 0x100
- Import checks: pe.imports("kernel32.dll", "VirtualAlloc")

For malware families, include:
- Unique strings (C2 domains, mutex names, registry keys)
- Hex patterns (shellcode, encoded payloads)
- File structure markers
- Behavioral indicators"""


class YaraGenerator(BaseGenerator):
    """Generator for YARA detection rules."""
    
    format = RuleFormat.YARA
    
    def get_system_prompt(self) -> str:
        return YARA_SYSTEM_PROMPT
    
    def get_generation_prompt(self, threat: ThreatDescription) -> str:
        prompt_parts = [
            f"Generate a YARA rule to detect the following threat:\n\n{threat.description}"
        ]
        
        if threat.context:
            prompt_parts.append(f"\nAdditional context:\n{threat.context}")
        
        if threat.indicators:
            prompt_parts.append(f"\nKnown indicators (IOCs, hashes, strings):\n- " + "\n- ".join(threat.indicators))
        
        # Generate rule name from description
        rule_name = self._generate_rule_name(threat.description)
        prompt_parts.append(f"\nSuggested rule name: {rule_name}")
        prompt_parts.append(f"Date: {self.get_current_date()}")
        
        prompt_parts.append("\nOutput only the YARA rule, no additional text.")
        
        return "\n".join(prompt_parts)
    
    def _generate_rule_name(self, description: str) -> str:
        """Generate a valid YARA rule name from description."""
        # Extract key words
        words = re.findall(r'[A-Za-z]+', description)
        # Take first few significant words
        significant = [w for w in words if len(w) > 2 and w.lower() not in 
                       {'the', 'and', 'for', 'that', 'with', 'from', 'detect', 'detection'}]
        name_parts = significant[:4]
        if not name_parts:
            name_parts = ['Malware', 'Detection']
        # Join with underscores
        return '_'.join(w.capitalize() for w in name_parts)
    
    def parse_response(self, response: str, threat: ThreatDescription) -> DetectionRule:
        """Parse LLM response into a YARA DetectionRule."""
        
        # Extract YARA content
        yara_content = self._extract_yara_block(response)
        if not yara_content:
            yara_content = response.strip()
        
        # Parse rule metadata
        rule_name = self._extract_rule_name(yara_content)
        description = self._extract_meta_field(yara_content, 'description') or threat.description
        references = self._extract_references(yara_content)
        mitre_mappings = self._extract_mitre_mappings(yara_content)
        tags = self._extract_tags(yara_content)
        
        severity = self.infer_severity(threat)
        
        return DetectionRule(
            id=self.generate_rule_id(),
            name=rule_name or "YARA Rule",
            description=description,
            format=RuleFormat.YARA,
            content=yara_content,
            severity=severity,
            mitre=mitre_mappings,
            tags=tags,
            references=references,
            false_positives=[],
            author=self._extract_meta_field(yara_content, 'author') or "Artemis",
            date_created=self._extract_meta_field(yara_content, 'date'),
        )
    
    def _extract_yara_block(self, text: str) -> Optional[str]:
        """Extract YARA rule from response."""
        # Try markdown code block
        match = re.search(r'```(?:yara)?\s*\n(.*?)\n```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Try to find rule ... { ... } pattern
        match = re.search(r'(rule\s+\w+.*?\{.*?\})', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        return None
    
    def _extract_rule_name(self, content: str) -> Optional[str]:
        """Extract rule name from YARA content."""
        match = re.search(r'rule\s+(\w+)', content)
        return match.group(1) if match else None
    
    def _extract_meta_field(self, content: str, field: str) -> Optional[str]:
        """Extract a metadata field value."""
        pattern = rf'{field}\s*=\s*"([^"]*)"'
        match = re.search(pattern, content, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_references(self, content: str) -> list[str]:
        """Extract reference URLs from metadata."""
        refs = []
        pattern = r'reference\s*=\s*"([^"]*)"'
        for match in re.finditer(pattern, content, re.IGNORECASE):
            refs.append(match.group(1))
        return refs
    
    def _extract_mitre_mappings(self, content: str) -> list[MitreMapping]:
        """Extract MITRE ATT&CK mappings from metadata."""
        mappings = []
        
        # Look for mitre_attack, mitre, or attack_* fields
        patterns = [
            r'mitre_attack\s*=\s*"([^"]*)"',
            r'mitre\s*=\s*"([^"]*)"',
            r'attack_technique\s*=\s*"([^"]*)"',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1)
                # Extract technique IDs
                tech_ids = re.findall(r'T\d{4}(?:\.\d{3})?', value, re.IGNORECASE)
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
    
    def _extract_tags(self, content: str) -> list[str]:
        """Extract rule tags."""
        match = re.search(r'rule\s+\w+\s*:\s*([\w\s]+)\s*\{', content)
        if match:
            tags = match.group(1).strip().split()
            return [t for t in tags if t]
        return []
    
    def validate_rule(self, rule: DetectionRule) -> tuple[bool, list[str]]:
        """Validate a YARA rule."""
        errors = []
        content = rule.content
        
        # Check basic structure
        if not re.search(r'rule\s+\w+', content):
            errors.append("Missing rule declaration")
        
        # Check for opening/closing braces
        if content.count('{') != content.count('}'):
            errors.append("Mismatched braces")
        
        # Check for required sections
        if 'strings:' not in content and 'condition:' not in content:
            errors.append("Rule must have either strings or condition section")
        
        if 'condition:' not in content:
            errors.append("Missing condition section")
        
        # Validate string definitions
        string_defs = re.findall(r'\$(\w+)\s*=', content)
        condition_match = re.search(r'condition:\s*(.*?)(?:\}|$)', content, re.DOTALL)
        
        if condition_match:
            condition = condition_match.group(1)
            
            # Check for referenced but undefined strings
            referenced_strings = re.findall(r'\$(\w+)', condition)
            for ref in referenced_strings:
                # Skip special patterns like $* or $s*
                if ref not in string_defs and not re.match(r'^[a-z]\*?$', ref):
                    # Allow wildcards like $s* which expand
                    if not any(s.startswith(ref.rstrip('*')) for s in string_defs):
                        pass  # Could be a wildcard pattern
            
            # Check for empty condition
            if not condition.strip():
                errors.append("Empty condition")
        
        # Validate hex strings
        hex_strings = re.findall(r'\{\s*([^}]+)\s*\}', content)
        for hs in hex_strings:
            # Skip if it's a section (contains :)
            if ':' in hs:
                continue
            # Check hex pattern validity
            cleaned = re.sub(r'[\s\[\]\(\)\|\?]', '', hs)
            if cleaned and not re.match(r'^[0-9A-Fa-f]+$', cleaned):
                if not re.match(r'^[0-9A-Fa-f\s\[\]\(\)\|\?]+$', hs):
                    errors.append(f"Invalid hex pattern")
        
        # Check for common mistakes
        if re.search(r'filesize\s*[<>]=?\s*\d+[GMK]B', content, re.IGNORECASE):
            # Check for space before unit - common mistake
            if re.search(r'filesize\s*[<>]=?\s*\d+\s+[GMK]B', content, re.IGNORECASE):
                errors.append("Invalid filesize syntax - no space before unit (use 5MB not 5 MB)")
        
        return len(errors) == 0, errors
