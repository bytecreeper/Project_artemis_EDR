"""Tests for Snort/Suricata generator."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from artemis.generators.snort import SnortGenerator
from artemis.models import ThreatDescription, RuleFormat, Severity, DetectionRule


class MockLLM:
    """Mock LLM for testing."""
    
    def __init__(self, response: str):
        self.response = response
        self.generate = AsyncMock(return_value=(response, {"model": "test"}))
    
    def get_model_name(self) -> str:
        return "test/mock"


class TestSnortGenerator:
    """Test Snort rule generation."""
    
    def test_generate_basic(self):
        """Test basic Snort rule generation."""
        response = '''# Title: Detect Cobalt Strike Beacon Traffic
# Description: Detects Cobalt Strike beacon HTTP traffic patterns
# Author: Artemis
# Date: 2026-02-16
# Severity: High
# MITRE: T1071.001, T1573
# References: https://attack.mitre.org/techniques/T1071/001/
# False Positives: Legitimate HTTPS traffic with similar patterns

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ARTEMIS Cobalt Strike Beacon HTTP Traffic"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/submit.php?"; fast_pattern; content:"id="; distance:0; http.user_agent; content:"Mozilla/"; classtype:trojan-activity; sid:1000001; rev:1; metadata:mitre_technique T1071.001;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Detect Cobalt Strike beacon C2 traffic",
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert rule.name == "Detect Cobalt Strike Beacon Traffic"
        assert rule.format == RuleFormat.SNORT
        assert "alert http" in rule.content
        assert "Cobalt Strike" in rule.content
        assert "sid:1000001" in rule.content
    
    def test_generate_with_indicators(self):
        """Test Snort rule generation with IOCs."""
        response = '''# Title: Malicious Domain DNS Query
# Description: Detects DNS queries to known malicious domains
# Author: Artemis
# Severity: Critical
# MITRE: T1071.004

alert dns $HOME_NET any -> any 53 (msg:"ARTEMIS DNS Query to Malicious Domain"; dns.query; content:"evil.com"; nocase; classtype:trojan-activity; sid:1000002; rev:1;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Detect DNS queries to malicious domains",
            indicators=["evil.com", "bad-domain.net"],
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert "dns" in rule.content.lower()
        assert "evil.com" in rule.content
    
    def test_mitre_extraction(self):
        """Test MITRE ATT&CK extraction from comments."""
        response = '''# Title: Test Rule
# MITRE: T1071.001, T1573, T1041

alert tcp any any -> any any (msg:"Test"; sid:1000003; rev:1;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert len(rule.mitre) == 3
        technique_ids = [m.technique_id for m in rule.mitre]
        assert "T1071" in technique_ids
        assert "T1573" in technique_ids
        assert "T1041" in technique_ids
    
    def test_severity_from_comment(self):
        """Test severity extraction from comment."""
        response = '''# Title: Critical Alert
# Severity: Critical

alert tcp any any -> any any (msg:"Critical"; sid:1000004; rev:1;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        assert rule.severity == Severity.CRITICAL
    
    def test_sid_extraction(self):
        """Test SID extraction from rule."""
        response = '''# Title: Test
alert tcp any any -> any any (msg:"Test"; sid:5555555; rev:1;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        assert rule.id == "5555555"
    
    def test_classtype_as_tag(self):
        """Test classtype extraction as tag."""
        response = '''# Title: Test
alert tcp any any -> any any (msg:"Test"; classtype:attempted-admin; sid:1000005; rev:1;)
'''
        llm = MockLLM(response)
        generator = SnortGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.SNORT,
        )
        
        rule = generator.parse_response(response, threat)
        assert "attempted-admin" in rule.tags


class TestSnortValidation:
    """Test Snort rule validation."""
    
    def test_validation_pass(self):
        """Test valid Snort rule passes validation."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test Rule",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test Rule"; flow:established,to_server; content:"test"; sid:1000001; rev:1;)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert is_valid
        assert len(errors) == 0
    
    def test_validate_empty_rule(self):
        """Test empty rule fails validation."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content="",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert "Empty rule" in errors
    
    def test_validate_missing_action(self):
        """Test rule without action fails validation."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("action" in e.lower() for e in errors)
    
    def test_validate_missing_protocol(self):
        """Test rule without protocol fails validation."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("protocol" in e.lower() for e in errors)
    
    def test_validate_missing_direction(self):
        """Test rule without direction operator fails."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert tcp $HOME_NET any $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("direction" in e.lower() for e in errors)
    
    def test_validate_missing_msg(self):
        """Test rule without msg option fails."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (content:"test"; sid:1000001;)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("msg" in e.lower() for e in errors)
    
    def test_validate_missing_sid(self):
        """Test rule without SID fails."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test";)',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("sid" in e.lower() for e in errors)
    
    def test_validate_unbalanced_parens(self):
        """Test rule with unbalanced parentheses fails."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("parenthes" in e.lower() for e in errors)
    
    def test_validate_with_comments(self):
        """Test rule with comment metadata passes validation."""
        generator = SnortGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SNORT,
            content='''# Title: Test Rule
# Author: Artemis

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test Rule"; flow:established; content:"test"; sid:1000001; rev:1;)''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert is_valid
        assert len(errors) == 0


class TestSnortExtraction:
    """Test Snort content extraction."""
    
    def test_extract_from_code_block(self):
        """Test extraction from markdown code block."""
        generator = SnortGenerator(llm=None)
        
        text = '''Here's the Snort rule:

```snort
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;)
```

This rule detects test traffic.'''
        
        result = generator._extract_rule_block(text)
        assert result is not None
        assert "alert tcp" in result
        assert "Here's the Snort rule" not in result
    
    def test_extract_with_comments(self):
        """Test extraction with comment metadata."""
        generator = SnortGenerator(llm=None)
        
        text = '''# Title: Test Rule
# Description: A test

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1000001;)'''
        
        result = generator._extract_rule_block(text)
        assert result is not None
        assert "# Title: Test Rule" in result
        assert "alert tcp" in result
    
    def test_extract_comment_field(self):
        """Test comment field extraction."""
        generator = SnortGenerator(llm=None)
        
        content = '''# Title: My Detection Rule
# Description: Detects bad traffic
# Severity: High
# MITRE: T1071, T1573

alert tcp any any -> any any (msg:"Test"; sid:1;)'''
        
        assert generator._extract_comment_field(content, 'Title') == "My Detection Rule"
        assert generator._extract_comment_field(content, 'Description') == "Detects bad traffic"
        assert generator._extract_comment_field(content, 'Severity') == "High"
        assert generator._extract_comment_field(content, 'MITRE') == "T1071, T1573"
    
    def test_parse_mitre_string(self):
        """Test MITRE string parsing."""
        generator = SnortGenerator(llm=None)
        
        mitre_str = "T1071.001, T1573, T1041.002"
        mappings = generator._parse_mitre_string(mitre_str)
        
        assert len(mappings) == 3
        
        # Check sub-technique handling
        subtechs = [m for m in mappings if m.subtechnique_id]
        assert len(subtechs) == 2
        assert any(m.subtechnique_id == "T1071.001" for m in subtechs)
        assert any(m.subtechnique_id == "T1041.002" for m in subtechs)
