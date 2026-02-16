"""Tests for KQL generator."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from artemis.generators.kql import KqlGenerator
from artemis.models import ThreatDescription, RuleFormat, Severity, DetectionRule


class MockLLM:
    """Mock LLM for testing."""
    
    def __init__(self, response: str):
        self.response = response
        self.generate = AsyncMock(return_value=(response, {"model": "test"}))
    
    def get_model_name(self) -> str:
        return "test/mock"


class TestKqlGenerator:
    """Test KQL rule generation."""
    
    def test_generate_basic(self):
        """Test basic KQL generation."""
        response = '''// Title: Detect PowerShell Download Commands
// Description: Detects PowerShell commands that download files from the internet
// Author: Artemis
// Date: 2026-02-16
// Severity: Medium
// MITRE: T1059.001, T1105
// Tags: powershell, download, execution
// False Positives: Legitimate admin scripts
// References: https://attack.mitre.org/techniques/T1059/001/

DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl", "DownloadString", "DownloadFile", "WebClient")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
'''
        llm = MockLLM(response)
        generator = KqlGenerator(llm)
        
        threat = ThreatDescription(
            description="Detect PowerShell downloading files from the internet",
            target_format=RuleFormat.KQL,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert rule.name == "Detect PowerShell Download Commands"
        assert rule.format == RuleFormat.KQL
        assert "DeviceProcessEvents" in rule.content
        assert "Invoke-WebRequest" in rule.content
    
    def test_generate_with_context(self):
        """Test KQL generation with additional context."""
        response = '''// Title: Azure AD Suspicious Sign-In
// Description: Detects suspicious Azure AD sign-in patterns
// Author: Artemis
// Severity: High
// MITRE: T1078

SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| where RiskLevelDuringSignIn in ("high", "medium")
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts > 10
'''
        llm = MockLLM(response)
        generator = KqlGenerator(llm)
        
        threat = ThreatDescription(
            description="Detect brute force attacks on Azure AD",
            context="Azure AD environment with SigninLogs enabled",
            target_format=RuleFormat.KQL,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert rule.name == "Azure AD Suspicious Sign-In"
        assert "SigninLogs" in rule.content
        assert "FailedAttempts" in rule.content
    
    def test_mitre_extraction(self):
        """Test MITRE ATT&CK extraction from comments."""
        response = '''// Title: Test Rule
// MITRE: T1059.001, T1105, T1027

DeviceProcessEvents
| where FileName == "test.exe"
'''
        llm = MockLLM(response)
        generator = KqlGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.KQL,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert len(rule.mitre) == 3
        technique_ids = [m.technique_id for m in rule.mitre]
        assert "T1059" in technique_ids
        assert "T1105" in technique_ids
        assert "T1027" in technique_ids
    
    def test_severity_from_comment(self):
        """Test severity extraction from comment."""
        response = '''// Title: Critical Alert
// Severity: Critical

SecurityEvent
| where EventID == 4625
'''
        llm = MockLLM(response)
        generator = KqlGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.KQL,
        )
        
        rule = generator.parse_response(response, threat)
        assert rule.severity == Severity.CRITICAL
    
    def test_tag_extraction(self):
        """Test tag extraction from comment."""
        response = '''// Title: Test
// Tags: powershell, execution, download, malware

DeviceProcessEvents
| where FileName == "powershell.exe"
'''
        llm = MockLLM(response)
        generator = KqlGenerator(llm)
        
        threat = ThreatDescription(
            description="Test",
            target_format=RuleFormat.KQL,
        )
        
        rule = generator.parse_response(response, threat)
        
        assert "powershell" in rule.tags
        assert "execution" in rule.tags
        assert "malware" in rule.tags


class TestKqlValidation:
    """Test KQL rule validation."""
    
    def test_validation_pass(self):
        """Test valid KQL passes validation."""
        generator = KqlGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test Rule",
            description="Test",
            format=RuleFormat.KQL,
            content='''DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert is_valid
        assert len(errors) == 0
    
    def test_validate_empty_query(self):
        """Test empty query fails validation."""
        generator = KqlGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.KQL,
            content="",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert "Empty KQL query" in errors
    
    def test_validate_unbalanced_parens(self):
        """Test unbalanced parentheses detection."""
        generator = KqlGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.KQL,
            content='''DeviceProcessEvents
| where (FileName == "test.exe"
| project TimeGenerated''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert "Unbalanced parentheses" in errors
    
    def test_validate_with_let_statement(self):
        """Test query with let statement passes validation."""
        generator = KqlGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.KQL,
            content='''let timeframe = 1h;
let threshold = 10;
DeviceProcessEvents
| where TimeGenerated > ago(timeframe)
| summarize count() by DeviceName
| where count_ > threshold''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert is_valid
        assert len(errors) == 0
    
    def test_validate_no_table(self):
        """Test query without table fails validation."""
        generator = KqlGenerator(llm=None)
        
        rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.KQL,
            content='''| where FileName == "test.exe"
| project TimeGenerated''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(rule)
        assert not is_valid
        assert any("table" in e.lower() or "let" in e.lower() for e in errors)


class TestKqlExtraction:
    """Test KQL content extraction."""
    
    def test_extract_from_code_block(self):
        """Test extraction from markdown code block."""
        generator = KqlGenerator(llm=None)
        
        text = '''Here's the KQL query:

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName
```

This query detects PowerShell execution.'''
        
        result = generator._extract_kql_block(text)
        assert result is not None
        assert "DeviceProcessEvents" in result
        assert "project TimeGenerated" in result
        assert "Here's the KQL query" not in result
    
    def test_extract_from_comments(self):
        """Test extraction starting from comment headers."""
        generator = KqlGenerator(llm=None)
        
        text = '''// Title: Test Rule
// Description: A test rule

DeviceProcessEvents
| where FileName == "test.exe"
| project TimeGenerated'''
        
        result = generator._extract_kql_block(text)
        assert result is not None
        assert "// Title: Test Rule" in result
        assert "DeviceProcessEvents" in result
    
    def test_extract_comment_field(self):
        """Test comment field extraction."""
        generator = KqlGenerator(llm=None)
        
        content = '''// Title: My Detection Rule
// Description: Detects bad stuff
// Severity: High
// MITRE: T1059, T1105

DeviceProcessEvents
| where FileName == "evil.exe"'''
        
        assert generator._extract_comment_field(content, 'Title') == "My Detection Rule"
        assert generator._extract_comment_field(content, 'Description') == "Detects bad stuff"
        assert generator._extract_comment_field(content, 'Severity') == "High"
        assert generator._extract_comment_field(content, 'MITRE') == "T1059, T1105"
    
    def test_parse_mitre_string(self):
        """Test MITRE string parsing."""
        generator = KqlGenerator(llm=None)
        
        mitre_str = "T1059.001, T1105, T1027.005"
        mappings = generator._parse_mitre_string(mitre_str)
        
        assert len(mappings) == 3
        
        # Check sub-technique handling
        subtechs = [m for m in mappings if m.subtechnique_id]
        assert len(subtechs) == 2
        assert any(m.subtechnique_id == "T1059.001" for m in subtechs)
        assert any(m.subtechnique_id == "T1027.005" for m in subtechs)
