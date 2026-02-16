"""Tests for Sigma generator."""

import pytest
import yaml

from artemis.models import ThreatDescription, RuleFormat, Severity
from artemis.generators.sigma import SigmaGenerator


class MockLLM:
    """Mock LLM for testing without API calls."""
    
    def __init__(self, response: str):
        self.response = response
        self.calls = []
    
    async def generate(self, prompt: str, system: str = None) -> tuple[str, dict]:
        self.calls.append({"prompt": prompt, "system": system})
        return self.response, {"input_tokens": 100, "output_tokens": 200}
    
    def get_model_name(self) -> str:
        return "mock/test-model"


SAMPLE_SIGMA_RESPONSE = """```yaml
title: PowerShell Web Download Activity
id: a1b2c3d4-5678-90ab-cdef-123456789012
status: experimental
level: high
description: Detects PowerShell commands attempting to download content from the internet using Invoke-WebRequest, curl, or wget aliases
author: Sentinel
date: 2026/02/16
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1105/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_powershell:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_commands:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'IWR '
            - 'curl '
            - 'wget '
            - 'DownloadString'
            - 'DownloadFile'
            - 'WebClient'
    condition: selection_powershell and selection_commands
falsepositives:
    - Legitimate administrative scripts
    - Software installation scripts
    - System update mechanisms
```"""


@pytest.fixture
def mock_llm():
    return MockLLM(SAMPLE_SIGMA_RESPONSE)


@pytest.fixture
def generator(mock_llm):
    return SigmaGenerator(mock_llm)


class TestSigmaGenerator:
    """Test suite for SigmaGenerator."""
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, generator):
        """Test basic rule generation."""
        threat = ThreatDescription(
            description="Detect PowerShell downloading files",
            target_format=RuleFormat.SIGMA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule is not None
        assert result.rule.format == RuleFormat.SIGMA
        assert "PowerShell" in result.rule.name
    
    @pytest.mark.asyncio
    async def test_generate_with_context(self, generator):
        """Test generation with additional context."""
        threat = ThreatDescription(
            description="Detect PowerShell downloading files",
            context="Windows endpoint with Sysmon installed",
            indicators=["Invoke-WebRequest", "DownloadString"],
            severity_hint=Severity.HIGH,
            target_format=RuleFormat.SIGMA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule.severity == Severity.HIGH
    
    @pytest.mark.asyncio
    async def test_mitre_extraction(self, generator):
        """Test MITRE ATT&CK mapping extraction."""
        threat = ThreatDescription(
            description="Detect PowerShell downloading files",
            target_format=RuleFormat.SIGMA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert len(result.rule.mitre) > 0
        
        technique_ids = [m.technique_id for m in result.rule.mitre]
        assert any("T1059" in tid for tid in technique_ids)
    
    @pytest.mark.asyncio
    async def test_validation_pass(self, generator):
        """Test that valid rules pass validation."""
        threat = ThreatDescription(
            description="Detect PowerShell downloading files",
            target_format=RuleFormat.SIGMA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule.is_valid
        assert len(result.rule.validation_errors) == 0
    
    def test_validate_missing_fields(self, generator):
        """Test validation catches missing required fields."""
        from artemis.models import DetectionRule
        
        # Rule missing logsource
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SIGMA,
            content="title: Test\ndetection:\n  selection:\n    test: value\n  condition: selection",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("logsource" in e for e in errors)
    
    def test_validate_invalid_yaml(self, generator):
        """Test validation catches invalid YAML."""
        from artemis.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SIGMA,
            content="title: Test\n  bad indent: here\n    wrong: yaml",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("YAML" in e or "yaml" in e for e in errors)
    
    def test_validate_missing_condition(self, generator):
        """Test validation catches missing condition."""
        from artemis.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SIGMA,
            content="""title: Test
logsource:
  category: process_creation
detection:
  selection:
    Image: test.exe
""",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("condition" in e for e in errors)
    
    def test_severity_inference(self, generator):
        """Test automatic severity inference."""
        # Critical keywords
        threat = ThreatDescription(
            description="Detect ransomware encryption activity",
            target_format=RuleFormat.SIGMA,
        )
        assert generator.infer_severity(threat) == Severity.CRITICAL
        
        # High keywords
        threat = ThreatDescription(
            description="Detect credential dumping with mimikatz",
            target_format=RuleFormat.SIGMA,
        )
        assert generator.infer_severity(threat) == Severity.HIGH
        
        # Medium keywords
        threat = ThreatDescription(
            description="Detect suspicious network scanning",
            target_format=RuleFormat.SIGMA,
        )
        assert generator.infer_severity(threat) == Severity.MEDIUM
        
        # Low (default)
        threat = ThreatDescription(
            description="Detect user login events",
            target_format=RuleFormat.SIGMA,
        )
        assert generator.infer_severity(threat) == Severity.LOW


class TestYAMLExtraction:
    """Test YAML extraction from various response formats."""
    
    @pytest.fixture
    def generator(self):
        return SigmaGenerator(MockLLM(""))
    
    def test_extract_code_block(self, generator):
        """Test extraction from markdown code block."""
        response = """Here's the rule:

```yaml
title: Test Rule
logsource:
  category: test
```

Hope this helps!"""
        
        yaml_content = generator.extract_yaml_block(response)
        data = yaml.safe_load(yaml_content)
        
        assert data["title"] == "Test Rule"
    
    def test_extract_raw_yaml(self, generator):
        """Test extraction from raw YAML without code blocks."""
        response = """title: Test Rule
logsource:
  category: test
detection:
  selection:
    test: value
  condition: selection"""
        
        yaml_content = generator.extract_yaml_block(response)
        data = yaml.safe_load(yaml_content)
        
        assert data["title"] == "Test Rule"
