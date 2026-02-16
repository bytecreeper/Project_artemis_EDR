"""Tests for YARA generator."""

import pytest

from sentinel.models import ThreatDescription, RuleFormat, Severity
from sentinel.generators.yara import YaraGenerator


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


SAMPLE_YARA_RESPONSE = '''```yara
rule Cobalt_Strike_Beacon : malware trojan {
    meta:
        author = "Sentinel"
        description = "Detects Cobalt Strike beacon payload in memory or files"
        date = "2026/02/16"
        reference = "https://attack.mitre.org/software/S0154/"
        mitre_attack = "T1071.001, T1059.003"
        
    strings:
        $s1 = "%s (admin)" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "ReflectiveLoader" ascii
        $h1 = { 4D 5A 90 00 03 00 00 00 }  // MZ header
        $h2 = { 48 8B C4 48 89 58 08 48 89 68 10 }  // Common shellcode
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($s*) or $config or all of ($h*))
}
```'''


@pytest.fixture
def mock_llm():
    return MockLLM(SAMPLE_YARA_RESPONSE)


@pytest.fixture
def generator(mock_llm):
    return YaraGenerator(mock_llm)


class TestYaraGenerator:
    """Test suite for YaraGenerator."""
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, generator):
        """Test basic YARA rule generation."""
        threat = ThreatDescription(
            description="Detect Cobalt Strike beacon",
            target_format=RuleFormat.YARA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule is not None
        assert result.rule.format == RuleFormat.YARA
        assert "Cobalt" in result.rule.name
    
    @pytest.mark.asyncio
    async def test_generate_with_indicators(self, generator):
        """Test generation with IOC indicators."""
        threat = ThreatDescription(
            description="Detect malware sample",
            indicators=[
                "evil.com",
                "4D5A90000300000004000000FFFF0000",
                "suspicious_mutex_name",
            ],
            target_format=RuleFormat.YARA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        # Indicators should be in the prompt
        assert any("evil.com" in call["prompt"] for call in generator.llm.calls)
    
    @pytest.mark.asyncio
    async def test_mitre_extraction(self, generator):
        """Test MITRE ATT&CK mapping extraction."""
        threat = ThreatDescription(
            description="Detect Cobalt Strike",
            target_format=RuleFormat.YARA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert len(result.rule.mitre) > 0
        
        technique_ids = [m.technique_id for m in result.rule.mitre]
        assert "T1071" in technique_ids or any("T1" in tid for tid in technique_ids)
    
    @pytest.mark.asyncio
    async def test_tag_extraction(self, generator):
        """Test tag extraction from rule."""
        threat = ThreatDescription(
            description="Detect malware",
            target_format=RuleFormat.YARA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert "malware" in result.rule.tags
        assert "trojan" in result.rule.tags
    
    @pytest.mark.asyncio
    async def test_validation_pass(self, generator):
        """Test that valid YARA rules pass validation."""
        threat = ThreatDescription(
            description="Detect malware",
            target_format=RuleFormat.YARA,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule.is_valid
        assert len(result.rule.validation_errors) == 0
    
    def test_validate_missing_condition(self, generator):
        """Test validation catches missing condition."""
        from sentinel.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.YARA,
            content="""rule Test {
    strings:
        $s1 = "test"
}""",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("condition" in e.lower() for e in errors)
    
    def test_validate_mismatched_braces(self, generator):
        """Test validation catches mismatched braces."""
        from sentinel.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.YARA,
            content="""rule Test {
    strings:
        $s1 = "test"
    condition:
        $s1
""",  # Missing closing brace
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("brace" in e.lower() for e in errors)
    
    def test_validate_valid_rule(self, generator):
        """Test validation passes for valid rule."""
        from sentinel.models import DetectionRule
        
        good_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.YARA,
            content="""rule Test_Malware : malware {
    meta:
        author = "Test"
        description = "Test rule"
        
    strings:
        $s1 = "malicious" ascii wide
        $s2 = "payload" ascii
        $hex = { 4D 5A 90 00 }
        
    condition:
        uint16(0) == 0x5A4D and
        any of ($s*) or $hex
}""",
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(good_rule)
        
        assert is_valid
        assert len(errors) == 0


class TestYaraExtraction:
    """Test YARA content extraction."""
    
    @pytest.fixture
    def generator(self):
        return YaraGenerator(MockLLM(""))
    
    def test_extract_from_code_block(self, generator):
        """Test extraction from markdown code block."""
        response = '''Here's the rule:

```yara
rule Test {
    condition:
        true
}
```

Let me know if you need changes.'''
        
        content = generator._extract_yara_block(response)
        
        assert "rule Test" in content
        assert "condition:" in content
    
    def test_extract_raw_rule(self, generator):
        """Test extraction from raw response."""
        response = """rule Test {
    strings:
        $a = "test"
    condition:
        $a
}"""
        
        content = generator._extract_yara_block(response)
        
        assert "rule Test" in content
    
    def test_generate_rule_name(self, generator):
        """Test rule name generation from description."""
        name = generator._generate_rule_name("Detect Cobalt Strike beacon payloads")
        
        assert "Cobalt" in name
        assert "Strike" in name
        assert "_" in name  # Words joined with underscore
        assert name.replace("_", "").isalnum()  # Valid identifier
