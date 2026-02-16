"""Tests for Splunk SPL generator."""

import pytest

from artemis.models import ThreatDescription, RuleFormat, Severity
from artemis.generators.splunk import SplunkGenerator


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


SAMPLE_SPLUNK_RESPONSE = '''```spl
`comment("Title: PowerShell Encoded Command Execution")`
`comment("Description: Detects PowerShell execution with encoded commands, commonly used for obfuscation")`
`comment("Author: Sentinel")`
`comment("MITRE: T1059.001, T1027")`
`comment("Severity: high")`

index=windows sourcetype=WinEventLog:Security EventCode=4688
| search CommandLine="*powershell*" AND (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")
| eval decoded_cmd=if(match(CommandLine, "-enc"), "Encoded command detected", "N/A")
| stats count by _time, Computer, User, CommandLine, ParentCommandLine
| where count > 0
| table _time, Computer, User, CommandLine, ParentCommandLine, decoded_cmd
```'''


@pytest.fixture
def mock_llm():
    return MockLLM(SAMPLE_SPLUNK_RESPONSE)


@pytest.fixture
def generator(mock_llm):
    return SplunkGenerator(mock_llm)


class TestSplunkGenerator:
    """Test suite for SplunkGenerator."""
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, generator):
        """Test basic Splunk query generation."""
        threat = ThreatDescription(
            description="Detect PowerShell encoded command execution",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule is not None
        assert result.rule.format == RuleFormat.SPLUNK
        assert "PowerShell" in result.rule.name
    
    @pytest.mark.asyncio
    async def test_generate_with_context(self, generator):
        """Test generation with environment context."""
        threat = ThreatDescription(
            description="Detect lateral movement",
            context="Windows environment with Sysmon logs in Splunk",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert any("Windows" in call["prompt"] or "Sysmon" in call["prompt"] 
                   for call in generator.llm.calls)
    
    @pytest.mark.asyncio
    async def test_mitre_extraction(self, generator):
        """Test MITRE ATT&CK mapping extraction."""
        threat = ThreatDescription(
            description="Detect encoded PowerShell",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert len(result.rule.mitre) > 0
        
        technique_ids = [m.technique_id for m in result.rule.mitre]
        assert "T1059" in technique_ids
    
    @pytest.mark.asyncio
    async def test_severity_from_comment(self, generator):
        """Test severity extraction from comments."""
        threat = ThreatDescription(
            description="Detect encoded PowerShell",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule.severity == Severity.HIGH
    
    @pytest.mark.asyncio
    async def test_tag_extraction(self, generator):
        """Test automatic tag extraction from query."""
        threat = ThreatDescription(
            description="Detect PowerShell",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert "windows" in result.rule.tags
        assert "process" in result.rule.tags or "authentication" in result.rule.tags
    
    @pytest.mark.asyncio
    async def test_validation_pass(self, generator):
        """Test that valid queries pass validation."""
        threat = ThreatDescription(
            description="Detect PowerShell",
            target_format=RuleFormat.SPLUNK,
        )
        
        result = await generator.generate(threat)
        
        assert result.success
        assert result.rule.is_valid
        assert len(result.rule.validation_errors) == 0
    
    def test_validate_empty_query(self, generator):
        """Test validation catches empty queries."""
        from artemis.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SPLUNK,
            content='`comment("Title: Test")`',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("empty" in e.lower() for e in errors)
    
    def test_validate_unbalanced_parens(self, generator):
        """Test validation catches unbalanced parentheses."""
        from artemis.models import DetectionRule
        
        bad_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SPLUNK,
            content='index=test | where (foo="bar"',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(bad_rule)
        
        assert not is_valid
        assert any("parenthes" in e.lower() for e in errors)
    
    def test_validate_valid_query(self, generator):
        """Test validation passes for valid query."""
        from artemis.models import DetectionRule
        
        good_rule = DetectionRule(
            id="test",
            name="Test",
            description="Test",
            format=RuleFormat.SPLUNK,
            content='''index=windows sourcetype=WinEventLog:Security EventCode=4688
| search CommandLine="*powershell*"
| stats count by Computer, User, CommandLine
| where count > 5
| table _time, Computer, User, CommandLine, count''',
            severity=Severity.MEDIUM,
        )
        
        is_valid, errors = generator.validate_rule(good_rule)
        
        assert is_valid
        assert len(errors) == 0


class TestSplunkExtraction:
    """Test SPL content extraction."""
    
    @pytest.fixture
    def generator(self):
        return SplunkGenerator(MockLLM(""))
    
    def test_extract_from_code_block(self, generator):
        """Test extraction from markdown code block."""
        response = '''Here's your query:

```spl
index=test sourcetype=test
| stats count
```

Let me know if you need changes.'''
        
        content = generator._extract_spl_block(response)
        
        assert "index=test" in content
        assert "stats count" in content
    
    def test_extract_comment_field(self, generator):
        """Test metadata field extraction."""
        content = '''`comment("Title: Test Query")`
`comment("MITRE: T1059.001")`
`comment("Severity: high")`
index=test'''
        
        title = generator._extract_comment_field(content, "Title")
        mitre = generator._extract_comment_field(content, "MITRE")
        severity = generator._extract_comment_field(content, "Severity")
        
        assert title == "Test Query"
        assert mitre == "T1059.001"
        assert severity == "high"
    
    def test_parse_mitre_string(self, generator):
        """Test MITRE technique parsing."""
        mitre_str = "T1059.001, T1027, T1055"
        
        mappings = generator._parse_mitre_string(mitre_str)
        
        assert len(mappings) == 3
        technique_ids = [m.technique_id for m in mappings]
        assert "T1059" in technique_ids
        assert "T1027" in technique_ids
        assert "T1055" in technique_ids
