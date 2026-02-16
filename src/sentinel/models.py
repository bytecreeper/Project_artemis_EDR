"""Data models for Sentinel."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RuleFormat(str, Enum):
    """Supported detection rule formats."""
    SIGMA = "sigma"
    YARA = "yara"
    SPLUNK = "splunk"
    KQL = "kql"
    SNORT = "snort"
    SURICATA = "suricata"


class Severity(str, Enum):
    """Detection rule severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping."""
    tactic: str = Field(..., description="ATT&CK tactic (e.g., 'execution')")
    technique_id: str = Field(..., description="Technique ID (e.g., 'T1059')")
    technique_name: str = Field(..., description="Technique name")
    subtechnique_id: Optional[str] = Field(None, description="Sub-technique ID")
    subtechnique_name: Optional[str] = Field(None, description="Sub-technique name")


class ThreatDescription(BaseModel):
    """Input threat description for rule generation."""
    description: str = Field(..., description="Natural language threat description")
    context: Optional[str] = Field(None, description="Additional context (log source, environment)")
    indicators: Optional[list[str]] = Field(None, description="Known IOCs or patterns")
    severity_hint: Optional[Severity] = Field(None, description="Suggested severity level")
    target_format: RuleFormat = Field(RuleFormat.SIGMA, description="Target rule format")


class DetectionRule(BaseModel):
    """Generated detection rule."""
    id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    format: RuleFormat = Field(..., description="Rule format")
    content: str = Field(..., description="Raw rule content")
    severity: Severity = Field(..., description="Rule severity")
    mitre: list[MitreMapping] = Field(default_factory=list, description="MITRE ATT&CK mappings")
    tags: list[str] = Field(default_factory=list, description="Rule tags")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    false_positives: list[str] = Field(default_factory=list, description="Known false positive scenarios")
    
    # Metadata
    author: str = Field(default="Sentinel", description="Rule author")
    date_created: Optional[str] = Field(None, description="Creation date")
    
    # Validation
    is_valid: bool = Field(default=False, description="Whether rule passed validation")
    validation_errors: list[str] = Field(default_factory=list, description="Validation errors if any")


class GenerationResult(BaseModel):
    """Result of rule generation."""
    success: bool
    rule: Optional[DetectionRule] = None
    error: Optional[str] = None
    model_used: Optional[str] = None
    tokens_used: Optional[int] = None
    generation_time_ms: Optional[int] = None
