"""
Project Artemis - AI-powered detection engineering and security operations platform.

Features:
- Detection rule generation from natural language (Sigma, YARA, Splunk, KQL, Snort)
- Autonomous SOC with network monitoring and threat detection
- Shannon-inspired AI penetration testing
- Professional pentest reporting

Powered by local DeepSeek R1:70b model.
"""

__version__ = "1.1.0"
__author__ = "ByteCreeper"

from artemis.core import Artemis
from artemis.models import ThreatDescription, DetectionRule, RuleFormat

__all__ = [
    "Artemis",
    "ThreatDescription", 
    "DetectionRule",
    "RuleFormat",
]
