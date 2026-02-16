"""
Sentinel - AI-powered detection engineering platform.

Generate detection rules from natural language threat descriptions.
Supports Sigma, YARA, Splunk SPL, KQL, and Snort/Suricata formats.
"""

__version__ = "0.1.0"
__author__ = "ByteCreeper"

from sentinel.core import Sentinel
from sentinel.models import ThreatDescription, DetectionRule, RuleFormat

__all__ = ["Sentinel", "ThreatDescription", "DetectionRule", "RuleFormat"]
