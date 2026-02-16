"""
Project Artemis - AI-powered detection engineering platform.

Generate detection rules from natural language threat descriptions.
Supports Sigma, YARA, Splunk SPL, KQL, and Snort/Suricata formats.
"""

__version__ = "0.5.0"
__author__ = "ByteCreeper"

from artemis.core import Artemis
from artemis.models import ThreatDescription, DetectionRule, RuleFormat

__all__ = ["Artemis", "ThreatDescription", "DetectionRule", "RuleFormat"]
