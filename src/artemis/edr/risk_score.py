"""Risk scoring and security posture calculation for Project Artemis.

Calculates an overall security posture score (0-100) based on:
- Active threats and their severity
- Endpoint health
- Detection coverage
- Response readiness
- Historical trend
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("artemis.edr.risk_score")


@dataclass
class RiskFactors:
    """Individual risk factor scores."""
    # Threat-based (lower is better, inverted for final score)
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    
    # Coverage-based (higher is better)
    endpoints_monitored: int = 0
    endpoints_total: int = 0
    sysmon_enabled: bool = False
    process_monitor_running: bool = False
    threat_intel_loaded: bool = False
    
    # Response readiness
    auto_response_enabled: bool = False
    last_threat_intel_update: Optional[datetime] = None
    
    # Calculated
    threat_score: float = 0.0  # 0-100, lower is worse
    coverage_score: float = 0.0  # 0-100
    readiness_score: float = 0.0  # 0-100


@dataclass
class SecurityPosture:
    """Overall security posture assessment."""
    score: int  # 0-100
    grade: str  # A, B, C, D, F
    trend: str  # improving, stable, declining
    factors: RiskFactors
    recommendations: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "trend": self.trend,
            "timestamp": self.timestamp.isoformat(),
            "factors": {
                "threat_score": self.factors.threat_score,
                "coverage_score": self.factors.coverage_score,
                "readiness_score": self.factors.readiness_score,
                "critical_alerts": self.factors.critical_alerts,
                "high_alerts": self.factors.high_alerts,
                "medium_alerts": self.factors.medium_alerts,
                "low_alerts": self.factors.low_alerts,
                "endpoints_monitored": self.factors.endpoints_monitored,
                "endpoints_total": self.factors.endpoints_total,
                "sysmon_enabled": self.factors.sysmon_enabled,
                "process_monitor_running": self.factors.process_monitor_running,
                "threat_intel_loaded": self.factors.threat_intel_loaded,
            },
            "recommendations": self.recommendations,
        }


class RiskScorer:
    """Calculate security risk score and posture."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("data/risk")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.data_dir / "score_history.jsonl"
    
    def calculate_posture(
        self,
        alerts: list[dict],
        devices: list[dict],
        edr_status: dict,
        connections: Optional[list[dict]] = None,
    ) -> SecurityPosture:
        """Calculate current security posture.
        
        Args:
            alerts: List of current alerts
            devices: List of discovered devices
            edr_status: EDR module status dict
            connections: Optional list of network connections
            
        Returns:
            SecurityPosture assessment
        """
        factors = RiskFactors()
        recommendations = []
        
        # Count alerts by severity
        for alert in alerts:
            severity = alert.get("severity", "medium").lower()
            if severity == "critical":
                factors.critical_alerts += 1
            elif severity == "high":
                factors.high_alerts += 1
            elif severity == "medium":
                factors.medium_alerts += 1
            else:
                factors.low_alerts += 1
        
        # Calculate threat score (100 = no threats, 0 = critical situation)
        # Weighted: critical=40, high=20, medium=5, low=1
        threat_penalty = (
            factors.critical_alerts * 40 +
            factors.high_alerts * 20 +
            factors.medium_alerts * 5 +
            factors.low_alerts * 1
        )
        factors.threat_score = max(0, 100 - threat_penalty)
        
        if factors.critical_alerts > 0:
            recommendations.append(f"🚨 {factors.critical_alerts} CRITICAL alerts require immediate attention")
        if factors.high_alerts > 0:
            recommendations.append(f"⚠️ {factors.high_alerts} high-severity alerts need investigation")
        
        # Coverage score
        factors.endpoints_total = len(devices)
        factors.endpoints_monitored = len(devices)  # For now, assume all discovered are monitored
        
        # Check EDR components
        pm = edr_status.get("process_monitor", {})
        sm = edr_status.get("sysmon", {})
        ti = edr_status.get("threat_intel", {})
        
        factors.process_monitor_running = pm.get("running", False)
        factors.sysmon_enabled = sm.get("total_events", 0) > 0
        factors.threat_intel_loaded = ti.get("total_iocs", 0) > 0
        
        # Calculate coverage score
        coverage_points = 0
        coverage_max = 0
        
        # Process monitor: 30 points
        coverage_max += 30
        if factors.process_monitor_running:
            coverage_points += 30
        else:
            recommendations.append("Start process monitor for real-time detection")
        
        # Sysmon: 30 points
        coverage_max += 30
        if factors.sysmon_enabled:
            coverage_points += 30
        else:
            recommendations.append("Install Sysmon for comprehensive endpoint visibility")
        
        # Threat intel: 20 points
        coverage_max += 20
        if factors.threat_intel_loaded:
            coverage_points += 20
            # Check freshness
            last_update = ti.get("last_update")
            if last_update:
                try:
                    update_time = datetime.fromisoformat(last_update)
                    if datetime.now() - update_time > timedelta(days=1):
                        recommendations.append("Update threat intelligence feeds (>24h old)")
                except:
                    pass
        else:
            recommendations.append("Load threat intelligence feeds for IoC detection")
        
        # Endpoint coverage: 20 points
        coverage_max += 20
        if factors.endpoints_total > 0:
            coverage_points += 20
        else:
            recommendations.append("Run network scan to discover endpoints")
        
        factors.coverage_score = (coverage_points / coverage_max * 100) if coverage_max > 0 else 0
        
        # Readiness score (future: response automation, playbooks, etc.)
        factors.readiness_score = 50  # Baseline, can be expanded
        
        # Calculate overall score (weighted average)
        # Threats: 50%, Coverage: 35%, Readiness: 15%
        overall_score = int(
            factors.threat_score * 0.50 +
            factors.coverage_score * 0.35 +
            factors.readiness_score * 0.15
        )
        
        # Determine grade
        if overall_score >= 90:
            grade = "A"
        elif overall_score >= 80:
            grade = "B"
        elif overall_score >= 70:
            grade = "C"
        elif overall_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        # Determine trend
        trend = self._calculate_trend(overall_score)
        
        posture = SecurityPosture(
            score=overall_score,
            grade=grade,
            trend=trend,
            factors=factors,
            recommendations=recommendations[:5],  # Top 5
        )
        
        # Save to history
        self._save_history(posture)
        
        return posture
    
    def _calculate_trend(self, current_score: int) -> str:
        """Calculate score trend based on history."""
        try:
            if not self.history_file.exists():
                return "stable"
            
            # Read last 10 scores
            scores = []
            with open(self.history_file) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        scores.append(entry.get("score", 0))
                    except:
                        continue
            
            if len(scores) < 3:
                return "stable"
            
            # Compare current to average of last 5
            recent_avg = sum(scores[-5:]) / len(scores[-5:])
            
            if current_score > recent_avg + 5:
                return "improving"
            elif current_score < recent_avg - 5:
                return "declining"
            else:
                return "stable"
                
        except Exception as e:
            logger.warning(f"Failed to calculate trend: {e}")
            return "stable"
    
    def _save_history(self, posture: SecurityPosture):
        """Save score to history."""
        try:
            with open(self.history_file, "a") as f:
                entry = {
                    "score": posture.score,
                    "grade": posture.grade,
                    "timestamp": posture.timestamp.isoformat(),
                }
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")
    
    def get_history(self, hours: int = 24) -> list[dict]:
        """Get score history for the specified time period."""
        history = []
        cutoff = datetime.now() - timedelta(hours=hours)
        
        try:
            if self.history_file.exists():
                with open(self.history_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            ts = datetime.fromisoformat(entry["timestamp"])
                            if ts >= cutoff:
                                history.append(entry)
                        except:
                            continue
        except Exception as e:
            logger.warning(f"Failed to read history: {e}")
        
        return history


# MITRE ATT&CK Framework mapping
MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "color": "#e74c3c"},
    "TA0002": {"name": "Execution", "color": "#e67e22"},
    "TA0003": {"name": "Persistence", "color": "#f1c40f"},
    "TA0004": {"name": "Privilege Escalation", "color": "#2ecc71"},
    "TA0005": {"name": "Defense Evasion", "color": "#1abc9c"},
    "TA0006": {"name": "Credential Access", "color": "#3498db"},
    "TA0007": {"name": "Discovery", "color": "#9b59b6"},
    "TA0008": {"name": "Lateral Movement", "color": "#34495e"},
    "TA0009": {"name": "Collection", "color": "#e91e63"},
    "TA0010": {"name": "Exfiltration", "color": "#673ab7"},
    "TA0011": {"name": "Command and Control", "color": "#ff5722"},
    "TA0040": {"name": "Impact", "color": "#795548"},
}

MITRE_TECHNIQUES = {
    # Execution
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1059.001": {"name": "PowerShell", "tactic": "TA0002"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "TA0002"},
    "T1059.005": {"name": "Visual Basic", "tactic": "TA0002"},
    "T1059.007": {"name": "JavaScript", "tactic": "TA0002"},
    
    # Persistence
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "TA0003"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003"},
    
    # Privilege Escalation
    "T1055": {"name": "Process Injection", "tactic": "TA0004"},
    "T1055.001": {"name": "DLL Injection", "tactic": "TA0004"},
    "T1055.012": {"name": "Process Hollowing", "tactic": "TA0004"},
    
    # Defense Evasion
    "T1070": {"name": "Indicator Removal", "tactic": "TA0005"},
    "T1070.004": {"name": "File Deletion", "tactic": "TA0005"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1140": {"name": "Deobfuscate/Decode Files", "tactic": "TA0005"},
    
    # Credential Access
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "TA0006"},
    "T1110": {"name": "Brute Force", "tactic": "TA0006"},
    
    # Discovery
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "TA0007"},
    "T1057": {"name": "Process Discovery", "tactic": "TA0007"},
    "T1018": {"name": "Remote System Discovery", "tactic": "TA0007"},
    
    # Lateral Movement
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "TA0008"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "TA0008"},
    
    # Collection
    "T1005": {"name": "Data from Local System", "tactic": "TA0009"},
    "T1039": {"name": "Data from Network Shared Drive", "tactic": "TA0009"},
    
    # Command and Control
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1071.001": {"name": "Web Protocols", "tactic": "TA0011"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011"},
    "T1571": {"name": "Non-Standard Port", "tactic": "TA0011"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "TA0011"},
    "T1568.002": {"name": "Domain Generation Algorithms", "tactic": "TA0011"},
    
    # Impact
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1489": {"name": "Service Stop", "tactic": "TA0040"},
}


def get_mitre_coverage(detected_techniques: list[str]) -> dict:
    """Get MITRE ATT&CK coverage statistics.
    
    Args:
        detected_techniques: List of technique IDs seen (e.g., ["T1059", "T1003"])
        
    Returns:
        Coverage statistics by tactic
    """
    tactic_hits = {tactic_id: [] for tactic_id in MITRE_TACTICS}
    
    for tech_id in detected_techniques:
        if tech_id in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[tech_id]
            tactic_id = tech["tactic"]
            if tactic_id in tactic_hits:
                tactic_hits[tactic_id].append({
                    "id": tech_id,
                    "name": tech["name"],
                })
    
    coverage = {
        "tactics": [],
        "total_techniques_detected": len(set(detected_techniques)),
        "total_techniques_known": len(MITRE_TECHNIQUES),
    }
    
    for tactic_id, tactic_info in MITRE_TACTICS.items():
        hits = tactic_hits[tactic_id]
        coverage["tactics"].append({
            "id": tactic_id,
            "name": tactic_info["name"],
            "color": tactic_info["color"],
            "techniques_detected": len(hits),
            "techniques": hits,
        })
    
    return coverage
