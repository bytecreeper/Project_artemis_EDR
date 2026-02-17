# Shannon Integration Plan
## Project Artemis + Shannon: Active Defense System

**Created:** 2026-02-17  
**Status:** Planning  
**Goal:** Integrate Shannon autonomous pentesting into Artemis for defense + counter-attack capabilities

---

## 1. Vision

Transform Artemis from passive monitoring into an **active defense platform**:

```
CURRENT STATE                      FUTURE STATE
─────────────────                  ─────────────────
Monitor → Detect → Alert    →     Monitor → Detect → Analyze → Respond → Counter
         (passive)                          (active defense)
```

### Core Capabilities

| Capability | Description | Priority |
|------------|-------------|----------|
| **Internal Audit** | Scheduled pentests on own infrastructure | P1 |
| **Service Discovery Scan** | Auto-scan new services detected on network | P2 |
| **Threat Investigation** | Deep-dive on suspicious IPs/activity | P2 |
| **Counter-Attack** | Pentest attacker's infrastructure (with safeguards) | P3 |
| **Honeypot Integration** | Trace/fingerprint anyone touching honeypots | P3 |

---

## 2. Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ARTEMIS DASHBOARD                                │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐              │
│  │ Network  │ Devices  │ Threats  │ Traffic  │ Red Team │              │
│  │ Monitor  │          │          │          │ (NEW)    │              │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘              │
└─────────────────────────────┬───────────────────────────────────────────┘
                              │ REST API
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ARTEMIS BACKEND                                  │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  Monitor    │  │  Threat     │  │  Intel      │  │  Red Team   │    │
│  │  Engine     │  │  Detector   │  │  Engine     │  │  Controller │    │
│  │  (monitor.py)│ │             │  │  (NEW)      │  │  (NEW)      │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────┬──────┘    │
│                                                             │           │
└─────────────────────────────────────────────────────────────┼───────────┘
                                                              │
                              ┌────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         SHANNON ENGINE                                   │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Temporal Orchestration (Docker)                                 │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │Pre-Recon│→│  Recon  │→│  Vuln   │→│ Exploit │→│ Report  │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Modes: internal_audit | service_scan | threat_intel | counter_attack   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Integration Points

1. **Artemis → Shannon** (Job Launch)
   - Target URL/IP
   - Scan mode (audit/recon/full)
   - Scope constraints
   - Credential configs (for internal)

2. **Shannon → Artemis** (Results)
   - Vulnerability findings
   - Exploit confirmations  
   - Attack surface reports
   - Threat intelligence

3. **Shared Data**
   - Device/service inventory
   - Network topology
   - Historical scan results
   - Threat actor profiles

---

## 3. Implementation Phases

### Phase 0: Foundation (Week 1)
**Goal:** Get Shannon running standalone, understand the codebase

- [ ] Test Shannon on a local vulnerable app (Juice Shop)
- [ ] Document Shannon's input/output formats
- [ ] Identify required dependencies (Docker, Temporal, API keys)
- [ ] Create `artemis.redteam` module structure

**Deliverables:**
- Working Shannon installation
- Shannon API documentation
- Module skeleton

---

### Phase 1: Basic Integration (Week 2-3)
**Goal:** Launch Shannon jobs from Artemis, view results

#### Backend
- [ ] `artemis/web/redteam.py` - Red team controller
- [ ] `/api/redteam/jobs` - List all pentest jobs
- [ ] `/api/redteam/launch` - Start new job
- [ ] `/api/redteam/status/{id}` - Job status
- [ ] `/api/redteam/report/{id}` - Get report
- [ ] `/api/redteam/cancel/{id}` - Cancel job

#### Frontend
- [ ] "Red Team" tab in dashboard
- [ ] Job launch form (target, mode, scope)
- [ ] Job status list with progress
- [ ] Report viewer (markdown → HTML)

#### Data Model
```python
@dataclass
class PentestJob:
    id: str
    target: str
    mode: str  # audit, recon, vuln, full
    status: str  # pending, running, completed, failed
    started_at: datetime
    completed_at: Optional[datetime]
    findings_count: int
    critical_count: int
    report_path: Optional[str]
    config: dict
```

**Deliverables:**
- Manual job launch working
- Results visible in dashboard
- Basic job management

---

### Phase 2: Automated Triggers (Week 4-5)
**Goal:** Artemis automatically triggers scans based on events

#### Trigger Types
```python
class ScanTrigger(Enum):
    NEW_SERVICE = "new_service"      # New port/service detected
    NEW_DEVICE = "new_device"        # Unknown device on network
    THREAT_DETECTED = "threat"       # Suspicious activity
    SCHEDULED = "scheduled"          # Cron-based audit
    HONEYPOT = "honeypot"           # Honeypot interaction
    MANUAL = "manual"               # User-initiated
```

#### Implementation
- [ ] Event hooks in monitor.py for triggers
- [ ] Trigger configuration UI
- [ ] Rate limiting (don't spam scans)
- [ ] Scope validation (don't scan the internet)

#### Safety Rails
```python
SCAN_CONSTRAINTS = {
    "internal_only": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    "max_concurrent_jobs": 2,
    "cooldown_minutes": 30,  # Per-target cooldown
    "require_approval": ["counter_attack"],  # Modes needing human approval
}
```

**Deliverables:**
- Auto-scan on new service detection
- Scheduled internal audits
- Rate limiting & safety checks

---

### Phase 3: Counter-Attack Mode (Week 6-7)
**Goal:** Safely investigate/scan threat actors

#### Workflow
```
Threat Detected → Human Review → Approval → Counter-Scan → Intel Report
                      │
                      └── (Optional) Auto-approve for known bad IPs
```

#### Features
- [ ] Threat actor profile builder
- [ ] External IP scanning (with legal warnings)
- [ ] OSINT integration (Shodan, VirusTotal)
- [ ] Attribution correlation
- [ ] Evidence preservation

#### Legal/Ethical Safeguards
- [ ] Confirmation dialogs with legal disclaimer
- [ ] Audit log of all counter-attack actions
- [ ] Scope lock (only scan the specific threat IP)
- [ ] No exploitation in counter-attack (recon only by default)

**Deliverables:**
- Counter-scan workflow
- Threat actor profiles
- Audit trail

---

### Phase 4: Intelligence & Reporting (Week 8)
**Goal:** Unified security intelligence

- [ ] Consolidated threat database
- [ ] Trend analysis (attack patterns over time)
- [ ] Executive reports (scheduled)
- [ ] Alert integration (Slack, email, webhook)
- [ ] Export formats (PDF, JSON, STIX)

**Deliverables:**
- Unified intel dashboard
- Automated reporting
- Integration webhooks

---

## 4. Technical Decisions

### Q1: How to run Shannon?

**Option A: Docker (Recommended)**
- Shannon runs in Docker with Temporal
- Artemis calls via REST/gRPC
- Isolation, reproducibility
- Requires Docker daemon

**Option B: Native Process**
- Run Shannon TypeScript directly
- Simpler setup, harder to isolate
- Resource contention risk

**Decision:** Docker - matches Shannon's design, provides isolation

---

### Q2: Job queue & state management?

**Option A: Use Shannon's Temporal**
- Leverage existing orchestration
- Query Temporal for job status
- Learning curve for Temporal API

**Option B: Artemis-side queue (Redis/SQLite)**
- Artemis manages jobs, calls Shannon
- More control, more code
- Duplication of orchestration

**Decision:** TBD - need to evaluate Temporal API complexity

---

### Q3: Where to store results?

**Option A: Shannon's audit-logs/**
- Keep Shannon's output format
- Artemis reads from filesystem
- Simple, but tight coupling

**Option B: Artemis database**
- Import results into Artemis DB
- Unified querying
- More integration work

**Decision:** Hybrid - Shannon writes to audit-logs, Artemis indexes key findings

---

### Q4: Counter-attack legal considerations?

**Recon-only by default:**
- Port scanning: Generally legal (check jurisdiction)
- Service fingerprinting: Generally legal
- Exploitation: **NEVER without explicit authorization**

**Safeguards:**
- Counter-attack = recon only (no exploitation)
- Full exploitation requires written authorization upload
- All actions logged with timestamps
- "I understand" checkbox before any external scan

---

## 5. Dependencies & Prerequisites

### Required
- [ ] Docker Desktop installed and running
- [ ] Anthropic API key (for Shannon's Claude)
- [ ] ~4GB RAM for Temporal + workers
- [ ] Npcap installed (for packet capture)

### Optional
- [ ] Shodan API key (OSINT)
- [ ] VirusTotal API key (threat intel)
- [ ] Slack webhook (alerts)

### Network Requirements
- Ports 7233, 8233 for Temporal
- Port 8890 for Artemis
- Outbound HTTPS for API calls

---

## 6. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Accidental external scan | Medium | High | Strict scope validation, confirmation dialogs |
| API cost overrun | Medium | Medium | Token limits, job quotas, cost tracking |
| Legal issues from counter-attack | Low | Critical | Recon-only default, legal disclaimers, audit logs |
| Performance impact | Medium | Medium | Docker isolation, resource limits |
| Shannon breaking changes | Low | Medium | Pin versions, integration tests |

---

## 7. Success Metrics

### Phase 1
- [ ] Can launch a Shannon job from Artemis UI
- [ ] Can view completed report in dashboard
- [ ] Job lifecycle (start → complete → report) works

### Phase 2
- [ ] New service triggers auto-scan within 5 minutes
- [ ] Scheduled weekly audit runs successfully
- [ ] No false-positive scan triggers in 1 week

### Phase 3
- [ ] Counter-scan workflow completes with audit trail
- [ ] Threat actor profile generated from scan
- [ ] All safety checks enforced

### Phase 4
- [ ] Executive report generated weekly
- [ ] Alerts delivered to configured channels
- [ ] <5 minute from threat detection to investigation start

---

## 8. Decisions Made (2026-02-17)

1. **Model:** Anthropic API for now. DeepSeek local is Phase 5 enhancement.
2. **Docker + Temporal:** Approved ✓
3. **Counter-Attack:** Recon-only default. Full pentest requires explicit approval.
4. **Autonomy Level:** "Antivirus on steroids" - autonomous operation, only ask permission for destructive actions.
5. **Guardrails:** Minimal - this is a personal home tool. Permission prompt for destructive ops only.
6. **Scope:** Deep scans, targeted traffic scans, autonomous threat response.

## 8b. Future Enhancements (Phase 5+)

- [ ] DeepSeek/Ollama local model support
- [ ] Custom model routing for cost optimization
- [ ] Offline operation mode

---

## 9. Next Steps

1. **Review this plan** - Adjust scope/timeline as needed
2. **Phase 0 kickoff** - Get Shannon running standalone
3. **Weekly check-ins** - Adjust based on learnings

---

*This is a living document. Update as decisions are made.*
