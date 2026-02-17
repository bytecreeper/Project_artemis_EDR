# Dashboard Improvement Plan
## Making Artemis Amazing

**Status:** Assessment Complete  
**Date:** 2026-02-17

---

## Current State Assessment

### ✅ Working Well
- Traffic stats (bytes in/out, packets)
- Device discovery (MAC lookup, vendor identification)
- Threat detection (suspicious domain patterns)
- Settings persistence (JSON file)
- WebSocket real-time updates
- Connection monitoring (psutil-based, fast)
- Network scan with subnet filtering

### ⚠️ Needs Improvement
1. **Device Classification** - All types showing as "unknown"
2. **AI Analysis** - DeepSeek/Ollama integration not active
3. **Dashboard UX** - Some rough edges
4. **Real-time Updates** - Could be smoother

### ❌ Missing/Broken
1. Ollama not in PATH (can't reach local DeepSeek)
2. Device type inference from vendor/ports
3. Proactive AI threat analysis
4. Smart alerts (not just pattern matching)

---

## Priority Improvements

### P0: Fix Ollama/DeepSeek Connection
**Goal:** Get local AI working for threat analysis

**Tasks:**
- [ ] Find Ollama installation path
- [ ] Add to PATH or configure URL
- [ ] Test connection from Artemis
- [ ] Verify deepseek-r1 model available

### P1: Smart Device Classification
**Goal:** Automatically identify device types from context

**Current:** Vendor lookup works, but type always "unknown"

**Solution:**
```python
# Infer type from vendor + ports + behavior
def classify_device(vendor: str, open_ports: list, hostname: str) -> str:
    vendor_lower = vendor.lower()
    
    # Router indicators
    if any(x in vendor_lower for x in ['eero', 'netgear', 'asus', 'tp-link', 'cisco', 'ubiquiti']):
        if 80 in open_ports or 443 in open_ports:
            return 'router'
    
    # Smart TV
    if any(x in vendor_lower for x in ['samsung', 'lg', 'sony', 'roku', 'vizio']):
        return 'smart_tv'
    
    # Apple devices
    if 'apple' in vendor_lower:
        if 62078 in open_ports:  # iPhone sync
            return 'phone'
        if 548 in open_ports:  # AFP
            return 'desktop'
        return 'apple_device'
    
    # Google devices
    if 'google' in vendor_lower:
        if 8008 in open_ports or 8443 in open_ports:
            return 'chromecast'
        return 'google_device'
    
    # Gaming consoles
    if any(x in vendor_lower for x in ['sony', 'microsoft', 'nintendo']):
        if 3074 in open_ports:  # Xbox Live
            return 'gaming_console'
    
    # Computers
    if 22 in open_ports or 3389 in open_ports:
        return 'server' if 22 in open_ports else 'desktop'
    
    # IoT
    if 'espressif' in vendor_lower or 'tuya' in vendor_lower:
        return 'iot_device'
    
    return 'unknown'
```

### P2: AI-Powered Threat Analysis
**Goal:** Use DeepSeek to analyze network behavior intelligently

**Features:**
1. **Connection Analysis** - "Why is this process connecting to X?"
2. **Anomaly Detection** - "This device usually doesn't do Y"
3. **Threat Contextualization** - "This looks like C2 traffic because..."
4. **Smart Recommendations** - "You should block X because..."

**Implementation:**
```python
async def analyze_with_ai(context: dict) -> dict:
    """Use DeepSeek to analyze security context."""
    
    prompt = f"""Analyze this network security context and identify any threats or anomalies:

Devices on network: {len(context['devices'])}
Active connections: {len(context['connections'])}
Recent threats: {len(context['threats'])}

Suspicious connections:
{format_suspicious(context['connections'])}

Recent DNS queries:
{format_dns(context['dns_queries'])}

Provide:
1. Risk assessment (1-10)
2. Key concerns
3. Recommended actions

Be concise and actionable."""

    response = await llm.generate(prompt, system=SECURITY_ANALYST_SYSTEM)
    return parse_analysis(response)
```

### P3: Dashboard UX Polish
**Goal:** Make it feel professional and responsive

**Improvements:**
- [ ] Smooth animations on data updates
- [ ] Better loading states
- [ ] Keyboard shortcuts (R to refresh, etc.)
- [ ] Dark/light theme toggle
- [ ] Device icons based on type
- [ ] Color-coded severity badges
- [ ] Connection graph visualization
- [ ] Export to PDF/CSV
- [ ] Notification sounds for critical alerts

### P4: Smart Alerting
**Goal:** Reduce noise, increase signal

**Features:**
- Alert deduplication
- Severity auto-escalation
- Time-based correlation
- Known-good baseline learning
- Snooze/mute options

---

## Implementation Order

### Phase 1: Core AI (Today)
1. Fix Ollama path/connection
2. Add `/api/ai/analyze` endpoint
3. Wire up AI analysis to dashboard
4. Test with real network data

### Phase 2: Device Intelligence (Tomorrow)
1. Implement smart classification
2. Add device type icons to dashboard
3. Port scanning for context
4. Device profile persistence

### Phase 3: Polish (This Week)
1. Dashboard animations
2. Keyboard shortcuts
3. Better visualizations
4. Export functionality

### Phase 4: Smart Features (Next Week)
1. Baseline learning
2. Anomaly detection
3. Automated responses
4. Alert intelligence

---

## Success Criteria

**Amazing Dashboard = All of these:**
- [ ] Devices correctly identified by type
- [ ] AI provides actionable analysis
- [ ] Real-time updates feel instant
- [ ] Zero false-positive noise
- [ ] Professional, polished look
- [ ] Works offline (local AI)
- [ ] Fast (no lag on any action)

---

## Notes

- DeepSeek-r1:70b is the target model
- Ollama should be running locally
- All processing stays on-device (privacy)
- Dashboard should work without internet
