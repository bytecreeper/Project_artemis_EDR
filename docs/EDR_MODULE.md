# Project Artemis EDR Module

The Endpoint Detection & Response (EDR) module provides host-based threat detection capabilities for Project Artemis.

## Features

### 1. Sysmon Log Ingestion
Parses Windows Sysmon events for security analysis.

**Supported Event Types:**
- Process Creation (Event ID 1)
- Network Connections (Event ID 3)
- Process Termination (Event ID 5)
- Image/DLL Loading (Event ID 7)
- CreateRemoteThread (Event ID 8)
- Process Access (Event ID 10)
- File Creation (Event ID 11)
- Registry Events (Event IDs 12-14)
- DNS Queries (Event ID 22)
- File Deletion (Event IDs 23, 26)
- Process Tampering (Event ID 25)

**Detection Capabilities:**
- LOLBAS abuse (certutil, mshta, regsvr32, etc.)
- Suspicious parent→child process chains
- Encoded PowerShell commands
- Credential dumping indicators (Mimikatz, LSASS access)
- Shadow copy deletion (ransomware indicator)
- Registry persistence

### 2. Real-Time Process Monitoring
Monitors process creation/termination using psutil and WMI.

**Features:**
- Real-time process creation detection
- Parent-child relationship tracking
- Command line analysis
- Suspicious behavior alerting
- Process analysis (connections, open files, etc.)

### 3. Threat Intelligence Integration
Aggregates IoCs from free threat intelligence feeds.

**Supported Feeds:**
- **URLhaus** (abuse.ch) - Malicious URLs
- **Feodo Tracker** (abuse.ch) - Botnet C2 IPs
- **ThreatFox** (abuse.ch) - Crowdsourced IoCs
- **MalwareBazaar** (abuse.ch) - Malware hashes
- **blocklist.de** - Attacking IPs
- **Emerging Threats** - Compromised IPs

**IoC Types:**
- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)

## Setup

### Install Sysmon (Recommended)

1. Download Sysmon from [Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

2. Install with the Artemis config:
   ```powershell
   # Run as Administrator
   cd C:\path\to\sysmon
   .\sysmon64.exe -accepteula -i C:\path\to\project-artemis\config\sysmon-config.xml
   ```

3. Verify installation:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```

### Configure Event Forwarding

To send Sysmon events to Artemis, you can use:

**Option 1: PowerShell Script (simple)**
```powershell
# Forward recent events to Artemis
$events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100
$jsonEvents = $events | ForEach-Object {
    @{
        EventID = $_.Id
        TimeCreated = $_.TimeCreated.ToString("o")
        Computer = $_.MachineName
        data = @{}  # Parse XML for actual data
    }
}
Invoke-RestMethod -Uri "http://localhost:8000/api/edr/sysmon/ingest" `
    -Method POST `
    -ContentType "application/json" `
    -Body (@{ events = $jsonEvents; format = "json" } | ConvertTo-Json -Depth 10)
```

**Option 2: Windows Event Forwarding (enterprise)**
Configure WEF to forward events to a collector that sends to Artemis.

## API Reference

### Sysmon Endpoints

```
POST /api/edr/sysmon/ingest     - Ingest Sysmon events
GET  /api/edr/sysmon/events     - Get recent events
GET  /api/edr/sysmon/alerts     - Get recent alerts
GET  /api/edr/sysmon/stats      - Get parser statistics
```

### Process Monitor Endpoints

```
GET  /api/edr/processes              - List running processes
GET  /api/edr/processes/{pid}        - Get process details
GET  /api/edr/processes/events       - Get process events
GET  /api/edr/processes/alerts       - Get process alerts
POST /api/edr/processes/monitor/start - Start monitoring
POST /api/edr/processes/monitor/stop  - Stop monitoring
GET  /api/edr/processes/monitor/stats - Get monitor stats
```

### Threat Intelligence Endpoints

```
GET  /api/edr/threat-intel/status    - Get feed status
POST /api/edr/threat-intel/update    - Update feeds
POST /api/edr/threat-intel/check     - Check IoCs
GET  /api/edr/threat-intel/search    - Search IoC database
```

### Combined Endpoints

```
GET /api/edr/status   - Overall EDR status
GET /api/edr/alerts   - All alerts combined
```

## Usage Examples

### Ingest Sysmon Events

```bash
curl -X POST http://localhost:8000/api/edr/sysmon/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "EventID": 1,
        "TimeCreated": "2024-01-15T10:30:00Z",
        "Computer": "WORKSTATION1",
        "data": {
          "Image": "C:\\Windows\\System32\\cmd.exe",
          "CommandLine": "cmd.exe /c whoami",
          "ParentImage": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
          "User": "DOMAIN\\user"
        }
      }
    ],
    "format": "json"
  }'
```

### Check IoCs Against Threat Intel

```bash
curl -X POST http://localhost:8000/api/edr/threat-intel/check \
  -H "Content-Type: application/json" \
  -d '{
    "values": [
      "8.8.8.8",
      "malware-domain.tk",
      "d41d8cd98f00b204e9800998ecf8427e"
    ]
  }'
```

### Update Threat Feeds

```bash
# Update all feeds
curl -X POST http://localhost:8000/api/edr/threat-intel/update

# Update specific feed
curl -X POST "http://localhost:8000/api/edr/threat-intel/update?feed=feodo_ipblocklist"
```

### Start Process Monitor

```bash
curl -X POST http://localhost:8000/api/edr/processes/monitor/start
```

## Detection Rules

### MITRE ATT&CK Mapping

| Technique | ID | Detection |
|-----------|-----|-----------|
| Command-Line Interface | T1059 | Process creation with shell |
| PowerShell | T1059.001 | Encoded PS, bypass, hidden |
| Process Injection | T1055 | CreateRemoteThread events |
| Credential Dumping | T1003 | LSASS access |
| Inhibit System Recovery | T1490 | Shadow copy deletion |
| Boot/Logon Autostart | T1547 | Registry run key modification |
| DGA | T1568.002 | High-entropy DNS queries |
| Non-Standard Port | T1571 | Connections to unusual ports |

### Severity Levels

- **Critical**: Credential dumping, ransomware indicators
- **High**: Process injection, suspicious parent-child, encoded commands
- **Medium**: LOLBAS usage, suspicious network activity
- **Low**: Informational events, potential indicators

## Data Storage

Events and alerts are stored in:
```
data/
├── sysmon/
│   ├── events.jsonl    # All Sysmon events
│   ├── alerts.jsonl    # Alerts only
│   └── state.json      # Parser state
├── process_monitor/
│   ├── events.jsonl    # Process events
│   └── alerts.jsonl    # Process alerts
└── threat_intel/
    ├── iocs.json       # IoC database
    └── state.json      # Feed state
```

## Performance Considerations

- **Sysmon Config**: The provided config excludes noisy processes. Customize for your environment.
- **Process Monitor**: Polling happens every 1 second. WMI provides real-time events on Windows.
- **Threat Intel**: Feed updates can be slow (large files). Run during off-hours or via cron.
- **Storage**: Events accumulate. Consider rotation or cleanup for long-running deployments.

## Roadmap

- [ ] Sigma rules engine integration
- [ ] YARA file scanning
- [ ] Memory forensics (Volatility3)
- [ ] Behavioral baselining with DeepSeek
- [ ] Automated response playbooks
- [ ] Dashboard integration
