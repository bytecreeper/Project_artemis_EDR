# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Project Artemis, please report it responsibly:

1. **Do NOT** open a public issue
2. Open a private security advisory via GitHub's Security tab
3. Or email the maintainers directly (see GitHub profiles)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Design Principles

### Local-First

- All monitoring targets YOUR network only
- AI inference can run entirely offline (Ollama)
- No telemetry or data collection

### No Offensive Capabilities

This tool is designed for **defensive** security operations:
- ✅ Monitor your own network
- ✅ Detect threats on your endpoints
- ✅ Generate detection rules
- ❌ No attack tools
- ❌ No exploitation frameworks
- ❌ No external targeting

### Credential Handling

- API keys should use environment variables
- Never commit credentials to the repository
- Use `settings.example.json` for templates

### Network Scope

- Configure only networks you own/manage in `settings.json`
- Default exclusions prevent scanning external networks
- Sysmon config excludes internal traffic by default

## Known Security Considerations

### Response Actions

The EDR module includes response actions:
- **Kill process** — Terminates a process by PID
- **Block IP** — Adds Windows Firewall rule
- **Quarantine file** — Moves file to quarantine folder

These actions affect only the LOCAL machine and require appropriate permissions.

### Threat Intelligence

IoCs are pulled from public threat feeds:
- URLhaus
- Feodo Tracker
- ThreatFox
- MalwareBazaar
- blocklist.de
- Emerging Threats

These are well-known, reputable sources. No user data is sent to these services.

## Hardening Recommendations

1. Run the dashboard on localhost only (`127.0.0.1`)
2. Use a firewall to restrict access if exposing to LAN
3. Keep Sysmon and Windows updated
4. Review response actions before enabling auto-quarantine

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. Watch the repository for releases.
