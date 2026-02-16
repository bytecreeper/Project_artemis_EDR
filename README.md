# Project Artemis

AI-powered detection engineering platform. Generate detection rules from natural language threat descriptions.

## Features

- **Natural language to detection rules** - Describe a threat, get a deployable rule
- **Multiple formats** - Sigma, YARA, Splunk SPL (available), KQL, Snort (coming)
- **Automatic MITRE ATT&CK mapping** - Rules tagged with relevant techniques
- **Rule validation** - Syntax and logic checks before deployment
- **Swappable LLM backends** - Anthropic, OpenAI, or local Ollama
- **Local inference** - Run entirely offline with Ollama + DeepSeek/Qwen models

## Installation

```bash
# Clone the repo
git clone https://github.com/whisperrr-ux/project-artemis.git
cd project-artemis

# Install with pip (editable mode for development)
pip install -e ".[all]"

# Or just core dependencies
pip install -e .
```

## Quick Start

Set your API key (or use Ollama for local inference):

```bash
export ANTHROPIC_API_KEY="your-key-here"
# or
export OPENAI_API_KEY="your-key-here"
```

Generate a Sigma rule:

```bash
artemis generate "Detect PowerShell downloading files from the internet"
```

With local Ollama:

```bash
artemis generate "Mimikatz credential dumping via lsass" \
  -p ollama -m qwen3:32b \
  --severity critical \
  --save mimikatz.yml
```

## CLI Usage

```
artemis generate <description>    Generate a detection rule
artemis batch <file>              Generate rules from file (one per line)
artemis validate <rule.yml>       Validate an existing rule
artemis formats                   List supported formats
```

### Options

```
-f, --format    Output format (sigma, yara, splunk, kql, snort)
-p, --provider  LLM provider (anthropic, openai, ollama)
-m, --model     Model name override
-c, --context   Additional context for generation
-i, --indicator Known IOC (can repeat: -i hash1 -i hash2)
-s, --severity  Severity hint (low, medium, high, critical)
-o, --output    Output format (pretty, json, raw)
--save          Save rule to file
```

## Python API

```python
import asyncio
from artemis import Artemis, RuleFormat

async def main():
    # Initialize with Anthropic (default)
    engine = Artemis(provider="anthropic")
    
    # Or use local Ollama
    engine = Artemis(provider="ollama", model="qwen3:32b")
    
    # Generate a Sigma rule
    result = await engine.generate(
        description="Detect scheduled task creation for persistence",
        format=RuleFormat.SIGMA,
        severity_hint="high",
    )
    
    if result.success:
        print(result.rule.content)
        print(f"MITRE: {[m.technique_id for m in result.rule.mitre]}")
    else:
        print(f"Error: {result.error}")

asyncio.run(main())
```

### Batch Generation

```python
descriptions = [
    "PowerShell execution with encoded commands",
    "WMI process creation",
    "Suspicious DNS TXT queries",
]

results = await engine.generate_batch(descriptions)
for r in results:
    if r.success:
        print(r.rule.name)
```

## Supported Formats

| Format | Status | Description |
|--------|--------|-------------|
| Sigma | Available | Generic format, converts to 20+ SIEMs |
| YARA | Available | Pattern matching for files/malware |
| Splunk SPL | Available | Native Splunk queries |
| KQL | Coming | Microsoft Sentinel/Defender |
| Snort/Suricata | Coming | Network IDS rules |

## Local LLM Setup (Ollama)

For fully offline operation:

```bash
# Install Ollama
winget install Ollama.Ollama

# Pull a model
ollama pull qwen3:32b      # Balanced (20GB)
ollama pull qwen3:14b      # Fast (9GB)
ollama pull deepseek-r1:70b # Best quality (42GB, needs 64GB RAM)

# Use with Artemis
artemis generate "Detect lateral movement via PsExec" -p ollama -m qwen3:32b
```

## Example Output

Input:
```
artemis generate "Detect Cobalt Strike beacon spawning processes"
```

Output:
```yaml
title: Cobalt Strike Beacon Process Spawning
id: 8a4b5c6d-1234-5678-9abc-def012345678
status: experimental
level: high
description: Detects process spawning patterns typical of Cobalt Strike beacon
author: Artemis
date: 2026/02/16
references:
    - https://attack.mitre.org/techniques/T1055/
tags:
    - attack.execution
    - attack.t1059
    - attack.defense_evasion
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate administration scripts
    - Software installers
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black src tests
ruff check src tests
```

## Architecture

```
project-artemis/
├── src/artemis/
│   ├── core.py           # Main Artemis class
│   ├── cli.py            # Click CLI
│   ├── llm.py            # LLM provider abstraction
│   ├── models.py         # Pydantic models
│   ├── generators/       # Rule generators by format
│   │   ├── base.py       # Base generator class
│   │   ├── sigma.py      # Sigma generator
│   │   ├── yara.py       # YARA generator
│   │   └── splunk.py     # Splunk SPL generator
│   ├── validators/       # Rule validators
│   └── mappings/         # MITRE ATT&CK data
├── tests/
├── samples/
│   ├── logs/             # Sample logs for testing
│   ├── malware/          # Sample malware for YARA
│   └── rules/            # Example rules
└── pyproject.toml
```

## Roadmap

- [x] Sigma rule generation
- [x] YARA rule generation
- [x] Splunk SPL generation
- [x] Rule validation
- [x] MITRE ATT&CK auto-mapping
- [x] Local LLM support (Ollama)
- [ ] KQL (Microsoft Sentinel/Defender) generation
- [ ] Rule testing against sample data
- [ ] Rule conversion between formats
- [ ] Web UI

## Author

ByteCreeper (bytecreeper@proton.me)

## License

MIT
