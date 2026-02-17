import subprocess
import json
from datetime import datetime, timedelta

last_time = datetime.now() - timedelta(seconds=60)
channel = 'Windows PowerShell'

ps_script = f'''
$startTime = [DateTime]::Parse("{last_time.strftime('%Y-%m-%dT%H:%M:%S')}")
try {{
    Get-WinEvent -LogName "{channel}" -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object {{ $_.TimeCreated -gt $startTime }} |
    ForEach-Object {{
        @{{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id = $_.Id
        }}
    }} | ConvertTo-Json -Compress
}} catch {{}}
'''

print("Running PowerShell...")
result = subprocess.run(
    ['powershell', '-NoProfile', '-Command', ps_script],
    capture_output=True,
    text=True,
    timeout=10,
)

print(f"Return code: {result.returncode}")
print(f"Stdout: {result.stdout[:500] if result.stdout else 'EMPTY'}")
print(f"Stderr: {result.stderr[:200] if result.stderr else 'NONE'}")

if result.stdout.strip():
    try:
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        print(f"Parsed {len(data)} events!")
    except json.JSONDecodeError as e:
        print(f"JSON error: {e}")
