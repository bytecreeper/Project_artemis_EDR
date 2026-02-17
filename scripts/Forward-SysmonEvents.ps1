<#
.SYNOPSIS
    Forward Sysmon events to Project Artemis EDR module.

.DESCRIPTION
    This script reads Sysmon events from the Windows Event Log and forwards them
    to the Artemis API for analysis and threat detection.

.PARAMETER ArtemisUrl
    Base URL of the Artemis server. Default: http://localhost:8000

.PARAMETER MaxEvents
    Maximum number of events to forward per batch. Default: 100

.PARAMETER Continuous
    Run continuously, polling for new events. Default: $false

.PARAMETER PollIntervalSeconds
    Interval between polls in continuous mode. Default: 10

.EXAMPLE
    .\Forward-SysmonEvents.ps1
    Forwards the last 100 Sysmon events to Artemis.

.EXAMPLE
    .\Forward-SysmonEvents.ps1 -Continuous -PollIntervalSeconds 5
    Continuously forwards new Sysmon events every 5 seconds.

.NOTES
    Requires: Administrator privileges to read Sysmon events
    Author: Project Artemis
#>

param(
    [string]$ArtemisUrl = "http://localhost:8000",
    [int]$MaxEvents = 100,
    [switch]$Continuous,
    [int]$PollIntervalSeconds = 10
)

$ErrorActionPreference = "Stop"

# Track last processed event for continuous mode
$script:LastRecordId = 0

function Get-SysmonEvents {
    param(
        [int]$MaxEvents = 100,
        [long]$AfterRecordId = 0
    )
    
    $logName = "Microsoft-Windows-Sysmon/Operational"
    
    try {
        if ($AfterRecordId -gt 0) {
            # Get events after the specified record ID
            $filterXml = @"
<QueryList>
  <Query Id="0" Path="$logName">
    <Select Path="$logName">*[System[EventRecordID > $AfterRecordId]]</Select>
  </Query>
</QueryList>
"@
            $events = Get-WinEvent -FilterXml $filterXml -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
        else {
            $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
        
        return $events
    }
    catch [System.Exception] {
        if ($_.Exception.Message -like "*No events were found*") {
            return @()
        }
        throw
    }
}

function Convert-SysmonEventToJson {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )
    
    # Parse XML to extract event data
    $xml = [xml]$Event.ToXml()
    
    $eventData = @{}
    $dataNodes = $xml.Event.EventData.Data
    
    foreach ($node in $dataNodes) {
        $name = $node.Name
        $value = $node.'#text'
        if ($name -and $value) {
            $eventData[$name] = $value
        }
    }
    
    return @{
        EventID = $Event.Id
        TimeCreated = $Event.TimeCreated.ToString("o")
        Computer = $Event.MachineName
        RecordId = $Event.RecordId
        data = $eventData
    }
}

function Send-EventsToArtemis {
    param(
        [array]$Events
    )
    
    if ($Events.Count -eq 0) {
        return @{ success = $true; processed = 0 }
    }
    
    $body = @{
        events = $Events
        format = "json"
    } | ConvertTo-Json -Depth 10 -Compress
    
    try {
        $response = Invoke-RestMethod `
            -Uri "$ArtemisUrl/api/edr/sysmon/ingest" `
            -Method POST `
            -ContentType "application/json" `
            -Body $body `
            -TimeoutSec 30
        
        return $response
    }
    catch {
        Write-Warning "Failed to send events: $_"
        return @{ success = $false; error = $_.Exception.Message }
    }
}

function Write-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           Project Artemis - Sysmon Event Forwarder           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Target: $ArtemisUrl" -ForegroundColor Gray
    Write-Host "  Mode:   $(if ($Continuous) { 'Continuous (polling every ${PollIntervalSeconds}s)' } else { 'One-shot' })" -ForegroundColor Gray
    Write-Host ""
}

# Main execution
Write-Banner

# Check if Sysmon log exists
try {
    $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
}
catch {
    Write-Host "[ERROR] Sysmon is not installed or no events exist." -ForegroundColor Red
    Write-Host ""
    Write-Host "To install Sysmon:" -ForegroundColor Yellow
    Write-Host "  1. Download from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Yellow
    Write-Host "  2. Run: sysmon64.exe -accepteula -i config\sysmon-config.xml" -ForegroundColor Yellow
    exit 1
}

# Check Artemis connectivity
try {
    $health = Invoke-RestMethod -Uri "$ArtemisUrl/api/health" -Method GET -TimeoutSec 5
    Write-Host "[OK] Connected to Artemis" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Cannot connect to Artemis at $ArtemisUrl" -ForegroundColor Red
    Write-Host "        Make sure the server is running." -ForegroundColor Red
    exit 1
}

if ($Continuous) {
    Write-Host "[*] Starting continuous event forwarding..." -ForegroundColor Cyan
    Write-Host "    Press Ctrl+C to stop" -ForegroundColor Gray
    Write-Host ""
    
    # Get current max record ID to start from
    $latestEvent = Get-SysmonEvents -MaxEvents 1
    if ($latestEvent) {
        $script:LastRecordId = $latestEvent.RecordId
        Write-Host "[*] Starting from Record ID: $($script:LastRecordId)" -ForegroundColor Gray
    }
    
    $totalForwarded = 0
    $totalAlerts = 0
    
    while ($true) {
        try {
            $events = Get-SysmonEvents -MaxEvents $MaxEvents -AfterRecordId $script:LastRecordId
            
            if ($events -and $events.Count -gt 0) {
                # Update last record ID
                $script:LastRecordId = ($events | Measure-Object -Property RecordId -Maximum).Maximum
                
                # Convert and send
                $jsonEvents = $events | ForEach-Object { Convert-SysmonEventToJson -Event $_ }
                $result = Send-EventsToArtemis -Events $jsonEvents
                
                if ($result.success) {
                    $totalForwarded += $result.processed
                    $totalAlerts += $result.alerts
                    
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    Write-Host "[$timestamp] Forwarded $($result.processed) events ($($result.alerts) alerts) | Total: $totalForwarded events, $totalAlerts alerts" -ForegroundColor $(if ($result.alerts -gt 0) { "Yellow" } else { "Green" })
                }
            }
            
            Start-Sleep -Seconds $PollIntervalSeconds
        }
        catch {
            Write-Warning "Error in poll loop: $_"
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
}
else {
    # One-shot mode
    Write-Host "[*] Fetching last $MaxEvents Sysmon events..." -ForegroundColor Cyan
    
    $events = Get-SysmonEvents -MaxEvents $MaxEvents
    
    if ($events.Count -eq 0) {
        Write-Host "[!] No Sysmon events found" -ForegroundColor Yellow
        exit 0
    }
    
    Write-Host "[*] Converting $($events.Count) events..." -ForegroundColor Cyan
    $jsonEvents = $events | ForEach-Object { Convert-SysmonEventToJson -Event $_ }
    
    Write-Host "[*] Sending to Artemis..." -ForegroundColor Cyan
    $result = Send-EventsToArtemis -Events $jsonEvents
    
    if ($result.success) {
        Write-Host ""
        Write-Host "[OK] Successfully forwarded $($result.processed) events" -ForegroundColor Green
        if ($result.alerts -gt 0) {
            Write-Host "[!] Generated $($result.alerts) alerts!" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[ERROR] Failed to forward events: $($result.error)" -ForegroundColor Red
        exit 1
    }
}
