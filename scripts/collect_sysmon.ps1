<#
.SYNOPSIS
    Collects Microsoft Sysmon Operational events (IDs 1, 3, 11, 12-14, 22).
.DESCRIPTION
    Extracts process creation, network connections, file creation, registry modifications,
    and DNS queries from Microsoft-Windows-Sysmon/Operational.
    Sysmon is OPTIONAL: if not installed, the script displays setup instructions and exits gracefully.
.PARAMETER Hours
    Hours back to query (default: 24).
.PARAMETER MaxEvents
    Maximum number of events to retrieve (default: 500).
.PARAMETER Incremental
    If specified, queries only events with EventRecordID greater than the saved checkpoint.
.PARAMETER CheckpointFile
    Path to checkpoint JSON file (default: data/checkpoints/sysmon_checkpoint.json).
.PARAMETER OutputFile
    Path to output XML file (default: data/collected/sysmon_events.xml).
.PARAMETER ValidateConfig
    Checks and reports whether Network Connection (Event ID 3) logging is detected.
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 500,
    [int[]]$EventIDs = @(1, 3, 11, 12, 13, 14, 22),
    [switch]$Incremental,
    [switch]$ValidateConfig,
    [string]$CheckpointFile = "data/checkpoints/sysmon_checkpoint.json",
    [string]$OutputFile = "data/collected/sysmon_events.xml"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   LogAnalyzer Pro 2.0 - Microsoft Sysmon Log Collector   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$channelName = "Microsoft-Windows-Sysmon/Operational"

# 1. Check if Sysmon Channel / Service Exists
$channelExists = $false
try {
    $logInfo = Get-WinEvent -ListLog $channelName -ErrorAction SilentlyContinue
    if ($logInfo -and $logInfo.IsEnabled) {
        $channelExists = $true
    }
} catch {
    $channelExists = $false
}

if (-not $channelExists) {
    Write-Host "[INFO] Microsoft Sysmon is not currently installed or the channel" -ForegroundColor Yellow
    Write-Host "       '$channelName' is not enabled on this host." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Sysmon integration is optional in LogAnalyzer Pro. To install Sysmon for endpoint monitoring:" -ForegroundColor White
    Write-Host "  1. Download Sysmon from Microsoft Sysinternals:" -ForegroundColor Cyan
    Write-Host "     https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Cyan
    Write-Host "  2. Download a recommended production configuration (e.g. SwiftOnSecurity):" -ForegroundColor Cyan
    Write-Host "     https://github.com/SwiftOnSecurity/sysmon-config" -ForegroundColor Cyan
    Write-Host "  3. From an elevated Administrator prompt, install with:" -ForegroundColor Cyan
    Write-Host "     sysmon64.exe -accepteula -i sysmonconfig-export.xml" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[+] LogAnalyzer Pro continues normal operation with Windows Security and Linux auth logs." -ForegroundColor Green
    exit 0
}

Write-Host "[+] Microsoft Sysmon channel '$channelName' is active and enabled." -ForegroundColor Green

# 2. Validate Sysmon Network Connection (Event ID 3) Logging
if ($ValidateConfig) {
    Write-Host "[i] Validating Sysmon telemetry configuration..." -ForegroundColor Gray
    try {
        $recentE3 = Get-WinEvent -FilterHashtable @{ LogName = $channelName; Id = 3 } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($recentE3) {
            Write-Host "[+] Sysmon Event ID 3 (Network Connection) logging is ACTIVE." -ForegroundColor Green
        } else {
            Write-Host "[!] Notice: No recent Event ID 3 (Network Connection) events found in buffer." -ForegroundColor Yellow
            Write-Host "    If you need network telemetry, ensure your Sysmon XML config includes:" -ForegroundColor Yellow
            Write-Host '    <NetworkConnect onmatch="include" />' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[-] Note: Could not query Event ID 3 status ($($_.Exception.Message))." -ForegroundColor Gray
    }
}

# 3. Checkpoint Handling
$outputDir = [System.IO.Path]::GetDirectoryName($OutputFile)
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$checkpointDir = [System.IO.Path]::GetDirectoryName($CheckpointFile)
if ($checkpointDir -and -not (Test-Path $checkpointDir)) {
    New-Item -ItemType Directory -Path $checkpointDir -Force | Out-Null
}

$lastRecordId = 0
if ($Incremental -and (Test-Path $CheckpointFile)) {
    try {
        $cp = Get-Content $CheckpointFile -Raw | ConvertFrom-Json
        if ($cp.last_record_id) {
            $lastRecordId = [int64]$cp.last_record_id
            Write-Host "[+] Resuming incremental collection from Sysmon RecordID > $lastRecordId" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Warning: Checkpoint file unreadable, defaulting to time range query." -ForegroundColor Yellow
    }
}

# 4. Query Sysmon Events
$startTime = (Get-Date).AddHours(-$Hours)
$eventIdsStr = $EventIDs -join ', '
$filter = @{
    LogName = $channelName
    Id = $EventIDs
    StartTime = $startTime
}

Write-Host "[i] Querying Sysmon events (IDs: $eventIdsStr) since $startTime..." -ForegroundColor Gray

try {
    $rawEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    $msg = $_.Exception.Message
    if ($msg -like "*No events were found that match the specified selection criteria*") {
        Write-Host "[+] Query succeeded, but no Sysmon events found in the past $Hours hours." -ForegroundColor Yellow
        exit 0
    }
    Write-Host "[-] Error querying Sysmon events: $msg" -ForegroundColor Red
    exit 1
}

if ($Incremental -and $lastRecordId -gt 0) {
    $eventsToProcess = @($rawEvents | Where-Object { $_.RecordId -gt $lastRecordId })
} else {
    $eventsToProcess = $rawEvents
}

$count = $eventsToProcess.Count
Write-Host "[+] Collected $count Sysmon event(s)." -ForegroundColor Green

if ($count -eq 0) {
    Write-Host "[i] No new events beyond RecordID $lastRecordId." -ForegroundColor Gray
    exit 0
}

# 5. Export XML
$xmlList = @()
$maxCollectedRecordId = $lastRecordId
$latestTimestamp = $null

foreach ($ev in $eventsToProcess) {
    $xmlList += $ev.ToXml()
    if ($ev.RecordId -gt $maxCollectedRecordId) {
        $maxCollectedRecordId = $ev.RecordId
        $latestTimestamp = $ev.TimeCreated.ToUniversalTime().ToString("o")
    }
}

$combinedXml = "<Events>`n" + ($xmlList -join "`n") + "`n</Events>"
[System.IO.File]::WriteAllText($OutputFile, $combinedXml, [System.Text.Encoding]::UTF8)
Write-Host "[+] Saved $count Sysmon events to $OutputFile" -ForegroundColor Green

# 6. Save Checkpoint
$newCheckpoint = [PSCustomObject]@{
    channel = $channelName
    last_record_id = $maxCollectedRecordId
    last_timestamp = $latestTimestamp
    last_collected_at = (Get-Date).ToUniversalTime().ToString("o")
    events_in_batch = $count
    computer_name = $env:COMPUTERNAME
}

$newCheckpoint | ConvertTo-Json -Depth 3 | Set-Content $CheckpointFile -Encoding UTF8
Write-Host "[+] Updated Sysmon checkpoint: RecordID = $maxCollectedRecordId in $CheckpointFile" -ForegroundColor Green
