<#
.SYNOPSIS
    Collects genuine Windows Security & System Event logs natively using Get-WinEvent.
.DESCRIPTION
    Extracts Windows event telemetry with support for incremental checkpointing,
    forensic XML retention, and graceful permission handling.
.PARAMETER LogName
    Channel name to query (default: 'Security'). Can also be 'Application', 'System', etc.
.PARAMETER Path
    Optional path to an exported .evtx log file.
.PARAMETER Hours
    Number of hours in the past to query (default: 24). Set 0 to query without time bound.
.PARAMETER MaxEvents
    Maximum number of events to retrieve (default: 500).
.PARAMETER EventIDs
    Array of Event IDs to collect. Defaults to security-critical IDs (4624, 4625, 4634, 4648, 4672, 4720, 4722, 4728, 4740) when LogName is Security.
.PARAMETER Incremental
    If specified, collects only events with EventRecordID greater than the saved checkpoint.
.PARAMETER CheckpointFile
    Path to checkpoint JSON file (default: data/checkpoints/{LogName}_checkpoint.json).
.PARAMETER OutputFile
    Path to output XML file (default: data/collected/{LogName}_events.xml).
#>

[CmdletBinding()]
param(
    [string]$LogName = "Security",
    [string]$Path = "",
    [int]$Hours = 24,
    [int]$MaxEvents = 500,
    [int[]]$EventIDs,
    [switch]$Incremental,
    [string]$CheckpointFile = "",
    [string]$OutputFile = ""
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   LogAnalyzer Pro 2.0 - Windows Event Telemetry Collector" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Set default filenames based on LogName if not provided
$safeLogName = $LogName -replace '[\\/:]', '_'
if (-not $CheckpointFile) {
    $CheckpointFile = "data/checkpoints/${safeLogName}_checkpoint.json"
}
if (-not $OutputFile) {
    $OutputFile = "data/collected/${safeLogName}_events.xml"
}

# Default EventIDs for Security channel if not specified
if ($LogName -eq "Security" -and (-not $EventIDs -or $EventIDs.Count -eq 0)) {
    $EventIDs = @(4624, 4625, 4634, 4648, 4672, 4720, 4722, 4728, 4740)
}

# 1. Administrator / Permission Check
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$currentUser
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($LogName -eq "Security" -and -not $Path) {
    if (-not $isAdmin) {
        Write-Host "[!] Current session does not have Administrator privileges." -ForegroundColor Yellow
        Write-Host "[!] Windows Security event log requires Administrator rights or membership" -ForegroundColor Yellow
        Write-Host "    in the 'Event Log Readers' group." -ForegroundColor Yellow
        Write-Host "[i] Verifying access permissions on channel '$LogName'..." -ForegroundColor Gray
    }
    # Explicit permission probe to prevent Get-WinEvent FilterHashtable from masking Access Denied as empty criteria
    try {
        $null = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -like "*unauthorized*" -or $msg -like "*Access is denied*") {
            Write-Host ""
            Write-Host "[-] ACCESS DENIED: Cannot read the Windows '$LogName' event log channel." -ForegroundColor Red
            Write-Host "[-] Resolution Options:" -ForegroundColor Yellow
            Write-Host "    Option A: Run PowerShell as Administrator:" -ForegroundColor White
            Write-Host "       Start-Process powershell -Verb RunAs" -ForegroundColor Cyan
            Write-Host "       Then run: powershell -ExecutionPolicy Bypass -File scripts/collect_windows_events.ps1 -LogName Security" -ForegroundColor Cyan
            Write-Host "    Option B: Add current user to 'Event Log Readers' group (requires elevation once):" -ForegroundColor White
            Write-Host "       net localgroup `"Event Log Readers`" `"$($currentUser.Name)`" /add" -ForegroundColor Cyan
            Write-Host "       (Note: You must sign out and sign back in for group membership to take effect)." -ForegroundColor Gray
            Write-Host "    Option C: Export directly to XML from an elevated command prompt:" -ForegroundColor White
            Write-Host "       wevtutil qe Security /f:xml /c:500 > data\collected\windows_security_events.xml" -ForegroundColor Cyan
            Write-Host "       or export to EVTX and parse with -Path:" -ForegroundColor White
            Write-Host "       wevtutil epl Security data\collected\Security_live.evtx" -ForegroundColor Cyan
            Write-Host "       powershell -ExecutionPolicy Bypass -File scripts/collect_windows_events.ps1 -Path data/collected/Security_live.evtx" -ForegroundColor Cyan
            exit 1
        }
    }
}

# Ensure destination directories exist
$outputDir = [System.IO.Path]::GetDirectoryName($OutputFile)
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$checkpointDir = [System.IO.Path]::GetDirectoryName($CheckpointFile)
if ($checkpointDir -and -not (Test-Path $checkpointDir)) {
    New-Item -ItemType Directory -Path $checkpointDir -Force | Out-Null
}

# 2. Incremental Checkpoint Handling
$lastRecordId = 0
if ($Incremental -and (Test-Path $CheckpointFile)) {
    try {
        $checkpointData = Get-Content $CheckpointFile -Raw | ConvertFrom-Json
        if ($checkpointData.last_record_id) {
            $lastRecordId = [int64]$checkpointData.last_record_id
            Write-Host "[+] Resuming incremental collection from EventRecordID > $lastRecordId" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Warning: Failed to parse checkpoint file, defaulting to full query." -ForegroundColor Yellow
    }
}

# 3. Build Query Filter
$filter = @{}
if ($Path) {
    $filter['Path'] = $Path
    Write-Host "[i] Querying exported EVTX file: $Path..." -ForegroundColor Gray
} else {
    $filter['LogName'] = $LogName
    if ($EventIDs -and $EventIDs.Count -gt 0) {
        $filter['Id'] = $EventIDs
        Write-Host "[i] Querying channel '$LogName' (IDs: $($EventIDs -join ', '))..." -ForegroundColor Gray
    } else {
        Write-Host "[i] Querying channel '$LogName' (All Event IDs)..." -ForegroundColor Gray
    }
    if ($Hours -gt 0) {
        $startTime = (Get-Date).AddHours(-$Hours)
        $filter['StartTime'] = $startTime
        Write-Host "[i] Filtering events since $startTime ($Hours hours ago)..." -ForegroundColor Gray
    }
}

try {
    $rawEvents = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    $msg = $_.Exception.Message
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $msg -like "*unauthorized*" -or $msg -like "*Access is denied*") {
        Write-Host ""
        Write-Host "[-] ACCESS DENIED: Cannot read the Windows '$LogName' event log channel." -ForegroundColor Red
        Write-Host "[-] To grant access:" -ForegroundColor Yellow
        Write-Host "    1. Run PowerShell as Administrator:" -ForegroundColor Yellow
        Write-Host "       Start-Process powershell -Verb RunAs" -ForegroundColor Cyan
        Write-Host "    2. Or add your account to 'Event Log Readers':" -ForegroundColor Yellow
        Write-Host "       net localgroup `"Event Log Readers`" `"$($currentUser.Name)`" /add" -ForegroundColor Cyan
        Write-Host "    3. Or export the Security log from an elevated prompt:" -ForegroundColor Yellow
        Write-Host "       wevtutil epl Security data/collected/Security_export.evtx" -ForegroundColor Cyan
        Write-Host "       and rerun with -Path data/collected/Security_export.evtx" -ForegroundColor Cyan
        exit 1
    }
    if ($msg -like "*No events were found that match the specified selection criteria*") {
        Write-Host "[+] Query succeeded, but no events matched the criteria." -ForegroundColor Yellow
        exit 0
    }
    Write-Host "[-] Error retrieving Windows events: $msg" -ForegroundColor Red
    exit 1
}

# 4. Filter incrementally if requested
if ($Incremental -and $lastRecordId -gt 0) {
    $eventsToProcess = @($rawEvents | Where-Object { $_.RecordId -gt $lastRecordId })
} else {
    $eventsToProcess = $rawEvents
}

$count = $eventsToProcess.Count
Write-Host "[+] Successfully collected $count event(s) from $LogName." -ForegroundColor Green

if ($count -eq 0) {
    Write-Host "[i] No new events beyond RecordID $lastRecordId." -ForegroundColor Gray
    exit 0
}

# 5. Export as XML preserving exact raw event structure
$xmlList = @()
$maxCollectedRecordId = $lastRecordId
$latestTimestamp = $null
$computerName = $env:COMPUTERNAME

foreach ($ev in $eventsToProcess) {
    $xmlList += $ev.ToXml()
    if ($ev.RecordId -gt $maxCollectedRecordId) {
        $maxCollectedRecordId = $ev.RecordId
        $latestTimestamp = $ev.TimeCreated.ToUniversalTime().ToString("o")
    }
}

$combinedXml = "<Events>`n" + ($xmlList -join "`n") + "`n</Events>"
[System.IO.File]::WriteAllText($OutputFile, $combinedXml, [System.Text.Encoding]::UTF8)
Write-Host "[+] Saved $count events to $OutputFile (forensic XML preserved)." -ForegroundColor Green

# 6. Save Checkpoint
$newCheckpoint = [PSCustomObject]@{
    channel = $LogName
    last_record_id = $maxCollectedRecordId
    last_timestamp = $latestTimestamp
    last_collected_at = (Get-Date).ToUniversalTime().ToString("o")
    events_in_batch = $count
    computer_name = $computerName
}

$newCheckpoint | ConvertTo-Json -Depth 3 | Set-Content $CheckpointFile -Encoding UTF8
Write-Host "[+] Updated checkpoint: RecordID = $maxCollectedRecordId in $CheckpointFile" -ForegroundColor Green
