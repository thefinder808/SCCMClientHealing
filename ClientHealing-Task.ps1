<#
.SYNOPSIS
    SCCM Client Healing Script -- Scheduled Task Edition

.DESCRIPTION
    Self-healing, self-retiring remediation agent designed to run as a
    GPO-deployed scheduled task. Fires on startup AND daily, performs the same
    deep diagnostic, cleanup, and reinstallation as the GPO startup script,
    but tracks consecutive healthy checks via a JSON state file and
    auto-removes itself after the client has been confirmed healthy N times
    in a row.

    Key differences from the GPO startup edition:
      - Self-staging: when launched from a UNC path, copies itself to
        C:\Support and re-launches locally (avoids Defender temp blocks
        and network dependency during execution)
      - Runs as a scheduled task (startup + daily) instead of GPO startup script
      - JSON state file tracks consecutive successes across runs
      - Auto-removes the scheduled task after N consecutive healthy checks
      - No marker file -- state file replaces it
      - All output goes to a log file (no Write-Host)
      - Runs as SYSTEM via scheduled task (no admin check needed)
      - Start-Transcript as a safety net

.NOTES
    DEPLOYMENT VIA GPO PREFERENCES:
    ================================
    1. Place this script on a share readable by Domain Computers
       (e.g. \\domain.com\NETLOGON\Scripts\ClientHealing-Task.ps1)

    2. Ensure the ClientSource share is also readable by Domain Computers

    3. Open Group Policy Management, create/edit a GPO linked to
       the OU containing affected workstations

    4. Navigate to:
       Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks

    5. Right-click > New > Scheduled Task (At least Windows 7)

    6. General tab:
       - Name: "SCCM Client Healing"  (must match $ScheduledTaskName in script)
       - Run as: NT AUTHORITY\SYSTEM
       - Run with highest privileges: checked
       - Configure for: Windows 7 / Windows Server 2008 R2 (or later)

    7. Triggers tab -- add TWO triggers:
       a. At startup -- Delay task for: 5 minutes
       b. Daily -- At a fixed time (e.g. 13:00), repeat every 1 day
          Optionally: enable "Delay task for up to (random delay): 1 hour"
          to avoid all machines hitting the share simultaneously

    8. Actions tab:
       - Action: Start a program
       - Program: powershell.exe
       - Arguments: -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "\\path\to\ClientHealing-Task.ps1"
       NOTE: The script self-stages to C:\Support and re-launches locally.
       The scheduled task can safely point to the UNC path.

    9. Settings tab:
       - Allow task to be run on demand: checked
       - Stop the task if it runs longer than: 30 minutes
       - If the task is already running: Do not start a new instance

    10. REMOVAL: Once all clients are healed, the task auto-removes itself.
        Remove the GPO link to stop deploying to new machines.
        If a machine was missed, GPO will re-create the task on next gpupdate.

    LOCAL FILES (created automatically in C:\Support):
    ==================================================
    - ClientHealing-Task.ps1    -- local copy of the script
    - SCCMHealing-Task.log      -- execution log
    - SCCMHealing-Task.state    -- JSON state file (consecutive successes)
    - SCCMHealing-Task-Transcript.log -- PowerShell transcript (safety net)

    TESTING:
    ========
    Test by running as SYSTEM before GPO deployment:
      psexec -s powershell.exe -ExecutionPolicy Bypass -File "\\path\to\ClientHealing-Task.ps1"

    Verify state file is created/updated after each run.
    Verify auto-removal: set $ConsecutiveSuccessThreshold = 1 on a healthy
    machine, run once -- task should unregister itself.
#>

# ===== CONFIGURATION - EDIT THESE VALUES =====================================
$SiteCode                    = "YOURSITECODE"
$ManagementPoint             = "YOURMP.domain.com"
$ClientSource                = "\\SERVER\Share\Client"
$LocalStagingDir             = "C:\Support"             # Local execution directory (avoids Defender temp blocks)
$LogPath                     = "$LocalStagingDir\SCCMHealing-Task.log"
$StateFile                   = "$LocalStagingDir\SCCMHealing-Task.state"
$MaxRetries                  = 3          # Network path retry attempts
$RetryDelaySec               = 30         # Seconds between retries
$ConsecutiveSuccessThreshold = 3          # Auto-remove after this many consecutive healthy checks
$ScheduledTaskName           = "SCCM Client Healing"   # Must match the name in GPO Preferences
$ScheduledTaskPath           = "\"                      # Root of Task Scheduler
$NetworkLogShare             = "\\SERVER\Share\SCCMLogs"   # UNC path -- logs deposited to $NetworkLogShare\<ComputerName>\
# =============================================================================

# ============================================================================
#  SELF-STAGING BOOTSTRAP
#  If running from a UNC path, copy self to C:\Support and re-launch locally.
#  This avoids network dependency during execution and Defender temp blocks.
# ============================================================================

# Ensure C:\Support exists
if (-not (Test-Path $LocalStagingDir)) {
    New-Item -Path $LocalStagingDir -ItemType Directory -Force | Out-Null
}

$scriptPath = $MyInvocation.MyCommand.Path
$localScript = Join-Path $LocalStagingDir "ClientHealing-Task.ps1"

if ($scriptPath -and $scriptPath -match '^\\\\') {
    # Running from a UNC path -- stage locally and re-launch
    try {
        Copy-Item -Path $scriptPath -Destination $localScript -Force -ErrorAction Stop
    } catch {
        # If copy fails, still try to run from the network path
        exit 1
    }

    # Re-launch from the local copy and exit this instance
    $psArgs = @(
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-NonInteractive",
        "-File", $localScript
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $psArgs -WindowStyle Hidden -Wait
    exit $LASTEXITCODE
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
#  LOGGING
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","PHASE")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
}

function Copy-LogToNetworkShare {
    if (-not $NetworkLogShare -or $NetworkLogShare -match '\\\\SERVER\\Share') { return }
    try {
        $destDir = Join-Path $NetworkLogShare $env:COMPUTERNAME
        if (-not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        $healthStatusLocal = Join-Path $LocalStagingDir "HealthStatus.json"
        foreach ($file in @($LogPath, $transcriptPath, $StateFile, $healthStatusLocal)) {
            if ($file -and (Test-Path $file)) {
                Copy-Item -Path $file -Destination $destDir -Force -ErrorAction Stop
            }
        }
        Write-Log "Logs copied to $destDir" "INFO"
    } catch {
        Write-Log "Failed to copy logs to network share: $($_.Exception.Message)" "WARN"
    }
}

# ============================================================================
#  STATE FILE MANAGEMENT
# ============================================================================

function Read-State {
    $default = @{
        ConsecutiveSuccesses = 0
        LastCheckTime        = $null
        LastHealTime         = $null
        LastHealthScore      = 0
        ClientVersion        = $null
        TotalRuns            = 0
        TotalHeals           = 0
    }

    if (-not (Test-Path $StateFile)) {
        Write-Log "State file not found -- initializing fresh state" "INFO"
        return $default
    }

    try {
        $raw = Get-Content -Path $StateFile -Raw -ErrorAction Stop
        $state = $raw | ConvertFrom-Json
        # Validate expected properties exist, fill in missing ones
        $result = @{
            ConsecutiveSuccesses = if ($null -ne $state.ConsecutiveSuccesses) { [int]$state.ConsecutiveSuccesses } else { 0 }
            LastCheckTime        = $state.LastCheckTime
            LastHealTime         = $state.LastHealTime
            LastHealthScore      = if ($null -ne $state.LastHealthScore) { [int]$state.LastHealthScore } else { 0 }
            ClientVersion        = $state.ClientVersion
            TotalRuns            = if ($null -ne $state.TotalRuns) { [int]$state.TotalRuns } else { 0 }
            TotalHeals           = if ($null -ne $state.TotalHeals) { [int]$state.TotalHeals } else { 0 }
        }
        Write-Log "State loaded: ConsecutiveSuccesses=$($result.ConsecutiveSuccesses), TotalRuns=$($result.TotalRuns), TotalHeals=$($result.TotalHeals)" "INFO"
        return $result
    } catch {
        Write-Log "State file corrupt or unreadable -- reinitializing: $($_.Exception.Message)" "WARN"
        return $default
    }
}

function Write-State {
    param([hashtable]$State)

    try {
        $json = $State | ConvertTo-Json -Depth 2
        Set-Content -Path $StateFile -Value $json -Force -ErrorAction Stop
        Write-Log "State written: ConsecutiveSuccesses=$($State.ConsecutiveSuccesses), LastHealthScore=$($State.LastHealthScore)" "INFO"
    } catch {
        Write-Log "Failed to write state file: $($_.Exception.Message)" "ERROR"
    }
}

# ============================================================================
#  GUI-COMPATIBLE REPORTING (ConfigMgrHealthAgent-GUI Fleet Dashboard)
# ============================================================================

function Get-HealthStatusText {
    param([int]$Score)
    if ($Score -eq 100) { return "Healthy" }
    elseif ($Score -ge 75) { return "Degraded" }
    else { return "Critical" }
}

function Write-HealthStatus {
    param(
        [hashtable]$HealthResult,
        [int]$RemediationTier = 0,
        [string]$RemediationResult = "None",
        [string]$ClientVersion = ""
    )

    $statusText = Get-HealthStatusText -Score $HealthResult.Score

    $status = [ordered]@{
        ComputerName      = $env:COMPUTERNAME
        HealthScore       = $HealthResult.Score
        HealthStatus      = $statusText
        ChecksPassed      = $HealthResult.Passed
        ChecksFailed      = $HealthResult.Total - $HealthResult.Passed
        ChecksTotal       = $HealthResult.Total
        RemediationTier   = $RemediationTier
        RemediationResult = $RemediationResult
        ClientVersion     = $ClientVersion
        SiteCode          = $SiteCode
        AgentVersion      = "1.0.0-SCCMHealing"
        LastCheckTime     = (Get-Date).ToString("o")
        CheckDetails      = $HealthResult.CheckDetails
    }

    $json = $status | ConvertTo-Json -Depth 3

    # Write local copy
    $localPath = Join-Path $LocalStagingDir "HealthStatus.json"
    try {
        Set-Content -Path $localPath -Value $json -Force -ErrorAction Stop
        Write-Log "HealthStatus.json written locally" "INFO"
    } catch {
        Write-Log "Failed to write local HealthStatus.json: $($_.Exception.Message)" "WARN"
    }

    # Write to network share
    if ($NetworkLogShare -and $NetworkLogShare -notmatch '\\\\SERVER\\Share') {
        try {
            $destDir = Join-Path $NetworkLogShare $env:COMPUTERNAME
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            $netPath = Join-Path $destDir "HealthStatus.json"
            Set-Content -Path $netPath -Value $json -Force -ErrorAction Stop
            Write-Log "HealthStatus.json written to network share" "INFO"
        } catch {
            Write-Log "Failed to write network HealthStatus.json: $($_.Exception.Message)" "WARN"
        }
    }
}

function Write-HealthHistory {
    param(
        [int]$HealthScore,
        [int]$RemediationTier = 0,
        [string]$RemediationResult = "None"
    )

    $statusText = Get-HealthStatusText -Score $HealthScore

    $entry = [ordered]@{
        Timestamp         = (Get-Date).ToString("o")
        HealthScore       = $HealthScore
        HealthStatus      = $statusText
        RemediationTier   = $RemediationTier
        RemediationResult = $RemediationResult
    }

    $jsonLine = $entry | ConvertTo-Json -Compress

    # Append to network share (JSONL is append-only, write directly to share)
    if ($NetworkLogShare -and $NetworkLogShare -notmatch '\\\\SERVER\\Share') {
        try {
            $destDir = Join-Path $NetworkLogShare $env:COMPUTERNAME
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            $histPath = Join-Path $destDir "HealthHistory.jsonl"
            Add-Content -Path $histPath -Value $jsonLine -ErrorAction Stop
            Write-Log "HealthHistory.jsonl entry appended" "INFO"
        } catch {
            Write-Log "Failed to append HealthHistory.jsonl: $($_.Exception.Message)" "WARN"
        }
    }

    # Also append to local copy
    $localHistPath = Join-Path $LocalStagingDir "HealthHistory.jsonl"
    try {
        Add-Content -Path $localHistPath -Value $jsonLine -ErrorAction Stop
    } catch {
        Write-Log "Failed to append local HealthHistory.jsonl: $($_.Exception.Message)" "WARN"
    }
}

# ============================================================================
#  NETWORK WAIT
# ============================================================================

function Wait-ForNetwork {
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        $sourcePath = Join-Path $ClientSource "ccmsetup.exe"
        if (Test-Path $sourcePath) {
            Write-Log "Client source accessible: $sourcePath (attempt $attempt)" "SUCCESS"
            return $true
        }
        Write-Log "Client source not reachable (attempt $attempt of $MaxRetries). Waiting $RetryDelaySec seconds..." "WARN"
        Start-Sleep -Seconds $RetryDelaySec
    }
    Write-Log "Client source unreachable after $MaxRetries attempts. Exiting." "ERROR"
    return $false
}

# ============================================================================
#  HEALTH CHECK
# ============================================================================

function Get-SCCMHealthScore {
    Write-Log "===== HEALTH CHECK =====" "PHASE"

    $passed = 0
    $total  = 0
    $checkDetails = @()

    # CcmExec Service
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") { $passed++; $checkStatus = "Pass"; $checkDetail = "CcmExec service is running"; Write-Log "CcmExec Service: Running" "SUCCESS" }
        else { $checkDetail = "CcmExec service status: $($svc.Status)"; Write-Log "CcmExec Service: $($svc.Status)" "ERROR" }
    } catch { $checkDetail = "CcmExec service not found"; Write-Log "CcmExec Service: Not found" "ERROR" }
    $checkDetails += @{ Name = "CcmExec Service"; Category = "Client Service"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # Client Version
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
        $passed++; $checkStatus = "Pass"; $checkDetail = "Client version: $($client.ClientVersion)"; Write-Log "Client Version: $($client.ClientVersion)" "SUCCESS"
    } catch { $checkDetail = "Cannot query root\ccm"; Write-Log "Client Version: Cannot query root\ccm" "ERROR" }
    $checkDetails += @{ Name = "Client Version"; Category = "Client Installation"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # WMI Health
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Out-Null
        $passed++; $checkStatus = "Pass"; $checkDetail = "WMI repository is healthy"; Write-Log "WMI Health: OK" "SUCCESS"
    } catch { $checkDetail = "WMI query failed"; Write-Log "WMI Health: FAILED" "ERROR" }
    $checkDetails += @{ Name = "WMI Health"; Category = "System Health"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # SCCM WMI Namespaces (root\ccm is required; root\sms is optional on clients)
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    $ccmNsOk = $true
    try { Get-CimInstance -Namespace "root\ccm" -ClassName "__NAMESPACE" -ErrorAction Stop | Out-Null }
    catch { $ccmNsOk = $false }
    if ($ccmNsOk) { $passed++; $checkStatus = "Pass"; $checkDetail = "root\ccm namespace present"; Write-Log "SCCM WMI Namespaces: root\ccm present" "SUCCESS" }
    else { $checkDetail = "root\ccm namespace missing"; Write-Log "SCCM WMI Namespaces: root\ccm missing" "ERROR" }
    $checkDetails += @{ Name = "SCCM WMI Namespaces"; Category = "System Health"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # BITS Service
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $bits = Get-Service -Name BITS -ErrorAction Stop
        if ($bits.Status -eq "Running" -or $bits.StartType -ne "Disabled") { $passed++; $checkStatus = "Pass"; $checkDetail = "BITS status: $($bits.Status)/$($bits.StartType)"; Write-Log "BITS: $($bits.Status)/$($bits.StartType)" "SUCCESS" }
        else { $checkDetail = "BITS service is disabled"; Write-Log "BITS: Disabled" "ERROR" }
    } catch { $checkDetail = "BITS service not found"; Write-Log "BITS: Not found" "ERROR" }
    $checkDetails += @{ Name = "BITS Service"; Category = "System Services"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # Windows Update Service
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        if ($wu.StartType -ne "Disabled") { $passed++; $checkStatus = "Pass"; $checkDetail = "Windows Update status: $($wu.Status)/$($wu.StartType)"; Write-Log "WU: $($wu.Status)/$($wu.StartType)" "SUCCESS" }
        else { $checkDetail = "Windows Update service is disabled"; Write-Log "WU: Disabled" "ERROR" }
    } catch { $checkDetail = "Windows Update service not found"; Write-Log "WU: Not found" "ERROR" }
    $checkDetails += @{ Name = "Windows Update Service"; Category = "System Services"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # Cryptographic Services
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $crypto = Get-Service -Name CryptSvc -ErrorAction Stop
        if ($crypto.Status -eq "Running") { $passed++; $checkStatus = "Pass"; $checkDetail = "Cryptographic Services running"; Write-Log "CryptSvc: Running" "SUCCESS" }
        else { $checkDetail = "Cryptographic Services status: $($crypto.Status)"; Write-Log "CryptSvc: $($crypto.Status)" "ERROR" }
    } catch { $checkDetail = "Cryptographic Services not found"; Write-Log "CryptSvc: Not found" "ERROR" }
    $checkDetails += @{ Name = "Cryptographic Services"; Category = "System Services"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # SCCM Certificate
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $smsCerts = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction Stop
        $validCerts = $smsCerts | Where-Object { $_.NotAfter -gt (Get-Date) }
        if ($validCerts) { $passed++; $checkStatus = "Pass"; $checkDetail = "$($validCerts.Count) valid SMS certificate(s)"; Write-Log "SMS Certs: $($validCerts.Count) valid" "SUCCESS" }
        else { $checkDetail = "No valid SMS certificates"; Write-Log "SMS Certs: No valid certs" "ERROR" }
    } catch { $checkDetail = "SMS certificate store not found"; Write-Log "SMS Certs: Store not found" "ERROR" }
    $checkDetails += @{ Name = "SMS Certificates"; Category = "Security"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # DNS Resolution
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    $mpHostname = $ManagementPoint -replace '^https?://', ''
    try {
        Resolve-DnsName -Name $mpHostname -ErrorAction Stop | Out-Null
        $passed++; $checkStatus = "Pass"; $checkDetail = "Resolved $mpHostname"; Write-Log "DNS: Resolved $mpHostname" "SUCCESS"
    } catch { $checkDetail = "Cannot resolve $mpHostname"; Write-Log "DNS: Cannot resolve $mpHostname" "ERROR" }
    $checkDetails += @{ Name = "DNS Resolution"; Category = "Network"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # ccmsetup.log (check last exit code only)
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    $ccmsetupLog = "$env:SystemRoot\ccmsetup\Logs\ccmsetup.log"
    if (Test-Path $ccmsetupLog) {
        try {
            $logContent = Get-Content $ccmsetupLog -Tail 100 -ErrorAction Stop
            $exitLine = $logContent | Select-String -Pattern "CcmSetup is exiting with return code (\d+)" | Select-Object -Last 1
            if ($exitLine) {
                $exitCode = [int]$exitLine.Matches[0].Groups[1].Value
                if ($exitCode -eq 0 -or $exitCode -eq 7) { $passed++; $checkStatus = "Pass"; $checkDetail = "Last exit code $exitCode (success)"; Write-Log "ccmsetup.log: Last exit code $exitCode (success)" "SUCCESS" }
                else { $checkDetail = "Last exit code $exitCode"; Write-Log "ccmsetup.log: Last exit code $exitCode" "ERROR" }
            } else {
                $passed++; $checkStatus = "Pass"; $checkDetail = "No exit code line found in log"; Write-Log "ccmsetup.log: No exit code line found" "INFO"
            }
        } catch {
            $checkDetail = "Could not read ccmsetup.log"; Write-Log "ccmsetup.log: Could not read" "WARN"
        }
    } else {
        $passed++; $checkStatus = "Pass"; $checkDetail = "ccmsetup.log not present (normal)"; Write-Log "ccmsetup.log: Not present" "INFO"
    }
    $checkDetails += @{ Name = "ccmsetup.log Exit Code"; Category = "Client Installation"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # MP Communication (CcmMessaging.log freshness)
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    $ccmMsgLog = "$env:SystemRoot\CCM\Logs\CcmMessaging.log"
    $mpCommMaxDays = 7
    if (Test-Path $ccmMsgLog) {
        try {
            $lastLines = Get-Content $ccmMsgLog -Tail 20 -ErrorAction Stop
            $lastTimestamp = $null
            for ($i = $lastLines.Count - 1; $i -ge 0; $i--) {
                if ($lastLines[$i] -match 'time="(\d{2}:\d{2}:\d{2})\.\d+[^"]*"\s+date="(\d{2}-\d{2}-\d{4})"') {
                    $lastTimestamp = [datetime]::ParseExact("$($Matches[2]) $($Matches[1])", 'MM-dd-yyyy HH:mm:ss', $null)
                    break
                }
            }
            if ($lastTimestamp) {
                $daysSince = ((Get-Date) - $lastTimestamp).Days
                if ($daysSince -le $mpCommMaxDays) { $passed++; $checkStatus = "Pass"; $checkDetail = "Last MP activity $daysSince day(s) ago"; Write-Log "MP Communication: Last activity $daysSince day(s) ago" "SUCCESS" }
                else { $checkDetail = "No MP activity for $daysSince days (threshold: $mpCommMaxDays)"; Write-Log "MP Communication: No activity for $daysSince days (threshold: $mpCommMaxDays)" "ERROR" }
            } else { $checkDetail = "Could not parse timestamps from CcmMessaging.log"; Write-Log "MP Communication: Could not parse timestamps" "WARN" }
        } catch { $checkDetail = "Could not read CcmMessaging.log"; Write-Log "MP Communication: Could not read log" "WARN" }
    } else { $checkDetail = "CcmMessaging.log not found"; Write-Log "MP Communication: CcmMessaging.log not found" "ERROR" }
    $checkDetails += @{ Name = "MP Communication"; Category = "Network"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    # Client Assignment
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $regSite = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -Name "AssignedSiteCode" -ErrorAction Stop).AssignedSiteCode
        if ($regSite -eq $SiteCode) { $passed++; $checkStatus = "Pass"; $checkDetail = "Site code $regSite (correct)"; Write-Log "Site Assignment: $regSite (correct)" "SUCCESS" }
        else { $checkDetail = "Site code $regSite (expected $SiteCode)"; Write-Log "Site Assignment: $regSite (expected $SiteCode)" "WARN" }
    } catch {
        try {
            $result = Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName GetAssignedSite -ErrorAction Stop
            if ($result.sSiteCode -eq $SiteCode) { $passed++; $checkStatus = "Pass"; $checkDetail = "Site code $($result.sSiteCode) via WMI (correct)"; Write-Log "Site Assignment: $($result.sSiteCode) via WMI (correct)" "SUCCESS" }
            else { $checkDetail = "Site code $($result.sSiteCode) via WMI (expected $SiteCode)"; Write-Log "Site Assignment: $($result.sSiteCode) via WMI (expected $SiteCode)" "WARN" }
        } catch { $checkDetail = "Cannot determine site assignment"; Write-Log "Site Assignment: Cannot determine" "ERROR" }
    }
    $checkDetails += @{ Name = "Site Assignment"; Category = "Site Configuration"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }

    $score = [math]::Round(($passed / $total) * 100)
    Write-Log "Health Score: $($score)% ($($passed)/$($total))" "INFO"

    return @{ Score = $score; Passed = $passed; Total = $total; CheckDetails = $checkDetails }
}

# ============================================================================
#  PHASE 3 -- STOP AND KILL EVERYTHING SCCM
# ============================================================================

function Stop-AllSCCM {
    Write-Log "===== STOP AND KILL SCCM =====" "PHASE"

    foreach ($svcName in @("CcmExec", "ccmsetup", "smstsmgr", "CmRcService")) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -ne "Stopped") {
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                Write-Log "Stopped service: $svcName" "SUCCESS"
            }
        } catch {
            Write-Log "Could not stop $svcName -- $($_.Exception.Message)" "WARN"
        }
    }

    foreach ($procName in @("CcmExec", "CcmRestart", "ccmsetup", "CmRcService")) {
        try {
            $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($running) {
                $running | Stop-Process -Force -ErrorAction Stop
                Write-Log "Killed process: $procName" "SUCCESS"
            }
        } catch {
            Write-Log "Could not kill $procName -- $($_.Exception.Message)" "WARN"
        }
    }

    try {
        $svc = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name CcmExec -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled CcmExec service" "SUCCESS"
        }
    } catch {
        Write-Log "Could not disable CcmExec -- $($_.Exception.Message)" "WARN"
    }

    Start-Sleep -Seconds 3
}

# ============================================================================
#  PHASE 4 -- ATTEMPT CLEAN UNINSTALL
# ============================================================================

function Invoke-CleanUninstall {
    Write-Log "===== CLEAN UNINSTALL =====" "PHASE"

    $ccmsetupLocal = "$env:SystemRoot\ccmsetup\ccmsetup.exe"
    if (-not (Test-Path $ccmsetupLocal)) {
        Write-Log "Local ccmsetup.exe not found -- skipping uninstall" "WARN"
        return $false
    }

    Write-Log "Running ccmsetup.exe /uninstall" "INFO"
    try {
        $proc = Start-Process -FilePath $ccmsetupLocal -ArgumentList "/uninstall" -PassThru -WindowStyle Hidden
        $timeout = 300
        $elapsed = 0
        while (-not $proc.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 10
            $elapsed += 10
        }

        if (-not $proc.HasExited) {
            $proc | Stop-Process -Force
            Write-Log "Uninstall timed out after $timeout seconds" "WARN"
            return $false
        }

        $exitCode = $proc.ExitCode
        if ($exitCode -eq 0) { Write-Log "Uninstall bootstrapper exited (exit code 0)" "SUCCESS" }
        else { Write-Log "Uninstall bootstrapper exit code: $exitCode" "WARN" }

        # ccmsetup.exe /uninstall is a two-stage process: the bootstrapper exits
        # quickly but spawns a child process that does the actual uninstall.
        # Wait for ALL ccmsetup.exe processes to finish before proceeding.
        Write-Log "Waiting for background uninstall to complete..." "INFO"
        $bgTimeout = 300
        $bgElapsed = 0
        while ($bgElapsed -lt $bgTimeout) {
            $ccmProcs = Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue
            if (-not $ccmProcs) { break }
            Start-Sleep -Seconds 10
            $bgElapsed += 10
            if ($bgElapsed % 60 -eq 0) {
                Write-Log "Background uninstall still running ($bgElapsed s)..." "INFO"
            }
        }

        if ($bgElapsed -ge $bgTimeout) {
            Write-Log "Background uninstall did not finish within $bgTimeout seconds -- forcing kill" "WARN"
            Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Uninstall fully completed ($bgElapsed s wait)" "SUCCESS"
        }

        return ($exitCode -eq 0)
    } catch {
        Write-Log "Uninstall failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ============================================================================
#  PHASE 5 -- DEEP CLEAN
# ============================================================================

function Invoke-DeepClean {
    Write-Log "===== DEEP CLEAN =====" "PHASE"

    # WMI Namespace Removal -- dynamically enumerate children
    $namespacesToRemove = @()
    try {
        $children = Get-CimInstance -Namespace "root\ccm" -ClassName "__NAMESPACE" -ErrorAction SilentlyContinue
        if ($children) {
            foreach ($child in $children) {
                $namespacesToRemove += "root\ccm\$($child.Name)"
            }
        }
    } catch {
        Write-Log "Could not enumerate root\ccm children (may already be gone)" "INFO"
    }
    $namespacesToRemove += "root\ccm"
    $namespacesToRemove += "root\sms"

    $namespacesToRemove | Sort-Object { $_.Split('\').Count } -Descending | ForEach-Object {
        $ns = $_
        try {
            $parts = $ns -split '\\'
            $leaf = $parts[-1]
            $parent = ($parts[0..($parts.Count - 2)]) -join '\'
            $existing = Get-CimInstance -Namespace $parent -ClassName "__NAMESPACE" -Filter "Name='$leaf'" -ErrorAction SilentlyContinue
            if ($existing) {
                Remove-CimInstance -InputObject $existing -ErrorAction Stop
                Write-Log "Removed WMI namespace: $ns" "SUCCESS"
            }
        } catch {
            Write-Log "Could not remove WMI namespace $ns -- $($_.Exception.Message)" "WARN"
        }
    }

    # File System Cleanup
    foreach ($dir in @("$env:SystemRoot\CCM", "$env:SystemRoot\ccmsetup", "$env:SystemRoot\ccmcache")) {
        if (Test-Path $dir) {
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Log "Removed directory: $dir" "SUCCESS"
            } catch {
                Start-Sleep -Seconds 2
                try {
                    Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed directory (retry): $dir" "SUCCESS"
                } catch {
                    Write-Log "Could not remove $dir -- $($_.Exception.Message)" "WARN"
                }
            }
        }
    }

    # Individual files
    if (Test-Path "$env:SystemRoot\SMSCFG.ini") {
        Remove-Item -Path "$env:SystemRoot\SMSCFG.ini" -Force -ErrorAction SilentlyContinue
        Write-Log "Removed SMSCFG.ini" "SUCCESS"
    }

    # Wildcard cleanup
    Get-ChildItem -Path $env:SystemRoot -Filter "SMS*.mif" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; Write-Log "Removed: $($_.Name)" "SUCCESS" }
    Get-ChildItem -Path "$env:SystemRoot\Temp" -Filter "ccm*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; Write-Log "Removed: $($_.Name)" "SUCCESS" }

    # Registry Cleanup
    foreach ($key in @(
        "HKLM:\SOFTWARE\Microsoft\CCM",
        "HKLM:\SOFTWARE\Microsoft\CCMSetup",
        "HKLM:\SOFTWARE\Microsoft\SMS",
        "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates"
    )) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Log "Removed registry: $key" "SUCCESS"
            } catch {
                Write-Log "Could not remove registry $key -- $($_.Exception.Message)" "WARN"
            }
        }
    }

    # Uninstall entries
    foreach ($uninstallPath in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )) {
        try {
            Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue |
                Where-Object {
                    $dn = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                    $dn -match "Configuration Manager Client|System Center Configuration Manager"
                } | ForEach-Object {
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed uninstall entry: $($_.PSPath)" "SUCCESS"
                }
        } catch {
            Write-Log "Uninstall entry cleanup issue -- $($_.Exception.Message)" "WARN"
        }
    }

    # Certificate Cleanup
    try {
        if (Test-Path "Cert:\LocalMachine\SMS") {
            Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Remove-Item -Path $_.PSPath -Force -ErrorAction Stop
                    Write-Log "Removed SMS cert: $($_.Thumbprint)" "SUCCESS"
                }
        }
    } catch {
        Write-Log "Certificate cleanup issue -- $($_.Exception.Message)" "WARN"
    }

    # Scheduled Task Cleanup (SCCM's own tasks, NOT our healing task)
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.TaskName -match "Configuration Manager|SCCM|CCM" -or $_.TaskPath -match "Microsoft\\Configuration Manager") -and
                $_.TaskName -ne $ScheduledTaskName
            } |
            ForEach-Object {
                Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
                Write-Log "Removed scheduled task: $($_.TaskPath)$($_.TaskName)" "SUCCESS"
            }
    } catch {
        Write-Log "Scheduled task cleanup issue -- $($_.Exception.Message)" "WARN"
    }

    Write-Log "Deep clean complete" "SUCCESS"
}

# ============================================================================
#  PHASE 6 -- PREREQUISITES REPAIR
# ============================================================================

function Repair-Prerequisites {
    Write-Log "===== PREREQUISITES REPAIR =====" "PHASE"

    # WMI
    try {
        $wmi = Get-Service -Name Winmgmt -ErrorAction Stop
        if ($wmi.Status -ne "Running") {
            Start-Service -Name Winmgmt -ErrorAction Stop
            Write-Log "Started WMI service" "SUCCESS"
        }
    } catch {
        Write-Log "Could not start WMI -- $($_.Exception.Message)" "ERROR"
    }

    try { $null = & winmgmt /resyncperf 2>&1; Write-Log "winmgmt /resyncperf done" "SUCCESS" }
    catch { Write-Log "winmgmt /resyncperf failed" "WARN" }

    # Check if WMI is fundamentally broken
    $wmiCorrupt = $false
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Out-Null
        Write-Log "WMI self-test (Win32_OperatingSystem): OK" "SUCCESS"
    } catch {
        $wmiCorrupt = $true
        Write-Log "WMI self-test FAILED -- will perform bulk MOF recompilation" "WARN"
    }

    $wbemPath = "$env:SystemRoot\System32\wbem"

    if ($wmiCorrupt) {
        # Bulk recompile all MOF/MFL files (except uninstall MOFs) to rebuild WMI repository
        Write-Log "Starting bulk MOF recompilation from $wbemPath ..." "INFO"
        try {
            $allMofs = Get-ChildItem -Path "$wbemPath\*" -Include "*.mof","*.mfl" -File -ErrorAction Stop |
                Where-Object { $_.Name -notmatch "uninstall" }
            $compiled = 0
            foreach ($mof in $allMofs) {
                try { $null = & mofcomp $mof.FullName 2>&1; $compiled++ } catch { }
            }
            Write-Log "Bulk MOF recompilation complete: $compiled of $($allMofs.Count) files" "SUCCESS"
        } catch {
            Write-Log "Bulk MOF recompilation error: $($_.Exception.Message)" "WARN"
        }
    } else {
        # Selective MOF recompilation
        $mofFiles = @(
            "cimwin32.mof", "cimwin32.mfl", "win32_encryptablevolume.mof",
            "rsop.mof", "rsop.mfl", "cmprov.mof", "cmprov.mfl",
            "msi.mof", "tscfgwmi.mof", "policman.mof", "policman.mfl", "sr.mof"
        )
        foreach ($mof in $mofFiles) {
            $mofPath = Join-Path $wbemPath $mof
            if (Test-Path $mofPath) {
                try {
                    $null = & mofcomp $mofPath 2>&1
                    Write-Log "Re-compiled MOF: $mof" "SUCCESS"
                } catch {
                    Write-Log "mofcomp failed for $mof" "WARN"
                }
            }
        }
    }

    # Microsoft Policy Platform ExtendedStatus.mof
    $extStatusMof = "$env:ProgramFiles\Microsoft Policy Platform\ExtendedStatus.mof"
    if (Test-Path $extStatusMof) {
        try {
            $null = & mofcomp $extStatusMof 2>&1
            Write-Log "Re-compiled MOF: ExtendedStatus.mof (Policy Platform)" "SUCCESS"
        } catch {
            Write-Log "mofcomp failed for ExtendedStatus.mof -- $($_.Exception.Message)" "WARN"
        }
    }

    # Service repair
    try { Set-Service -Name BITS -StartupType Manual -ErrorAction Stop; Start-Service -Name BITS -ErrorAction SilentlyContinue; Write-Log "BITS repaired" "SUCCESS" }
    catch { Write-Log "BITS repair issue -- $($_.Exception.Message)" "WARN" }

    try { Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop; Start-Service -Name wuauserv -ErrorAction SilentlyContinue; Write-Log "WU repaired" "SUCCESS" }
    catch { Write-Log "WU repair issue -- $($_.Exception.Message)" "WARN" }

    try {
        $crypto = Get-Service -Name CryptSvc -ErrorAction Stop
        if ($crypto.Status -ne "Running") { Start-Service -Name CryptSvc -ErrorAction Stop }
        Write-Log "CryptSvc running" "SUCCESS"
    } catch { Write-Log "CryptSvc issue -- $($_.Exception.Message)" "WARN" }

    # DLL re-registration
    foreach ($dll in @("qmgr.dll", "qmgrprxy.dll")) {
        try { $null = & regsvr32 /s "$env:SystemRoot\System32\$dll" 2>&1; Write-Log "Re-registered: $dll" "SUCCESS" }
        catch { Write-Log "Could not register $dll" "WARN" }
    }

    $wuDlls = @("wuaueng.dll","wuapi.dll","wups.dll","wups2.dll","wuwebv.dll","wucltux.dll","wudriver.dll","atl.dll","msxml3.dll","msxml6.dll")
    foreach ($dll in $wuDlls) {
        $dllPath = "$env:SystemRoot\System32\$dll"
        if (Test-Path $dllPath) {
            try { $null = & regsvr32 /s $dllPath 2>&1; Write-Log "Re-registered: $dll" "SUCCESS" }
            catch { Write-Log "Could not register $dll" "WARN" }
        }
    }

    # Registry.pol corruption check
    $polCorruptFound = $false
    foreach ($polScope in @("Machine", "User")) {
        $polPath = "$env:SystemRoot\System32\GroupPolicy\$polScope\registry.pol"
        if (Test-Path $polPath) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($polPath)
                $valid = $true
                $expectedHeader = @(0x50, 0x52, 0x65, 0x67, 0x01, 0x00, 0x00, 0x00)
                if ($bytes.Length -lt 8) {
                    $valid = $false
                } else {
                    for ($i = 0; $i -lt 8; $i++) {
                        if ($bytes[$i] -ne $expectedHeader[$i]) { $valid = $false; break }
                    }
                }

                if ($valid) {
                    Write-Log "registry.pol ($polScope): Valid (PReg header OK, $($bytes.Length) bytes)" "SUCCESS"
                } else {
                    Write-Log "registry.pol ($polScope): CORRUPT -- removing to allow GP rebuild" "WARN"
                    Remove-Item -Path $polPath -Force -ErrorAction Stop
                    Write-Log "registry.pol ($polScope) removed. Will be rebuilt on next gpupdate." "SUCCESS"
                    $polCorruptFound = $true
                }
            } catch {
                Write-Log "registry.pol ($polScope) check error: $($_.Exception.Message)" "WARN"
            }
        } else {
            Write-Log "registry.pol ($polScope): Not present (will be created on next gpupdate)" "INFO"
        }
    }

    if ($polCorruptFound) {
        try {
            $null = & gpupdate /force /target:computer 2>&1
            Write-Log "Triggered gpupdate /force to rebuild registry.pol" "INFO"
        } catch {
            Write-Log "gpupdate failed: $($_.Exception.Message)" "WARN"
        }
    }

    Write-Log "Prerequisites repair complete" "SUCCESS"
}

# ============================================================================
#  PHASE 7 -- CLIENT REINSTALLATION
# ============================================================================

function Install-SCCMClient {
    Write-Log "===== CLIENT REINSTALLATION =====" "PHASE"

    $stagingDir = "$LocalStagingDir\ccmsetup_healing"
    $stagingExe = Join-Path $stagingDir "ccmsetup.exe"
    $sourceExe  = Join-Path $ClientSource "ccmsetup.exe"

    if (-not (Test-Path $stagingDir)) {
        New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
    }

    try {
        Copy-Item -Path $sourceExe -Destination $stagingExe -Force -ErrorAction Stop
        # Copy additional source files
        Get-ChildItem -Path $ClientSource -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "ccmsetup.exe" } |
            ForEach-Object { Copy-Item -Path $_.FullName -Destination $stagingDir -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Log "Client files staged to $stagingDir" "SUCCESS"
    } catch {
        Write-Log "Failed to copy client source -- $($_.Exception.Message)" "ERROR"
        return $false
    }

    $mpHostnameForSuffix = $ManagementPoint -replace '^https?://', ''
    $dnsSuffix = ($mpHostnameForSuffix -split '\.', 2)[1]
    if (-not $dnsSuffix) { $dnsSuffix = (Get-CimInstance Win32_ComputerSystem).Domain }

    $installArgs = "/mp:$ManagementPoint /logon /usepkicert /allowmetered /nocrlcheck SMSSITECODE=$SiteCode SMSMP=$mpHostnameForSuffix DNSSUFFIX=$dnsSuffix RESETKEYINFORMATION=TRUE"

    Write-Log "Running: ccmsetup.exe $installArgs" "INFO"

    try {
        $proc = Start-Process -FilePath $stagingExe -ArgumentList $installArgs -PassThru -WindowStyle Hidden
        $timeout = 900  # 15 minutes
        $elapsed = 0

        while (-not $proc.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 15
            $elapsed += 15
            if ($elapsed % 60 -eq 0) {
                Write-Log "Installation in progress ($($elapsed)s / $($timeout)s max)" "INFO"
            }
        }

        if (-not $proc.HasExited) {
            Write-Log "Installation timed out after $timeout seconds" "ERROR"
            return $false
        }

        $exitCode = $proc.ExitCode

        # Clean up staging directory
        try {
            Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned up staging directory: $stagingDir" "INFO"
        } catch { }

        switch ($exitCode) {
            0       { Write-Log "ccmsetup completed (exit code 0)" "SUCCESS"; return $true }
            7       { Write-Log "ccmsetup exit code 7 -- reboot required" "WARN"; return $true }
            default { Write-Log "ccmsetup exit code $exitCode" "ERROR"; return $false }
        }
    } catch {
        Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ============================================================================
#  PHASE 8 -- POST-INSTALL VERIFICATION
# ============================================================================

function Test-PostInstall {
    Write-Log "===== POST-INSTALL VERIFICATION =====" "PHASE"
    Write-Log "Waiting 60 seconds for services to stabilize..." "INFO"
    Start-Sleep -Seconds 60

    $passed = 0
    $total = 0
    $clientVersion = "Unknown"

    # CcmExec service
    $total++
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") { $passed++; Write-Log "Post: CcmExec Running" "SUCCESS" }
        else {
            Start-Service -Name CcmExec -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
            $svc.Refresh()
            if ($svc.Status -eq "Running") { $passed++; Write-Log "Post: CcmExec started manually" "SUCCESS" }
            else { Write-Log "Post: CcmExec $($svc.Status)" "ERROR" }
        }
    } catch { Write-Log "Post: CcmExec not found" "ERROR" }

    # Client version
    $total++
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
        $clientVersion = $client.ClientVersion
        $passed++; Write-Log "Post: Client version $clientVersion" "SUCCESS"
    } catch { Write-Log "Post: Cannot query client version" "ERROR" }

    # Site assignment
    $total++
    try {
        $assignment = Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName GetAssignedSite -ErrorAction Stop
        $site = $assignment.sSiteCode
        if ($site -eq $SiteCode) { $passed++; Write-Log "Post: Site $site (correct)" "SUCCESS" }
        else { Write-Log "Post: Site $site (expected $SiteCode)" "WARN" }
    } catch { Write-Log "Post: Cannot determine site" "ERROR" }

    # Trigger machine policy
    $total++
    try {
        Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{
            sScheduleID = "{00000000-0000-0000-0000-000000000021}"
        } -ErrorAction Stop
        $passed++; Write-Log "Post: Machine policy triggered" "SUCCESS"
    } catch { Write-Log "Post: Could not trigger policy -- $($_.Exception.Message)" "ERROR" }

    # Trigger hardware inventory
    try {
        Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{
            sScheduleID = "{00000000-0000-0000-0000-000000000001}"
        } -ErrorAction SilentlyContinue
        Write-Log "Post: Hardware inventory triggered" "INFO"
    } catch { Write-Log "Post: Could not trigger HW inventory" "WARN" }

    $score = [math]::Round(($passed / $total) * 100)
    Write-Log "Post-install score: $($score)% ($($passed)/$($total))" "INFO"

    return @{ Score = $score; Passed = $passed; Total = $total; ClientVersion = $clientVersion }
}

# ============================================================================
#  AUTO-REMOVE -- UNREGISTER SELF
# ============================================================================

function Unregister-HealingTask {
    Write-Log "Client healthy for $ConsecutiveSuccessThreshold consecutive checks. Auto-removing scheduled task." "SUCCESS"

    try {
        $task = Get-ScheduledTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $ScheduledTaskName -TaskPath $ScheduledTaskPath -Confirm:$false -ErrorAction Stop
            Write-Log "Scheduled task '$ScheduledTaskName' unregistered successfully" "SUCCESS"
        } else {
            Write-Log "Scheduled task '$ScheduledTaskName' not found (already removed?)" "WARN"
        }
    } catch {
        Write-Log "Could not unregister scheduled task '$ScheduledTaskName' -- $($_.Exception.Message)" "WARN"
        Write-Log "Task may need manual removal from Task Scheduler" "WARN"
    }
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

# Initialize log
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

# Start transcript as safety net
$transcriptPath = "$LocalStagingDir\SCCMHealing-Task-Transcript.log"
try { Start-Transcript -Path $transcriptPath -Append -ErrorAction SilentlyContinue } catch {}

$startTime = Get-Date
Write-Log "========================================" "PHASE"
Write-Log "SCCM Client Healing (Task) started on $($env:COMPUTERNAME) at $startTime" "INFO"
Write-Log "Config: SiteCode=$SiteCode, MP=$ManagementPoint, Source=$ClientSource" "INFO"
Write-Log "Config: Threshold=$ConsecutiveSuccessThreshold, TaskName=$ScheduledTaskName" "INFO"

# Log system info
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
    Write-Log "OS: $($os.Caption) $($os.Version)" "INFO"
    Write-Log "Domain: $($cs.Domain)" "INFO"
    Write-Log "IP: $ip" "INFO"
    Write-Log "Last Boot: $($os.LastBootUpTime)" "INFO"
} catch {
    Write-Log "Could not collect system info: $($_.Exception.Message)" "WARN"
}

# Read state file
$state = Read-State
$state.TotalRuns++

# Check if we've already reached the consecutive success threshold
if ($state.ConsecutiveSuccesses -ge $ConsecutiveSuccessThreshold) {
    Write-Log "Already at $($state.ConsecutiveSuccesses) consecutive successes (threshold: $ConsecutiveSuccessThreshold)" "SUCCESS"
    Unregister-HealingTask
    $state.LastCheckTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-State -State $state
    $elapsed = (Get-Date) - $startTime
    Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "========================================" "PHASE"
    Copy-LogToNetworkShare
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 0
}

# Run health check
$healthResult = Get-SCCMHealthScore

if ($healthResult.Score -eq 100) {
    # Client is healthy -- increment consecutive successes
    $state.ConsecutiveSuccesses++
    $state.LastCheckTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $state.LastHealthScore = $healthResult.Score

    # Get client version for state
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue
        if ($client) { $state.ClientVersion = $client.ClientVersion }
    } catch {}

    Write-Log "Client healthy. Consecutive successes: $($state.ConsecutiveSuccesses) of $ConsecutiveSuccessThreshold required" "SUCCESS"
    Write-State -State $state
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 0 -RemediationResult "None" -ClientVersion $(if ($state.ClientVersion) { $state.ClientVersion } else { "" })
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 0 -RemediationResult "None"

    # Check if this success pushes us over the threshold
    if ($state.ConsecutiveSuccesses -ge $ConsecutiveSuccessThreshold) {
        Unregister-HealingTask
    }

    $elapsed = (Get-Date) - $startTime
    Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "========================================" "PHASE"
    Copy-LogToNetworkShare
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 0
}

# Client is NOT healthy -- reset consecutive successes and heal
Write-Log "Health score $($healthResult.Score)% -- healing required (resetting consecutive successes to 0)" "WARN"
$state.ConsecutiveSuccesses = 0
$state.LastCheckTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$state.LastHealthScore = $healthResult.Score

# Wait for network
if (-not (Wait-ForNetwork)) {
    Write-Log "Network unavailable. Will retry on next scheduled run." "ERROR"
    Write-State -State $state
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 0 -RemediationResult "Network unavailable - healing deferred" -ClientVersion ""
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 0 -RemediationResult "Network unavailable - healing deferred"
    $elapsed = (Get-Date) - $startTime
    Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "========================================" "PHASE"
    Copy-LogToNetworkShare
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 1
}

# Execute healing phases
$state.TotalHeals++
$state.LastHealTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

try { Stop-AllSCCM } catch { Write-Log "Stop phase error: $($_.Exception.Message)" "ERROR" }

try { Invoke-CleanUninstall } catch { Write-Log "Uninstall phase error: $($_.Exception.Message)" "ERROR" }

try { Invoke-DeepClean } catch { Write-Log "Deep clean phase error: $($_.Exception.Message)" "ERROR" }

try { Repair-Prerequisites } catch { Write-Log "Prerequisites phase error: $($_.Exception.Message)" "ERROR" }

$installSuccess = $false
try { $installSuccess = Install-SCCMClient } catch { Write-Log "Install phase error: $($_.Exception.Message)" "ERROR" }

if ($installSuccess) {
    try {
        $afterHealth = Test-PostInstall

        if ($afterHealth.Score -ge 75) {
            Write-Log "HEALING SUCCEEDED -- Score: $($afterHealth.Score)%" "SUCCESS"
            $state.ConsecutiveSuccesses = 1
            $state.LastHealthScore = $afterHealth.Score
            $state.ClientVersion = $afterHealth.ClientVersion
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Full client rebuild succeeded" -ClientVersion $(if ($afterHealth.ClientVersion) { $afterHealth.ClientVersion } else { "" })
            Write-HealthHistory -HealthScore $afterHealth.Score -RemediationTier 3 -RemediationResult "Full client rebuild succeeded"
        } else {
            Write-Log "HEALING PARTIAL -- Score: $($afterHealth.Score)%. Will retry on next scheduled run." "WARN"
            $state.ConsecutiveSuccesses = 0
            $state.LastHealthScore = $afterHealth.Score
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Full client rebuild - partial recovery" -ClientVersion ""
            Write-HealthHistory -HealthScore $afterHealth.Score -RemediationTier 3 -RemediationResult "Full client rebuild - partial recovery"
        }
    } catch {
        Write-Log "Post-install verification error: $($_.Exception.Message)" "ERROR"
        $state.ConsecutiveSuccesses = 0
        Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Post-install verification failed" -ClientVersion ""
        Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 3 -RemediationResult "Post-install verification failed"
    }
} else {
    Write-Log "INSTALLATION FAILED. Will retry on next scheduled run." "ERROR"
    $state.ConsecutiveSuccesses = 0
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Client installation failed" -ClientVersion ""
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 3 -RemediationResult "Client installation failed"
}

Write-State -State $state

$elapsed = (Get-Date) - $startTime
Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
Write-Log "========================================" "PHASE"

Copy-LogToNetworkShare
try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
