<#
.SYNOPSIS
    SCCM Client Healing Script -- Interactive Edition

.DESCRIPTION
    Deep-cleans and reinstalls the SCCM/ConfigMgr client on workstations with
    broken clients that resist normal push install / uninstall-reinstall.
    Designed to run as SYSTEM via remote PowerShell or scheduled task.

    Phases:
      1. Pre-Flight Checks (network, MP connectivity)
      2. Diagnostic Assessment (health score across 11 checks)
      3. Stop and Kill all SCCM processes/services
      4. Attempt Clean Uninstall via ccmsetup /uninstall
      5. Deep Clean (WMI namespaces, files, registry, certs, tasks)
      6. Prerequisites Repair (WMI MOFs, BITS, WU, Crypto DLLs)
      7. Client Reinstallation from network share
      8. Post-Install Verification
      9. Summary Report

.PARAMETER SiteCode
    SCCM site code (e.g. "ABC")

.PARAMETER ManagementPoint
    FQDN of the SCCM management point

.PARAMETER ClientSource
    UNC path to the folder containing ccmsetup.exe

.PARAMETER LogPath
    Full path for the healing log file

.PARAMETER ForceReinstall
    Skip health check -- go straight to nuke-and-pave

.PARAMETER DiagnosticsOnly
    Run Phases 1-2 only (no changes). Safe to run on any machine.

.EXAMPLE
    .\ClientHealing.ps1 -SiteCode "ABC" -ManagementPoint "sccm.contoso.com" -ClientSource "\\sccm\Client$"

.EXAMPLE
    .\ClientHealing.ps1 -DiagnosticsOnly

.NOTES
    Run from an elevated PowerShell session or via remote PS.
    Requires network access to the client source share and management point.
#>

[CmdletBinding()]
param(
    [string]$SiteCode        = "YOURSITECODE",
    [string]$ManagementPoint = "YOURMP.domain.com",
    [string]$ClientSource    = "\\SERVER\Share\Client",
    [string]$LogPath         = "$env:SystemRoot\Temp\SCCMHealing.log",
    [switch]$ForceReinstall,
    [switch]$DiagnosticsOnly
)

# ===== NETWORK LOG SHARE - EDIT THIS VALUE ===================================
$NetworkLogShare = "\\SERVER\Share\SCCMLogs"   # UNC path -- logs deposited to $NetworkLogShare\<ComputerName>\
# ==============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
#  LOGGING AND OUTPUT HELPERS
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

    switch ($Level) {
        "ERROR"   { Write-Host "  [FAIL] $Message" -ForegroundColor Red }
        "WARN"    { Write-Host "  [WARN] $Message" -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "  [ OK ] $Message" -ForegroundColor Green }
        "PHASE"   { } # handled by Write-Phase
        default   { Write-Host "  [INFO] $Message" -ForegroundColor Cyan }
    }
}

function Write-Phase {
    param([int]$Number, [string]$Title)
    $line = "=" * 70
    Write-Host ""
    Write-Host "  $line" -ForegroundColor White
    Write-Host "  PHASE $Number - $Title" -ForegroundColor White
    Write-Host "  $line" -ForegroundColor White
    Write-Log "===== PHASE $Number - $Title =====" "PHASE"
}

function Copy-LogToNetworkShare {
    if (-not $NetworkLogShare -or $NetworkLogShare -match '\\\\SERVER\\Share') { return }
    try {
        $destDir = Join-Path $NetworkLogShare $env:COMPUTERNAME
        if (-not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path $LogPath) {
            Copy-Item -Path $LogPath -Destination $destDir -Force -ErrorAction Stop
            Write-Host "  [INFO] Log copied to $destDir" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "  [WARN] Failed to copy log to network share: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n  --- $Title ---" -ForegroundColor Magenta
    Write-Log "--- $Title ---" "INFO"
}

# ============================================================================
#  PHASE 1 -- PRE-FLIGHT CHECKS
# ============================================================================

function Invoke-PreFlightChecks {
    Write-Phase 1 "Pre-Flight Checks"

    # System info
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" } | Select-Object -First 1).IPAddress
    $lastBoot = $os.LastBootUpTime

    Write-Log "Hostname:    $($env:COMPUTERNAME)" "INFO"
    Write-Log "OS:          $($os.Caption) $($os.Version)" "INFO"
    Write-Log "Domain:      $($cs.Domain)" "INFO"
    Write-Log "IP Address:  $ip" "INFO"
    Write-Log "Last Boot:   $lastBoot" "INFO"

    # Validate client source
    if (Test-Path (Join-Path $ClientSource "ccmsetup.exe")) {
        Write-Log "Client source validated: $ClientSource\ccmsetup.exe" "SUCCESS"
    } else {
        Write-Log "Cannot find ccmsetup.exe at $ClientSource" "ERROR"
        if (-not $DiagnosticsOnly) {
            return $false
        }
    }

    # Test MP connectivity
    $mpReachable = $false
    try {
        $ping = Test-Connection -ComputerName $ManagementPoint -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Log "Management Point responds to ping: $ManagementPoint" "SUCCESS"
        } else {
            Write-Log "Management Point does not respond to ping (may be blocked by firewall)" "WARN"
        }
    } catch {
        Write-Log "Ping test failed: $_" "WARN"
    }

    # HTTP connectivity to MP
    foreach ($port in @(443, 80)) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ConnectAsync($ManagementPoint, $port).Wait(3000) | Out-Null
            if ($tcp.Connected) {
                Write-Log "TCP connection to ${ManagementPoint}:$port succeeded" "SUCCESS"
                $mpReachable = $true
                $tcp.Close()
                break
            }
            $tcp.Close()
        } catch {
            Write-Log "TCP connection to ${ManagementPoint}:$port failed" "WARN"
        }
    }

    if (-not $mpReachable -and -not $DiagnosticsOnly) {
        Write-Log "Cannot reach Management Point on port 80 or 443. Proceeding anyway." "WARN"
    }

    return $true
}

# ============================================================================
#  PHASE 2 -- DIAGNOSTIC ASSESSMENT
# ============================================================================

function Get-SCCMHealthScore {
    Write-Phase 2 "Diagnostic Assessment"

    $checks = @{}
    $passed = 0
    $total  = 0

    # --- CcmExec Service ---
    $total++
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            $checks["CcmExec Service"] = "PASS - Running"
            $passed++
            Write-Log "CcmExec Service: Running" "SUCCESS"
        } else {
            $checks["CcmExec Service"] = "FAIL - Status: $($svc.Status)"
            Write-Log "CcmExec Service: $($svc.Status)" "ERROR"
        }
    } catch {
        $checks["CcmExec Service"] = "FAIL - Service not found"
        Write-Log "CcmExec Service: Not found" "ERROR"
    }

    # --- Client Version ---
    $total++
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
        $ver = $client.ClientVersion
        $checks["Client Version"] = "PASS - $ver"
        $passed++
        Write-Log "Client Version: $ver" "SUCCESS"
    } catch {
        $checks["Client Version"] = "FAIL - Cannot query root\ccm"
        Write-Log "Client Version: Cannot query" "ERROR"
    }

    # --- WMI Health (root\cimv2) ---
    $total++
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Out-Null
        $checks["WMI Health"] = "PASS"
        $passed++
        Write-Log "WMI Health (root\cimv2): OK" "SUCCESS"
    } catch {
        $checks["WMI Health"] = "FAIL - root\cimv2 query failed"
        Write-Log "WMI Health: FAILED" "ERROR"
    }

    # --- SCCM WMI Namespaces ---
    $total++
    $nsOk = $true
    foreach ($ns in @("root\ccm", "root\sms")) {
        try {
            Get-CimInstance -Namespace $ns -ClassName "__NAMESPACE" -ErrorAction Stop | Out-Null
        } catch {
            $nsOk = $false
        }
    }
    if ($nsOk) {
        $checks["SCCM WMI Namespaces"] = "PASS"
        $passed++
        Write-Log "SCCM WMI Namespaces (root\ccm, root\sms): Present" "SUCCESS"
    } else {
        $checks["SCCM WMI Namespaces"] = "FAIL - One or more missing"
        Write-Log "SCCM WMI Namespaces: Missing" "ERROR"
    }

    # --- BITS Service ---
    $total++
    try {
        $bits = Get-Service -Name BITS -ErrorAction Stop
        if ($bits.Status -eq "Running" -or $bits.StartType -ne "Disabled") {
            $checks["BITS Service"] = "PASS - $($bits.Status) / $($bits.StartType)"
            $passed++
            Write-Log "BITS Service: $($bits.Status) / $($bits.StartType)" "SUCCESS"
        } else {
            $checks["BITS Service"] = "FAIL - Disabled"
            Write-Log "BITS Service: Disabled" "ERROR"
        }
    } catch {
        $checks["BITS Service"] = "FAIL - Not found"
        Write-Log "BITS Service: Not found" "ERROR"
    }

    # --- Windows Update Service ---
    $total++
    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        if ($wu.StartType -ne "Disabled") {
            $checks["Windows Update Service"] = "PASS - $($wu.Status) / $($wu.StartType)"
            $passed++
            Write-Log "Windows Update Service: $($wu.Status) / $($wu.StartType)" "SUCCESS"
        } else {
            $checks["Windows Update Service"] = "FAIL - Disabled"
            Write-Log "Windows Update Service: Disabled" "ERROR"
        }
    } catch {
        $checks["Windows Update Service"] = "FAIL - Not found"
        Write-Log "Windows Update Service: Not found" "ERROR"
    }

    # --- Cryptographic Services ---
    $total++
    try {
        $crypto = Get-Service -Name CryptSvc -ErrorAction Stop
        if ($crypto.Status -eq "Running") {
            $checks["Cryptographic Services"] = "PASS - Running"
            $passed++
            Write-Log "Cryptographic Services: Running" "SUCCESS"
        } else {
            $checks["Cryptographic Services"] = "FAIL - $($crypto.Status)"
            Write-Log "Cryptographic Services: $($crypto.Status)" "ERROR"
        }
    } catch {
        $checks["Cryptographic Services"] = "FAIL - Not found"
        Write-Log "Cryptographic Services: Not found" "ERROR"
    }

    # --- SCCM Certificate ---
    $total++
    try {
        $smsCerts = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction Stop
        $validCerts = $smsCerts | Where-Object { $_.NotAfter -gt (Get-Date) }
        if ($validCerts) {
            $checks["SCCM Certificate"] = "PASS - $($validCerts.Count) valid cert(s)"
            $passed++
            Write-Log "SCCM Certificate: $($validCerts.Count) valid" "SUCCESS"
        } else {
            $checks["SCCM Certificate"] = "FAIL - No valid certificates"
            Write-Log "SCCM Certificate: No valid certs" "ERROR"
        }
    } catch {
        $checks["SCCM Certificate"] = "FAIL - SMS cert store not found"
        Write-Log "SCCM Certificate: Store not found" "ERROR"
    }

    # --- DNS Resolution ---
    $total++
    try {
        $dns = Resolve-DnsName -Name $ManagementPoint -ErrorAction Stop
        $checks["DNS Resolution"] = "PASS - $($dns[0].IPAddress)"
        $passed++
        Write-Log "DNS Resolution: $ManagementPoint -> $($dns[0].IPAddress)" "SUCCESS"
    } catch {
        $checks["DNS Resolution"] = "FAIL - Cannot resolve $ManagementPoint"
        Write-Log "DNS Resolution: FAILED for $ManagementPoint" "ERROR"
    }

    # --- ccmsetup.log Analysis ---
    $total++
    $ccmsetupLog = "$env:SystemRoot\ccmsetup\Logs\ccmsetup.log"
    if (Test-Path $ccmsetupLog) {
        try {
            $logContent = Get-Content $ccmsetupLog -Tail 50 -ErrorAction Stop
            $errorLines = $logContent | Select-String -Pattern "error|fail|0x8" -AllMatches
            if ($errorLines.Count -eq 0) {
                $checks["ccmsetup.log"] = "PASS - No recent errors"
                $passed++
                Write-Log "ccmsetup.log: No recent errors" "SUCCESS"
            } else {
                $lastErr = ($errorLines | Select-Object -Last 1).Line.Trim()
                $checks["ccmsetup.log"] = "WARN - $lastErr"
                Write-Log "ccmsetup.log: Errors found -- $lastErr" "WARN"
            }
        } catch {
            $checks["ccmsetup.log"] = "WARN - Could not read log"
            Write-Log "ccmsetup.log: Could not read" "WARN"
        }
    } else {
        $checks["ccmsetup.log"] = "INFO - Log not present"
        Write-Log "ccmsetup.log: Not present" "INFO"
        $passed++ # Not necessarily a failure
    }

    # --- Client Site Assignment ---
    $total++
    $assignedSite = $null
    # Try Invoke-CimMethod first (correct API for SMS_Client.GetAssignedSite)
    try {
        $result = Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName GetAssignedSite -ErrorAction Stop
        $assignedSite = $result.sSiteCode
    } catch {
        # Fallback: read from registry
        try {
            $assignedSite = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -Name "AssignedSiteCode" -ErrorAction Stop).AssignedSiteCode
        } catch { }
    }

    if ($assignedSite -eq $SiteCode) {
        $checks["Client Assignment"] = "PASS - Assigned to $assignedSite"
        $passed++
        Write-Log "Client Assignment: Correct site $assignedSite" "SUCCESS"
    } elseif ($assignedSite) {
        $checks["Client Assignment"] = "WARN - Assigned to $assignedSite (expected $SiteCode)"
        Write-Log "Client Assignment: Wrong site $assignedSite (expected $SiteCode)" "WARN"
    } else {
        $checks["Client Assignment"] = "FAIL - Not assigned"
        Write-Log "Client Assignment: Not assigned" "ERROR"
    }

    # --- Summary ---
    $score = [math]::Round(($passed / $total) * 100)
    $pct = "$($score)%"
    $detail = "$($passed)/$($total) checks passed"
    Write-Host ""
    $scoreColor = if ($score -ge 90) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
    Write-Host "  Health Score: $pct ($detail)" -ForegroundColor $scoreColor
    Write-Log "Health Score: $pct ($detail)" "INFO"

    Write-Host ""
    Write-Host "  Check                      Result" -ForegroundColor White
    Write-Host "  $('-' * 55)" -ForegroundColor Gray
    foreach ($check in $checks.GetEnumerator() | Sort-Object Name) {
        $color = if ($check.Value -match "^PASS") { "Green" }
                 elseif ($check.Value -match "^WARN|^INFO") { "Yellow" }
                 else { "Red" }
        $name = $check.Key.PadRight(28)
        Write-Host "  $name $($check.Value)" -ForegroundColor $color
    }

    return @{
        Score  = $score
        Passed = $passed
        Total  = $total
        Checks = $checks
    }
}

# ============================================================================
#  PHASE 3 -- STOP AND KILL EVERYTHING SCCM
# ============================================================================

function Stop-AllSCCM {
    Write-Phase 3 "Stop and Kill Everything SCCM"

    # Stop services
    foreach ($svcName in @("CcmExec", "ccmsetup", "smstsmgr", "CmRcService")) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -ne "Stopped") {
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                    Write-Log "Stopped service: $svcName" "SUCCESS"
                } else {
                    Write-Log "Service already stopped: $svcName" "INFO"
                }
            } else {
                Write-Log "Service not found (OK): $svcName" "INFO"
            }
        } catch {
            Write-Log "Could not stop service $svcName -- $($_.Exception.Message)" "WARN"
        }
    }

    # Kill processes
    foreach ($procName in @("CcmExec", "CcmRestart", "ccmsetup", "CmRcService")) {
        try {
            $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($running) {
                $running | Stop-Process -Force -ErrorAction Stop
                Write-Log "Killed process: $procName" "SUCCESS"
            }
        } catch {
            Write-Log "Could not kill process $procName -- $($_.Exception.Message)" "WARN"
        }
    }

    # Disable CcmExec to prevent auto-restart during cleanup
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name CcmExec -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled CcmExec service (will re-enable after reinstall)" "SUCCESS"
        }
    } catch {
        Write-Log "Could not disable CcmExec -- $($_.Exception.Message)" "WARN"
    }

    # Brief pause to let handles release
    Start-Sleep -Seconds 3
}

# ============================================================================
#  PHASE 4 -- ATTEMPT CLEAN UNINSTALL
# ============================================================================

function Invoke-CleanUninstall {
    Write-Phase 4 "Attempt Clean Uninstall"

    $ccmsetupLocal = "$env:SystemRoot\ccmsetup\ccmsetup.exe"

    if (-not (Test-Path $ccmsetupLocal)) {
        Write-Log "Local ccmsetup.exe not found at $ccmsetupLocal -- skipping uninstall step" "WARN"
        return $false
    }

    Write-Log "Running ccmsetup.exe /uninstall ..." "INFO"
    try {
        $proc = Start-Process -FilePath $ccmsetupLocal -ArgumentList "/uninstall" -PassThru -NoNewWindow
        $timeout = 300  # 5 minutes
        $elapsed = 0
        while (-not $proc.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 10
            $elapsed += 10
            $progressMsg = "  [....] Uninstall in progress ($($elapsed)s / $($timeout)s max)..."
            Write-Host $progressMsg -ForegroundColor Gray
        }

        if (-not $proc.HasExited) {
            $proc | Stop-Process -Force
            Write-Log "Uninstall timed out after $timeout seconds -- killed process" "WARN"
            return $false
        }

        $exitCode = $proc.ExitCode
        if ($exitCode -eq 0) {
            Write-Log "Uninstall bootstrapper exited (exit code 0)" "SUCCESS"
        } else {
            Write-Log "Uninstall bootstrapper exit code: $exitCode" "WARN"
        }

        # ccmsetup.exe /uninstall is a two-stage process: the bootstrapper exits
        # quickly but spawns a child process that does the actual uninstall.
        # Wait for ALL ccmsetup.exe processes to finish before proceeding.
        Write-Log "Waiting for background uninstall to complete..." "INFO"
        Write-Host "  [....] Waiting for background uninstall to complete..." -ForegroundColor Gray
        $bgTimeout = 300
        $bgElapsed = 0
        while ($bgElapsed -lt $bgTimeout) {
            $ccmProcs = Get-Process -Name "ccmsetup" -ErrorAction SilentlyContinue
            if (-not $ccmProcs) { break }
            Start-Sleep -Seconds 10
            $bgElapsed += 10
            if ($bgElapsed % 60 -eq 0) {
                Write-Host "  [....] Background uninstall still running ($bgElapsed s)..." -ForegroundColor Gray
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
#  PHASE 5 -- DEEP CLEAN (NUCLEAR CLEANUP)
# ============================================================================

function Invoke-DeepClean {
    Write-Phase 5 "Deep Clean (Nuclear Cleanup)"

    # --- WMI Namespace Removal ---
    Write-SectionHeader "WMI Namespace Removal"

    # Dynamically enumerate all child namespaces under root\ccm
    $namespacesToRemove = @()
    try {
        $children = Get-CimInstance -Namespace "root\ccm" -ClassName "__NAMESPACE" -ErrorAction SilentlyContinue
        if ($children) {
            foreach ($child in $children) {
                $namespacesToRemove += "root\ccm\$($child.Name)"
            }
        }
    } catch {
        Write-Log "Could not enumerate root\ccm child namespaces (may already be gone)" "INFO"
    }
    # Always include the parent namespaces themselves
    $namespacesToRemove += "root\ccm"
    $namespacesToRemove += "root\sms"

    # Remove child namespaces first (deepest first), then parents
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

    # --- File System Cleanup ---
    Write-SectionHeader "File System Cleanup"
    $dirsToRemove = @(
        "$env:SystemRoot\CCM",
        "$env:SystemRoot\ccmsetup",
        "$env:SystemRoot\ccmcache"
    )

    foreach ($dir in $dirsToRemove) {
        if (Test-Path $dir) {
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Log "Removed directory: $dir" "SUCCESS"
            } catch {
                # Some files may be locked; try again after a brief wait
                Start-Sleep -Seconds 2
                try {
                    Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                    Write-Log "Removed directory (second attempt): $dir" "SUCCESS"
                } catch {
                    Write-Log "Could not fully remove $dir -- $($_.Exception.Message)" "WARN"
                }
            }
        } else {
            Write-Log "Directory not present (OK): $dir" "INFO"
        }
    }

    # Individual files
    $filesToRemove = @(
        "$env:SystemRoot\SMSCFG.ini"
    )
    foreach ($file in $filesToRemove) {
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Log "Removed file: $file" "SUCCESS"
            } catch {
                Write-Log "Could not remove $file -- $($_.Exception.Message)" "WARN"
            }
        }
    }

    # Wildcard cleanup
    $wildcardPatterns = @(
        @{ Path = "$env:SystemRoot"; Filter = "SMS*.mif" },
        @{ Path = "$env:SystemRoot\Temp"; Filter = "ccm*" }
    )
    foreach ($pattern in $wildcardPatterns) {
        try {
            $items = Get-ChildItem -Path $pattern.Path -Filter $pattern.Filter -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed: $($item.FullName)" "SUCCESS"
            }
        } catch {
            Write-Log "Wildcard cleanup issue in $($pattern.Path)\$($pattern.Filter) -- $($_.Exception.Message)" "WARN"
        }
    }

    # --- Registry Cleanup ---
    Write-SectionHeader "Registry Cleanup"
    $regKeysToRemove = @(
        "HKLM:\SOFTWARE\Microsoft\CCM",
        "HKLM:\SOFTWARE\Microsoft\CCMSetup",
        "HKLM:\SOFTWARE\Microsoft\SMS",
        "HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS\Certificates"
    )

    foreach ($key in $regKeysToRemove) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Log "Removed registry key: $key" "SUCCESS"
            } catch {
                Write-Log "Could not remove registry key $key -- $($_.Exception.Message)" "WARN"
            }
        } else {
            Write-Log "Registry key not present (OK): $key" "INFO"
        }
    }

    # Uninstall entries
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($uninstallPath in $uninstallPaths) {
        try {
            $sccmUninstall = Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue |
                Where-Object {
                    $dn = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                    $dn -match "Configuration Manager Client|System Center Configuration Manager"
                }
            foreach ($entry in $sccmUninstall) {
                Remove-Item -Path $entry.PSPath -Recurse -Force -ErrorAction Stop
                Write-Log "Removed uninstall entry: $($entry.PSPath)" "SUCCESS"
            }
        } catch {
            Write-Log "Uninstall entry cleanup issue -- $($_.Exception.Message)" "WARN"
        }
    }

    # --- Certificate Cleanup ---
    Write-SectionHeader "Certificate Cleanup"
    try {
        if (Test-Path "Cert:\LocalMachine\SMS") {
            $certs = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction SilentlyContinue
            foreach ($cert in $certs) {
                Remove-Item -Path $cert.PSPath -Force -ErrorAction Stop
                Write-Log "Removed SMS certificate: $($cert.Thumbprint)" "SUCCESS"
            }
        } else {
            Write-Log "SMS certificate store not present (OK)" "INFO"
        }
    } catch {
        Write-Log "Certificate cleanup issue -- $($_.Exception.Message)" "WARN"
    }

    # --- Scheduled Task Cleanup ---
    Write-SectionHeader "Scheduled Task Cleanup"
    try {
        $sccmTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -match "Configuration Manager|SCCM|CCM" -or $_.TaskPath -match "Microsoft\\Configuration Manager" }
        foreach ($task in $sccmTasks) {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-Log "Removed scheduled task: $($task.TaskPath)$($task.TaskName)" "SUCCESS"
        }
        if (-not $sccmTasks) {
            Write-Log "No SCCM scheduled tasks found (OK)" "INFO"
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
    Write-Phase 6 "Prerequisites Repair"

    # --- WMI MOF Re-registration ---
    Write-SectionHeader "WMI MOF Re-registration"

    # Ensure WMI is running
    try {
        $wmi = Get-Service -Name Winmgmt -ErrorAction Stop
        if ($wmi.Status -ne "Running") {
            Start-Service -Name Winmgmt -ErrorAction Stop
            Write-Log "Started WMI service" "SUCCESS"
        } else {
            Write-Log "WMI service already running" "SUCCESS"
        }
    } catch {
        Write-Log "Could not start WMI service -- $($_.Exception.Message)" "ERROR"
    }

    # Resync performance counters
    try {
        $null = & winmgmt /resyncperf 2>&1
        Write-Log "winmgmt /resyncperf completed" "SUCCESS"
    } catch {
        Write-Log "winmgmt /resyncperf failed -- $($_.Exception.Message)" "WARN"
    }

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
                try {
                    $null = & mofcomp $mof.FullName 2>&1
                    $compiled++
                } catch { }
            }
            Write-Log "Bulk MOF recompilation complete: $compiled of $($allMofs.Count) files" "SUCCESS"
        } catch {
            Write-Log "Bulk MOF recompilation error: $($_.Exception.Message)" "WARN"
        }
    } else {
        # Re-compile core MOF files (selective list)
        $mofFiles = @(
            "cimwin32.mof",
            "cimwin32.mfl",
            "win32_encryptablevolume.mof",
            "rsop.mof",
            "rsop.mfl",
            "cmprov.mof",
            "cmprov.mfl",
            "msi.mof",
            "tscfgwmi.mof",
            "policman.mof",
            "policman.mfl",
            "sr.mof"
        )

        foreach ($mof in $mofFiles) {
            $mofPath = Join-Path $wbemPath $mof
            if (Test-Path $mofPath) {
                try {
                    $null = & mofcomp $mofPath 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "Re-compiled MOF: $mof" "SUCCESS"
                    } else {
                        Write-Log "mofcomp returned code $LASTEXITCODE for $mof" "WARN"
                    }
                } catch {
                    Write-Log "mofcomp failed for $mof -- $($_.Exception.Message)" "WARN"
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

    # --- Service Repair ---
    Write-SectionHeader "Service Repair"

    # BITS
    try {
        Set-Service -Name BITS -StartupType Manual -ErrorAction Stop
        Start-Service -Name BITS -ErrorAction SilentlyContinue
        Write-Log "BITS set to Manual start and started" "SUCCESS"
    } catch {
        Write-Log "BITS service repair issue -- $($_.Exception.Message)" "WARN"
    }

    # Windows Update
    try {
        Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Write-Log "Windows Update service set to Manual and started" "SUCCESS"
    } catch {
        Write-Log "Windows Update service repair issue -- $($_.Exception.Message)" "WARN"
    }

    # Cryptographic Services
    try {
        $crypto = Get-Service -Name CryptSvc -ErrorAction Stop
        if ($crypto.Status -ne "Running") {
            Start-Service -Name CryptSvc -ErrorAction Stop
            Write-Log "Started Cryptographic Services" "SUCCESS"
        } else {
            Write-Log "Cryptographic Services already running" "SUCCESS"
        }
    } catch {
        Write-Log "CryptSvc repair issue -- $($_.Exception.Message)" "WARN"
    }

    # --- DLL Re-registration ---
    Write-SectionHeader "DLL Re-registration"

    # BITS DLLs
    $bitsDlls = @("qmgr.dll", "qmgrprxy.dll")
    foreach ($dll in $bitsDlls) {
        try {
            $null = & regsvr32 /s "$env:SystemRoot\System32\$dll" 2>&1
            Write-Log "Re-registered: $dll" "SUCCESS"
        } catch {
            Write-Log "Could not re-register $dll" "WARN"
        }
    }

    # Windows Update DLLs
    $wuDlls = @(
        "wuaueng.dll", "wuapi.dll", "wups.dll", "wups2.dll",
        "wuwebv.dll", "wucltux.dll", "wudriver.dll",
        "atl.dll", "msxml3.dll", "msxml6.dll"
    )
    foreach ($dll in $wuDlls) {
        $dllPath = "$env:SystemRoot\System32\$dll"
        if (Test-Path $dllPath) {
            try {
                $null = & regsvr32 /s $dllPath 2>&1
                Write-Log "Re-registered: $dll" "SUCCESS"
            } catch {
                Write-Log "Could not re-register $dll" "WARN"
            }
        }
    }

    # --- Registry.pol Corruption Check ---
    Write-SectionHeader "Registry.pol Corruption Check"

    $polCorruptFound = $false
    foreach ($polScope in @("Machine", "User")) {
        $polPath = "$env:SystemRoot\System32\GroupPolicy\$polScope\registry.pol"
        if (Test-Path $polPath) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($polPath)
                # Valid registry.pol starts with PReg signature (0x50 0x52 0x65 0x67) + version (0x01 0x00 0x00 0x00)
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
    Write-Phase 7 "Client Reinstallation"

    $stagingDir = "$env:SystemRoot\Temp\ccmsetup_healing"
    $stagingExe = Join-Path $stagingDir "ccmsetup.exe"
    $sourceExe  = Join-Path $ClientSource "ccmsetup.exe"

    # Create staging directory
    if (-not (Test-Path $stagingDir)) {
        New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
    }

    # Copy ccmsetup.exe from source
    Write-Log "Copying ccmsetup.exe from $ClientSource ..." "INFO"
    try {
        Copy-Item -Path $sourceExe -Destination $stagingExe -Force -ErrorAction Stop

        # Also copy any additional source files (i7, x64, etc.) in the share
        $sourceItems = Get-ChildItem -Path $ClientSource -ErrorAction SilentlyContinue
        foreach ($item in $sourceItems) {
            if ($item.Name -ne "ccmsetup.exe") {
                Copy-Item -Path $item.FullName -Destination $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Log "Client files staged to $stagingDir" "SUCCESS"
    } catch {
        Write-Log "Failed to copy client source files -- $($_.Exception.Message)" "ERROR"
        return $false
    }

    # Determine DNS suffix from MP FQDN
    $dnsSuffix = ($ManagementPoint -split '\.', 2)[1]
    if (-not $dnsSuffix) { $dnsSuffix = (Get-CimInstance Win32_ComputerSystem).Domain }

    # Build install arguments
    $installArgs = @(
        "/mp:$ManagementPoint",
        "/logon",
        "/usepkicert",
        "/allowmetered",
        "/nocrlcheck",
        "SMSSITECODE=$SiteCode",
        "SMSMP=$ManagementPoint",
        "DNSSUFFIX=$dnsSuffix",
        "RESETKEYINFORMATION=TRUE"
    )
    $argString = $installArgs -join " "

    Write-Log "Running: ccmsetup.exe $argString" "INFO"

    try {
        $proc = Start-Process -FilePath $stagingExe -ArgumentList $argString -PassThru -NoNewWindow

        $timeout = 900  # 15 minutes
        $elapsed = 0
        $ccmsetupLog = "$env:SystemRoot\ccmsetup\Logs\ccmsetup.log"

        while (-not $proc.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds 15
            $elapsed += 15

            # Show progress from ccmsetup.log if available
            $statusMsg = "Installing ($($elapsed)s / $($timeout)s max)"
            if (Test-Path $ccmsetupLog) {
                $lastLine = Get-Content $ccmsetupLog -Tail 1 -ErrorAction SilentlyContinue
                if ($lastLine) {
                    # Truncate long lines
                    if ($lastLine.Length -gt 80) { $lastLine = $lastLine.Substring(0, 77) + '...' }
                    $statusMsg = "$statusMsg | $lastLine"
                }
            }
            Write-Host "  [....] $statusMsg" -ForegroundColor Gray
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
            0       { Write-Log "ccmsetup completed successfully (exit code 0)" "SUCCESS"; return $true }
            7       { Write-Log "ccmsetup exit code 7 -- reboot required" "WARN"; return $true }
            default { Write-Log "ccmsetup finished with exit code $exitCode" "ERROR"; return $false }
        }
    } catch {
        Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
        # Attempt staging cleanup on failure too
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ============================================================================
#  PHASE 8 -- POST-INSTALL VERIFICATION
# ============================================================================

function Test-PostInstall {
    Write-Phase 8 "Post-Install Verification"

    Write-Log "Waiting 60 seconds for services to stabilize..." "INFO"
    Write-Host "  [....] Waiting 60 seconds for services to stabilize..." -ForegroundColor Gray
    Start-Sleep -Seconds 60

    $postChecks = @{}
    $passed = 0
    $total = 0

    # CcmExec service
    $total++
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            $postChecks["CcmExec Service"] = "PASS - Running"
            $passed++
            Write-Log "Post-check CcmExec: Running" "SUCCESS"
        } else {
            # Try to start it
            Start-Service -Name CcmExec -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 10
            $svc.Refresh()
            if ($svc.Status -eq "Running") {
                $postChecks["CcmExec Service"] = "PASS - Started manually"
                $passed++
                Write-Log "Post-check CcmExec: Started manually" "SUCCESS"
            } else {
                $postChecks["CcmExec Service"] = "FAIL - $($svc.Status)"
                Write-Log "Post-check CcmExec: $($svc.Status)" "ERROR"
            }
        }
    } catch {
        $postChecks["CcmExec Service"] = "FAIL - Not found"
        Write-Log "Post-check CcmExec: Not found" "ERROR"
    }

    # Client version
    $total++
    $clientVersion = "Unknown"
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
        $clientVersion = $client.ClientVersion
        $postChecks["Client Version"] = "PASS - $clientVersion"
        $passed++
        Write-Log "Post-check Client Version: $clientVersion" "SUCCESS"
    } catch {
        $postChecks["Client Version"] = "FAIL - Cannot query"
        Write-Log "Post-check Client Version: Cannot query" "ERROR"
    }

    # Site assignment
    $total++
    try {
        $assignment = Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName GetAssignedSite -ErrorAction Stop
        $site = $assignment.sSiteCode
        if ($site -eq $SiteCode) {
            $postChecks["Site Assignment"] = "PASS - $site"
            $passed++
            Write-Log "Post-check Site Assignment: $site" "SUCCESS"
        } else {
            $postChecks["Site Assignment"] = "WARN - $site (expected $SiteCode)"
            Write-Log "Post-check Site Assignment: $site (expected $SiteCode)" "WARN"
        }
    } catch {
        $postChecks["Site Assignment"] = "FAIL - Cannot determine"
        Write-Log "Post-check Site Assignment: Cannot determine" "ERROR"
    }

    # Trigger machine policy
    $total++
    try {
        Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{
            sScheduleID = "{00000000-0000-0000-0000-000000000021}"
        } -ErrorAction Stop
        $postChecks["Policy Trigger"] = "PASS - Machine policy requested"
        $passed++
        Write-Log "Post-check: Machine policy evaluation triggered" "SUCCESS"
    } catch {
        $postChecks["Policy Trigger"] = "FAIL - $($_.Exception.Message)"
        Write-Log "Post-check: Could not trigger machine policy -- $($_.Exception.Message)" "ERROR"
    }

    # Trigger hardware inventory
    try {
        Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{
            sScheduleID = "{00000000-0000-0000-0000-000000000001}"
        } -ErrorAction SilentlyContinue
        Write-Log "Triggered hardware inventory cycle" "INFO"
    } catch {
        Write-Log "Could not trigger hardware inventory" "WARN"
    }

    $score = [math]::Round(($passed / $total) * 100)
    $pct = "$($score)%"
    Write-Log "Post-install score: $pct ($($passed)/$($total))" "INFO"

    return @{
        Score         = $score
        Passed        = $passed
        Total         = $total
        Checks        = $postChecks
        ClientVersion = $clientVersion
    }
}

# ============================================================================
#  PHASE 9 -- SUMMARY REPORT
# ============================================================================

function Write-SummaryReport {
    param(
        [hashtable]$BeforeHealth,
        [hashtable]$AfterHealth,
        [hashtable]$PhaseResults
    )

    Write-Phase 9 "Summary Report"

    $line = "=" * 60
    Write-Host ""
    Write-Host "  $line" -ForegroundColor Cyan
    Write-Host "   SCCM CLIENT HEALING -- SUMMARY" -ForegroundColor White
    Write-Host "  $line" -ForegroundColor Cyan
    Write-Host ""

    # Before / After health
    $beforeColor = if ($BeforeHealth.Score -ge 90) { "Green" } elseif ($BeforeHealth.Score -ge 50) { "Yellow" } else { "Red" }
    $afterColor  = if ($AfterHealth.Score -ge 90) { "Green" } elseif ($AfterHealth.Score -ge 50) { "Yellow" } else { "Red" }

    Write-Host "   Health Score (Before):  " -NoNewline -ForegroundColor White
    Write-Host "$($BeforeHealth.Score)% ($($BeforeHealth.Passed)/$($BeforeHealth.Total))" -ForegroundColor $beforeColor
    Write-Host "   Health Score (After):   " -NoNewline -ForegroundColor White
    Write-Host "$($AfterHealth.Score)% ($($AfterHealth.Passed)/$($AfterHealth.Total))" -ForegroundColor $afterColor

    if ($AfterHealth.ClientVersion -and $AfterHealth.ClientVersion -ne "Unknown") {
        Write-Host "   Client Version:         $($AfterHealth.ClientVersion)" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "   Phase Results:" -ForegroundColor White
    Write-Host "   $('-' * 45)" -ForegroundColor Gray

    foreach ($phase in $PhaseResults.GetEnumerator() | Sort-Object Name) {
        $icon = if ($phase.Value -eq "PASS") { "[ OK ]" }
                elseif ($phase.Value -eq "WARN") { "[WARN]" }
                elseif ($phase.Value -eq "SKIP") { "[SKIP]" }
                else { "[FAIL]" }
        $color = if ($phase.Value -eq "PASS") { "Green" }
                 elseif ($phase.Value -match "WARN|SKIP") { "Yellow" }
                 else { "Red" }
        $label = $phase.Key.PadRight(32)
        Write-Host "   $icon $label" -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  $line" -ForegroundColor Cyan

    if ($AfterHealth.Score -ge 75) {
        Write-Host "   RESULT: Client appears healthy after healing." -ForegroundColor Green
    } elseif ($AfterHealth.Score -ge 50) {
        Write-Host "   RESULT: Partial success -- some checks still failing." -ForegroundColor Yellow
        Write-Host "   Review the log at $LogPath for details." -ForegroundColor Yellow
    } else {
        Write-Host "   RESULT: Healing may not have succeeded." -ForegroundColor Red
        Write-Host "   Manual intervention likely required." -ForegroundColor Red
        Write-Host "   Review the log at $LogPath for details." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "   Full log: $LogPath" -ForegroundColor Gray
    Write-Host "  $line" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "===== HEALING COMPLETE =====" "PHASE"
}

# ============================================================================
#  MAIN EXECUTION
# ============================================================================

# Initialize log
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
"" | Set-Content -Path $LogPath -Force

$startTime = Get-Date
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   SCCM Client Healing Script -- Interactive Edition" -ForegroundColor White
Write-Host "   Started: $startTime" -ForegroundColor Gray
Write-Host "   Computer: $($env:COMPUTERNAME)" -ForegroundColor Gray
Write-Host "  ================================================================" -ForegroundColor Cyan

Write-Log "Script started on $($env:COMPUTERNAME) at $startTime" "INFO"
Write-Log "Parameters: SiteCode=$SiteCode, MP=$ManagementPoint, Source=$ClientSource" "INFO"
Write-Log "Switches: ForceReinstall=$ForceReinstall, DiagnosticsOnly=$DiagnosticsOnly" "INFO"

$phaseResults = [ordered]@{}

# PHASE 1 -- Pre-Flight
$preFlight = Invoke-PreFlightChecks
if (-not $preFlight) {
    Write-Log "Pre-flight checks failed. Exiting." "ERROR"
    Write-Host "`n  Pre-flight checks failed. See log: $LogPath" -ForegroundColor Red
    Copy-LogToNetworkShare
    exit 1
}
$phaseResults["Phase 1: Pre-Flight"] = "PASS"

# PHASE 2 -- Diagnostics
$beforeHealth = Get-SCCMHealthScore

if ($DiagnosticsOnly) {
    Write-Host "`n  -DiagnosticsOnly specified. No changes were made." -ForegroundColor Yellow
    Write-Log "DiagnosticsOnly mode -- exiting after Phase 2" "INFO"
    Copy-LogToNetworkShare
    exit 0
}

if ($beforeHealth.Score -eq 100 -and -not $ForceReinstall) {
    Write-Host "`n  Client is fully healthy (100 percent). No action needed." -ForegroundColor Green
    Write-Host "  Use -ForceReinstall to override.`n" -ForegroundColor Gray
    Write-Log "Client healthy. Exiting." "INFO"
    Copy-LogToNetworkShare
    exit 0
}
$phaseResults["Phase 2: Diagnostics"] = "PASS"

if ($ForceReinstall) {
    Write-Log "-ForceReinstall specified -- proceeding regardless of health" "WARN"
}

# PHASE 3 -- Stop and Kill
try {
    Stop-AllSCCM
    $phaseResults["Phase 3: Stop Services"] = "PASS"
} catch {
    Write-Log "Phase 3 error: $($_.Exception.Message)" "ERROR"
    $phaseResults["Phase 3: Stop Services"] = "WARN"
}

# PHASE 4 -- Clean Uninstall
$uninstallResult = Invoke-CleanUninstall
$phaseResults["Phase 4: Clean Uninstall"] = if ($uninstallResult) { "PASS" } else { "SKIP" }

# PHASE 5 -- Deep Clean
try {
    Invoke-DeepClean
    $phaseResults["Phase 5: Deep Clean"] = "PASS"
} catch {
    Write-Log "Phase 5 error: $($_.Exception.Message)" "ERROR"
    $phaseResults["Phase 5: Deep Clean"] = "WARN"
}

# PHASE 6 -- Prerequisites Repair
try {
    Repair-Prerequisites
    $phaseResults["Phase 6: Prerequisites"] = "PASS"
} catch {
    Write-Log "Phase 6 error: $($_.Exception.Message)" "ERROR"
    $phaseResults["Phase 6: Prerequisites"] = "WARN"
}

# PHASE 7 -- Client Reinstallation
$installResult = Install-SCCMClient
$phaseResults["Phase 7: Reinstallation"] = if ($installResult) { "PASS" } else { "FAIL" }

if (-not $installResult) {
    Write-Log "Installation failed -- post-install verification will likely fail" "WARN"
}

# PHASE 8 -- Post-Install Verification
$afterHealth = Test-PostInstall
$phaseResults["Phase 8: Verification"] = if ($afterHealth.Score -ge 75) { "PASS" }
                                          elseif ($afterHealth.Score -ge 50) { "WARN" }
                                          else { "FAIL" }

# PHASE 9 -- Report
Write-SummaryReport -BeforeHealth $beforeHealth -AfterHealth $afterHealth -PhaseResults $phaseResults

$elapsed = (Get-Date) - $startTime
Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
Write-Host "  Total time: $($elapsed.ToString('hh\:mm\:ss'))`n" -ForegroundColor Gray

Copy-LogToNetworkShare
