<#
.SYNOPSIS
    SCCM Client Healing Script -- GPO Deployment Edition

.DESCRIPTION
    Silent, autonomous version of the SCCM client healing script designed to
    run as a Group Policy Computer Startup Script. Performs the same deep
    diagnostic, cleanup, and reinstallation as the interactive version but
    with all output directed to a log file (no console output).

    Key differences from the interactive version:
      - Configuration via variables at the top of the script (no parameters)
      - All output goes to a log file (no Write-Host)
      - Network wait with retries (network may not be ready at GPO startup)
      - Marker file prevents re-running on every boot
      - Runs as SYSTEM via GPO (no admin check needed)
      - Start-Transcript as a safety net

.NOTES
    DEPLOYMENT INSTRUCTIONS:
    ========================
    1. Place this script on a network share readable by Domain Computers
       (e.g. \\domain.com\NETLOGON\Scripts\ClientHealing-GPO.ps1)

    2. Ensure the ClientSource share is also readable by Domain Computers

    3. Create or edit a Group Policy Object:
       Computer Configuration > Policies > Windows Settings > Scripts > Startup
       - Add PowerShell script: ClientHealing-GPO.ps1
       - Set "Run Windows PowerShell scripts first" = Enabled (if available)

    4. Recommended: Set GPO startup script timeout:
       Computer Configuration > Administrative Templates > System > Scripts
       > "Maximum wait time for Group Policy scripts" = 900 (15 minutes)

    5. Link the GPO to the OU containing the affected workstations

    6. Optionally filter via WMI/security group to target only broken clients

    REMOVAL:
    ========
    After all machines are healed, remove the GPO link. The marker file
    prevents unnecessary re-runs, but removing the GPO is cleaner.

    TESTING:
    ========
    Test by running as SYSTEM before GPO deployment:
      psexec -s powershell.exe -ExecutionPolicy Bypass -File "\\path\to\ClientHealing-GPO.ps1"
#>

# ===== CONFIGURATION - EDIT THESE VALUES =====================================
$SiteCode        = "YOURSITECODE"
$ManagementPoint = "YOURMP.domain.com"
$ClientSource    = "\\SERVER\Share\Client"
$LogPath         = "$env:SystemRoot\Temp\SCCMHealing-GPO.log"
$MarkerFile      = "$env:SystemRoot\Temp\SCCMHealing-Success.marker"
$MaxRetries      = 3          # Network path retry attempts
$RetryDelaySec   = 30         # Seconds between retries
$MarkerMaxAgeDays = 7         # Re-run if marker is older than this
# =============================================================================

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

# ============================================================================
#  MARKER FILE CHECK
# ============================================================================

function Test-MarkerFile {
    if (Test-Path $MarkerFile) {
        $markerAge = (Get-Date) - (Get-Item $MarkerFile).LastWriteTime
        $ageDays = [math]::Round($markerAge.TotalDays, 1)
        if ($markerAge.TotalDays -lt $MarkerMaxAgeDays) {
            Write-Log "Marker file exists and is $ageDays days old (less than $MarkerMaxAgeDays day threshold). Already healed -- exiting." "INFO"
            return $true
        } else {
            Write-Log "Marker file exists but is $ageDays days old (at or above $MarkerMaxAgeDays day threshold). Will re-evaluate." "INFO"
            return $false
        }
    }
    return $false
}

function Write-MarkerFile {
    param([string]$ClientVersion)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $content = "Healed: $ts`r`nComputer: $($env:COMPUTERNAME)`r`nClientVersion: $ClientVersion`r`nSiteCode: $SiteCode`r`nManagementPoint: $ManagementPoint"
    Set-Content -Path $MarkerFile -Value $content -Force -ErrorAction SilentlyContinue
    Write-Log "Marker file written: $MarkerFile" "SUCCESS"
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

    # CcmExec Service
    $total++
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") { $passed++; Write-Log "CcmExec Service: Running" "SUCCESS" }
        else { Write-Log "CcmExec Service: $($svc.Status)" "ERROR" }
    } catch { Write-Log "CcmExec Service: Not found" "ERROR" }

    # Client Version
    $total++
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
        $passed++; Write-Log "Client Version: $($client.ClientVersion)" "SUCCESS"
    } catch { Write-Log "Client Version: Cannot query root\ccm" "ERROR" }

    # WMI Health
    $total++
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Out-Null
        $passed++; Write-Log "WMI Health: OK" "SUCCESS"
    } catch { Write-Log "WMI Health: FAILED" "ERROR" }

    # SCCM WMI Namespaces
    $total++
    $nsOk = $true
    foreach ($ns in @("root\ccm", "root\sms")) {
        try { Get-CimInstance -Namespace $ns -ClassName "__NAMESPACE" -ErrorAction Stop | Out-Null }
        catch { $nsOk = $false }
    }
    if ($nsOk) { $passed++; Write-Log "SCCM WMI Namespaces: Present" "SUCCESS" }
    else { Write-Log "SCCM WMI Namespaces: Missing" "ERROR" }

    # BITS Service
    $total++
    try {
        $bits = Get-Service -Name BITS -ErrorAction Stop
        if ($bits.Status -eq "Running" -or $bits.StartType -ne "Disabled") { $passed++; Write-Log "BITS: $($bits.Status)/$($bits.StartType)" "SUCCESS" }
        else { Write-Log "BITS: Disabled" "ERROR" }
    } catch { Write-Log "BITS: Not found" "ERROR" }

    # Windows Update Service
    $total++
    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        if ($wu.StartType -ne "Disabled") { $passed++; Write-Log "WU: $($wu.Status)/$($wu.StartType)" "SUCCESS" }
        else { Write-Log "WU: Disabled" "ERROR" }
    } catch { Write-Log "WU: Not found" "ERROR" }

    # Cryptographic Services
    $total++
    try {
        $crypto = Get-Service -Name CryptSvc -ErrorAction Stop
        if ($crypto.Status -eq "Running") { $passed++; Write-Log "CryptSvc: Running" "SUCCESS" }
        else { Write-Log "CryptSvc: $($crypto.Status)" "ERROR" }
    } catch { Write-Log "CryptSvc: Not found" "ERROR" }

    # SCCM Certificate
    $total++
    try {
        $smsCerts = Get-ChildItem -Path "Cert:\LocalMachine\SMS" -ErrorAction Stop
        $validCerts = $smsCerts | Where-Object { $_.NotAfter -gt (Get-Date) }
        if ($validCerts) { $passed++; Write-Log "SMS Certs: $($validCerts.Count) valid" "SUCCESS" }
        else { Write-Log "SMS Certs: No valid certs" "ERROR" }
    } catch { Write-Log "SMS Certs: Store not found" "ERROR" }

    # DNS Resolution
    $total++
    try {
        Resolve-DnsName -Name $ManagementPoint -ErrorAction Stop | Out-Null
        $passed++; Write-Log "DNS: Resolved $ManagementPoint" "SUCCESS"
    } catch { Write-Log "DNS: Cannot resolve $ManagementPoint" "ERROR" }

    # ccmsetup.log
    $total++
    $ccmsetupLog = "$env:SystemRoot\ccmsetup\Logs\ccmsetup.log"
    if (Test-Path $ccmsetupLog) {
        try {
            $logContent = Get-Content $ccmsetupLog -Tail 50 -ErrorAction Stop
            $errorLines = $logContent | Select-String -Pattern "error|fail|0x8" -AllMatches
            if ($errorLines.Count -eq 0) { $passed++; Write-Log "ccmsetup.log: No recent errors" "SUCCESS" }
            else { Write-Log "ccmsetup.log: Errors found" "WARN" }
        } catch {
            Write-Log "ccmsetup.log: Could not read" "WARN"
        }
    } else {
        $passed++; Write-Log "ccmsetup.log: Not present" "INFO"
    }

    # Client Assignment
    $total++
    try {
        $regSite = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -Name "AssignedSiteCode" -ErrorAction Stop).AssignedSiteCode
        if ($regSite -eq $SiteCode) { $passed++; Write-Log "Site Assignment: $regSite (correct)" "SUCCESS" }
        else { Write-Log "Site Assignment: $regSite (expected $SiteCode)" "WARN" }
    } catch {
        try {
            $null = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop
            $passed++; Write-Log "Site Assignment: via WMI" "SUCCESS"
        } catch { Write-Log "Site Assignment: Cannot determine" "ERROR" }
    }

    $score = [math]::Round(($passed / $total) * 100)
    Write-Log "Health Score: $($score)% ($($passed)/$($total))" "INFO"

    return @{ Score = $score; Passed = $passed; Total = $total }
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
        if ($exitCode -eq 0) { Write-Log "Uninstall completed (exit code 0)" "SUCCESS" }
        else { Write-Log "Uninstall exit code: $exitCode" "WARN" }
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

    # Scheduled Task Cleanup
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -match "Configuration Manager|SCCM|CCM" -or $_.TaskPath -match "Microsoft\\Configuration Manager" } |
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

    $stagingDir = "$env:SystemRoot\Temp\ccmsetup_healing"
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

    $dnsSuffix = ($ManagementPoint -split '\.', 2)[1]
    if (-not $dnsSuffix) { $dnsSuffix = (Get-CimInstance Win32_ComputerSystem).Domain }

    $installArgs = "/mp:$ManagementPoint /logon /usepkicert /allowmetered /nocrlcheck SMSSITECODE=$SiteCode SMSMP=$ManagementPoint DNSSUFFIX=$dnsSuffix RESETKEYINFORMATION=TRUE"

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
#  MAIN EXECUTION
# ============================================================================

# Initialize log
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

# Start transcript as safety net
$transcriptPath = "$env:SystemRoot\Temp\SCCMHealing-GPO-Transcript.log"
try { Start-Transcript -Path $transcriptPath -Append -ErrorAction SilentlyContinue } catch {}

$startTime = Get-Date
Write-Log "========================================" "PHASE"
Write-Log "SCCM Client Healing (GPO) started on $($env:COMPUTERNAME) at $startTime" "INFO"
Write-Log "Config: SiteCode=$SiteCode, MP=$ManagementPoint, Source=$ClientSource" "INFO"

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

# Check marker file -- exit early if already healed recently
if (Test-MarkerFile) {
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 0
}

# Quick health check -- exit if client is healthy
$beforeHealth = Get-SCCMHealthScore
if ($beforeHealth.Score -eq 100) {
    Write-Log "Client is healthy (100 percent). Writing marker and exiting." "SUCCESS"
    # Client is fine -- write marker so we don't re-check every boot
    try {
        $client = Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue
        $ver = if ($client) { $client.ClientVersion } else { "Healthy" }
    } catch { $ver = "Healthy" }
    Write-MarkerFile -ClientVersion $ver
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 0
}

Write-Log "Health score $($beforeHealth.Score) percent -- healing required" "WARN"

# Wait for network (GPO may run before network is ready)
if (-not (Wait-ForNetwork)) {
    Write-Log "Network unavailable. Will retry next boot." "ERROR"
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
    exit 1
}

# Execute healing phases
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
            Write-Log "HEALING SUCCEEDED -- Score: $($afterHealth.Score) percent" "SUCCESS"
            Write-MarkerFile -ClientVersion $afterHealth.ClientVersion
        } else {
            Write-Log "HEALING PARTIAL -- Score: $($afterHealth.Score) percent. Will retry next boot." "WARN"
        }
    } catch {
        Write-Log "Post-install verification error: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "INSTALLATION FAILED. Will retry next boot." "ERROR"
}

$elapsed = (Get-Date) - $startTime
Write-Log "Total elapsed time: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
Write-Log "========================================" "PHASE"

try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
