# GUI-Compatible Reporting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `HealthStatus.json` and `HealthHistory.jsonl` output to `ClientHealing-Task.ps1` so the ConfigMgrHealthAgent-GUI Fleet Dashboard can read SCCM client health data.

**Architecture:** Modify `Get-SCCMHealthScore` to build a `CheckDetails` array alongside the existing score calculation. Add two new reporting functions (`Write-HealthStatus`, `Write-HealthHistory`) that produce GUI-compatible JSON. Call them at each exit path in the main flow.

**Tech Stack:** PowerShell 5.1, JSON via `ConvertTo-Json`, existing script patterns

---

### Task 1: Modify Get-SCCMHealthScore to collect CheckDetails

**Files:**
- Modify: `ClientHealing-Task.ps1:246-384`

**Step 1: Add CheckDetails array initialization after the $total/$passed variables**

At line 250, after `$total = 0`, add:

```powershell
    $checkDetails = @()
```

**Step 2: Wrap each of the 13 checks to populate CheckDetails**

For each check, after the pass/fail decision, append a hashtable to `$checkDetails`. The pattern for each check is:

```powershell
    # Check 1: CcmExec Service (lines 252-258)
    $total++
    $checkStatus = "Fail"
    $checkDetail = ""
    try {
        $svc = Get-Service -Name CcmExec -ErrorAction Stop
        if ($svc.Status -eq "Running") {
            $passed++; $checkStatus = "Pass"; $checkDetail = "Service running"
            Write-Log "CcmExec Service: Running" "SUCCESS"
        } else {
            $checkDetail = "Service status: $($svc.Status)"
            Write-Log "CcmExec Service: $($svc.Status)" "ERROR"
        }
    } catch {
        $checkDetail = "Service not found"
        Write-Log "CcmExec Service: Not found" "ERROR"
    }
    $checkDetails += @{ Name = "CcmExec Service"; Category = "Client Service"; Status = $checkStatus; Weight = 10; Detail = $checkDetail; RemediationTier = 0 }
```

Apply this pattern to all 13 checks with these names and categories:

| # | Lines | Name | Category | Pass Detail | Fail Detail |
|---|-------|------|----------|-------------|-------------|
| 1 | 252-258 | CcmExec Service | Client Service | "Service running" | "Service status: {status}" / "Service not found" |
| 2 | 260-265 | Client Version | Client Installation | "Version: {version}" | "Cannot query root\ccm" |
| 3 | 267-272 | WMI Health | System Health | "WMI repository healthy" | "WMI query failed" |
| 4 | 274-280 | SCCM WMI Namespaces | System Health | "root\ccm namespace present" | "root\ccm namespace missing" |
| 5 | 282-288 | BITS Service | System Services | "Status: {status}/{startType}" | "Service disabled" / "Service not found" |
| 6 | 290-296 | Windows Update Service | System Services | "Status: {status}/{startType}" | "Service disabled" / "Service not found" |
| 7 | 298-304 | Cryptographic Services | System Services | "Service running" | "Service status: {status}" / "Service not found" |
| 8 | 306-313 | SMS Certificates | Security | "{count} valid certificate(s)" | "No valid certificates" / "Certificate store not found" |
| 9 | 315-321 | DNS Resolution | Network | "Resolved {hostname}" | "Cannot resolve {hostname}" |
| 10 | 323-342 | ccmsetup.log Exit Code | Client Installation | "Last exit code {code} (success)" / "No exit code line found" / "Log not present" | "Last exit code {code}" / "Could not read log" |
| 11 | 344-364 | MP Communication | Network | "Last activity {days} day(s) ago" | "No activity for {days} days" / "Could not parse timestamps" / "Log not found" |
| 12 | 366-378 | Site Assignment | Site Configuration | "Site code {code} (correct)" | "Site code {code} (expected {expected})" / "Cannot determine site" |

Note: Check 12 (Site Assignment) covers both the registry and WMI fallback attempts — it's one logical check producing one CheckDetails entry.

**Step 3: Update the return value at line 383**

Replace:
```powershell
    return @{ Score = $score; Passed = $passed; Total = $total }
```

With:
```powershell
    return @{ Score = $score; Passed = $passed; Total = $total; CheckDetails = $checkDetails }
```

**Step 4: Verify existing callers still work**

The return value is used at:
- Line 989: `$healthResult = Get-SCCMHealthScore` — accesses `.Score` (still works)
- Line 991: `$healthResult.Score -eq 100` (still works)

No callers access `.CheckDetails` yet — that's added in Task 3.

**Step 5: Commit**

```bash
git add ClientHealing-Task.ps1
git commit -m "feat: collect per-check details in Get-SCCMHealthScore

Add CheckDetails array to health check return value with Name, Category,
Status, Weight, Detail, and RemediationTier for each of the 13 checks.
Existing score calculation unchanged."
```

---

### Task 2: Add Write-HealthStatus and Write-HealthHistory functions

**Files:**
- Modify: `ClientHealing-Task.ps1` — insert new functions after `Write-State` (after line 222)

**Step 1: Add the helper function to determine HealthStatus string**

Insert after `Write-State` function (after line 222):

```powershell
function Get-HealthStatusText {
    param([int]$Score)
    if ($Score -eq 100) { return "Healthy" }
    elseif ($Score -ge 75) { return "Degraded" }
    else { return "Critical" }
}
```

**Step 2: Add Write-HealthStatus function**

```powershell
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
```

**Step 3: Add Write-HealthHistory function**

```powershell
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
```

**Step 4: Commit**

```bash
git add ClientHealing-Task.ps1
git commit -m "feat: add Write-HealthStatus and Write-HealthHistory functions

New functions produce HealthStatus.json and HealthHistory.jsonl in the
format expected by ConfigMgrHealthAgent-GUI Fleet Dashboard.
Files written to both local staging dir and network share."
```

---

### Task 3: Integrate reporting into the main execution flow

**Files:**
- Modify: `ClientHealing-Task.ps1:989-1082` (main execution flow)

**Step 1: Add reporting calls to the healthy path (after line 1004)**

After `Write-State -State $state` on line 1004, before the threshold check on line 1007, add:

```powershell
    # Write GUI-compatible reporting files
    $clientVer = ""
    try { $clientVer = (Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction SilentlyContinue).ClientVersion } catch {}
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 0 -RemediationResult "None" -ClientVersion $clientVer
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 0 -RemediationResult "None"
```

Note: We already query client version at lines 998-1001 for the state. We can reuse `$state.ClientVersion` instead:

```powershell
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 0 -RemediationResult "None" -ClientVersion ($state.ClientVersion ?? "")
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 0 -RemediationResult "None"
```

**Step 2: Add reporting calls to the post-healing success path (after line 1059)**

Inside the `if ($afterHealth.Score -ge 75)` block, after line 1060 (`$state.ClientVersion = $afterHealth.ClientVersion`), add:

```powershell
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Full client rebuild succeeded" -ClientVersion ($afterHealth.ClientVersion ?? "")
            Write-HealthHistory -HealthScore $afterHealth.Score -RemediationTier 3 -RemediationResult "Full client rebuild succeeded"
```

Note: We pass the original `$healthResult` (pre-healing) for CheckDetails context, but the post-healing score via `$afterHealth.Score`. Actually — we should update `$healthResult.Score` to reflect the post-heal score. Better approach: pass `$afterHealth.Score` as the score. Let me reconsider.

The `$healthResult` has the pre-healing CheckDetails. The post-heal `$afterHealth` from `Test-PostInstall` is a simpler check. For accuracy, we should report the pre-healing CheckDetails (showing what was broken) with the post-healing score. Update `$healthResult.Score` and `$healthResult.Passed`:

```powershell
            $healthResult.Score = $afterHealth.Score
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Full client rebuild succeeded" -ClientVersion ($afterHealth.ClientVersion ?? "")
            Write-HealthHistory -HealthScore $afterHealth.Score -RemediationTier 3 -RemediationResult "Full client rebuild succeeded"
```

**Step 3: Add reporting calls to the post-healing partial/failure paths**

Inside the `else` block (line 1061-1064, partial success), after line 1064:

```powershell
            $healthResult.Score = $afterHealth.Score
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Full client rebuild - partial recovery" -ClientVersion ""
            Write-HealthHistory -HealthScore $afterHealth.Score -RemediationTier 3 -RemediationResult "Full client rebuild - partial recovery"
```

Inside the `catch` block (line 1066-1069):

```powershell
            Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Post-install verification failed" -ClientVersion ""
            Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 3 -RemediationResult "Post-install verification failed"
```

Inside the install failure block (line 1070-1072):

```powershell
        Write-HealthStatus -HealthResult $healthResult -RemediationTier 3 -RemediationResult "Client installation failed" -ClientVersion ""
        Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 3 -RemediationResult "Client installation failed"
```

**Step 4: Add reporting to the network-unavailable path (after line 1028)**

After `Write-State -State $state` on line 1028:

```powershell
    Write-HealthStatus -HealthResult $healthResult -RemediationTier 0 -RemediationResult "Network unavailable - healing deferred" -ClientVersion ""
    Write-HealthHistory -HealthScore $healthResult.Score -RemediationTier 0 -RemediationResult "Network unavailable - healing deferred"
```

Note: This writes locally only (network is unavailable), but the local files will be copied on the next successful run.

**Step 5: Extend Copy-LogToNetworkShare to include HealthStatus.json**

At line 160, update the file list:

Replace:
```powershell
        foreach ($file in @($LogPath, $transcriptPath, $StateFile)) {
```

With:
```powershell
        $healthStatusLocal = Join-Path $LocalStagingDir "HealthStatus.json"
        foreach ($file in @($LogPath, $transcriptPath, $StateFile, $healthStatusLocal)) {
```

This ensures the local `HealthStatus.json` backup is also copied on log sync. The `Write-HealthStatus` function already writes directly to the share, but this serves as a fallback.

**Step 6: Commit**

```bash
git add ClientHealing-Task.ps1
git commit -m "feat: integrate GUI reporting into all execution paths

Call Write-HealthStatus and Write-HealthHistory after health checks,
post-healing verification, and failure paths. Extend Copy-LogToNetworkShare
to include HealthStatus.json as fallback."
```

---

### Task 4: Final review and test

**Step 1: Read through the full modified script**

Verify:
- All 4 exit paths call both `Write-HealthStatus` and `Write-HealthHistory`
- `Get-SCCMHealthScore` returns `CheckDetails` in the hashtable
- `Copy-LogToNetworkShare` includes `HealthStatus.json`
- No syntax errors in the PowerShell

**Step 2: Verify JSON output format matches GUI expectations**

Check that the JSON property names exactly match what `FileShareService.cs` expects:
- `ComputerName`, `HealthScore`, `HealthStatus`, `ChecksPassed`, `ChecksFailed`, `ChecksTotal`
- `RemediationTier`, `RemediationResult`, `ClientVersion`, `SiteCode`, `AgentVersion`, `LastCheckTime`
- `CheckDetails[].Name`, `.Category`, `.Status`, `.Weight`, `.Detail`, `.RemediationTier`

**Step 3: Verify JSONL format**

Check that `HealthHistory.jsonl` entries match:
- `Timestamp`, `HealthScore`, `HealthStatus`, `RemediationTier`, `RemediationResult`
- Each line is a single compressed JSON object (no pretty-printing)

**Step 4: Final commit**

```bash
git add ClientHealing-Task.ps1
git commit -m "chore: verify GUI-compatible reporting implementation"
```
