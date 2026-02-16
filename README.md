# SCCM Client Healing

A PowerShell remediation suite for repairing broken Microsoft SCCM/ConfigMgr clients that resist normal repair procedures. Performs deep diagnostic assessment, nuclear cleanup, and automated reinstallation across three deployment models.

## The Problem

SCCM clients break. Sometimes spectacularly. Corrupted WMI namespaces, orphaned registry keys, stale certificates, and half-finished uninstalls leave machines in a state where the standard `ccmsetup /remediate` or `/uninstall + reinstall` cycle just spins its wheels. These machines fall out of compliance, stop receiving updates, and become invisible to your management infrastructure.

This toolkit goes deeper — tearing out every trace of the client (WMI namespaces, file system, registry, certificates, scheduled tasks) before rebuilding prerequisites and performing a clean install.

## Three Editions

| Edition | Script | Use Case | Deployment |
|---------|--------|----------|------------|
| **Interactive** | `ClientHealing.ps1` | Ad-hoc troubleshooting | Run manually via PSSession or local admin console |
| **GPO** | `ClientHealing-GPO.ps1` | Large-scale rollout | Group Policy Computer Startup Script |
| **Scheduled Task** | `ClientHealing-Task.ps1` | Autonomous self-healing | GPO Preferences Scheduled Task |

### Interactive Edition

Best for testing and one-off repairs. Provides color-coded console output with real-time progress and a summary report at the end.

```powershell
# Full healing
.\ClientHealing.ps1 -SiteCode "ABC" -ManagementPoint "mp.domain.com" -ClientSource "\\server\share\CCMClient"

# Diagnostics only (no changes made)
.\ClientHealing.ps1 -SiteCode "ABC" -ManagementPoint "mp.domain.com" -DiagnosticsOnly

# Force reinstall (skip health check)
.\ClientHealing.ps1 -SiteCode "ABC" -ManagementPoint "mp.domain.com" -ClientSource "\\server\share\CCMClient" -ForceReinstall
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SiteCode` | Yes | Your SCCM site code |
| `-ManagementPoint` | Yes | FQDN of your management point |
| `-ClientSource` | Yes* | UNC path to directory containing `ccmsetup.exe` |
| `-LogPath` | No | Custom log file path |
| `-ForceReinstall` | No | Skip health check, proceed directly to healing |
| `-DiagnosticsOnly` | No | Run assessment only — no modifications |

*Not required when using `-DiagnosticsOnly`.

### GPO Edition

Designed for silent, large-scale deployment. Runs at computer startup, logs to file, and uses a marker file to prevent redundant re-runs on subsequent boots.

**Setup:**

1. Place `ClientHealing-GPO.ps1` on a domain-accessible share (e.g., `\\domain.com\NETLOGON\Scripts\`)
2. Edit the configuration variables at the top of the script:
   ```powershell
   $SiteCode         = "ABC"
   $ManagementPoint  = "mp.domain.com"
   $ClientSource     = "\\server\share\CCMClient"
   ```
3. Create a GPO: **Computer Configuration > Policies > Windows Settings > Scripts > Startup**
4. Link the GPO to the OU containing affected workstations
5. Optional: Set the script timeout to 900 seconds in the GP editor

**Behavior:**
- Waits for network availability (configurable retries)
- Exits immediately if the client is already healthy (100% health score)
- Creates a marker file on success to skip re-runs
- Re-evaluates after marker expires (default: 7 days)

### Scheduled Task Edition

A self-healing agent that monitors client health over time and gracefully removes itself after the client stabilizes.

**Setup:**

1. Place `ClientHealing-Task.ps1` on a domain share
2. Edit the configuration variables at the top of the script
3. Create a GPO: **Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks**
4. Configure the task:
   - **Run as:** `NT AUTHORITY\SYSTEM` with highest privileges
   - **Triggers:** At startup (5-min delay) + Daily at your preferred time
   - **Action:** `powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "\\path\to\ClientHealing-Task.ps1"`
   - **Settings:** Allow on-demand, 30-min timeout, do not start a new instance

**Behavior:**
- Self-stages: copies itself from the UNC share to `C:\Support` on first run (avoids network dependency and Defender temp-path blocks on subsequent runs)
- Tracks state in a JSON file across runs
- Counts consecutive healthy results
- Auto-unregisters the scheduled task after 3 consecutive healthy checks (configurable)
- Cleans up its own staged files on retirement

## How It Works

All three editions execute the same 9-phase healing engine:

### Phase 1: Pre-Flight Checks
Validates system info, verifies the client source share is accessible, and tests management point connectivity on ports 80/443.

### Phase 2: Diagnostic Assessment
Evaluates 12 health checks across four categories and produces a percentage-based health score:

| Category | Checks |
|----------|--------|
| **Service & Process** | CcmExec service, client version (WMI), WMI health, SCCM WMI namespaces |
| **Core Dependencies** | BITS service, Windows Update service, Cryptographic Services |
| **Certificates & Network** | SMS certificate store validity, MP DNS resolution |
| **Configuration** | ccmsetup.log error analysis, site code assignment |

Health scores: **90%+** healthy | **50–89%** degraded | **<50%** critical

### Phase 3: Stop Services & Kill Processes
Stops CcmExec, ccmsetup, smstsmgr, CmRcService. Kills any remaining processes. Disables CcmExec to prevent auto-restart during cleanup.

### Phase 4: Clean Uninstall Attempt
Runs `ccmsetup.exe /uninstall` with a 300-second timeout, handling the two-stage bootstrap process.

### Phase 5: Nuclear Cleanup
Removes all SCCM traces:

- **WMI:** Dynamically enumerates and removes all child namespaces under `root\ccm` and `root\sms` (deepest first)
- **File System:** `%SystemRoot%\CCM`, `ccmsetup`, `ccmcache`, `SMSCFG.ini`, `SMS*.mif`, `Temp\ccm*`
- **Registry:** `HKLM:\SOFTWARE\Microsoft\CCM`, `CCMSetup`, `SMS`, SMS certificate entries, uninstall entries (x86/x64)
- **Certificates:** `Cert:\LocalMachine\SMS` store
- **Scheduled Tasks:** SCCM-related tasks (preserving the healing task in the Task edition)

### Phase 6: Prerequisites Repair
- Repairs WMI (`winmgmt /resyncperf`, selective or bulk MOF recompilation)
- Restores BITS, Windows Update, and Cryptographic Services
- Re-registers core DLLs (qmgr, wuaueng, wuapi, msxml, etc.)
- Detects and repairs corrupted Group Policy `Registry.pol` files

### Phase 7: Client Reinstallation
Stages `ccmsetup.exe` locally and installs with:
```
ccmsetup.exe /mp:<MP> /logon /usepkicert /allowmetered /nocrlcheck
  SMSSITECODE=<Site> SMSMP=<MP> DNSSUFFIX=<suffix> RESETKEYINFORMATION=TRUE
```
15-minute timeout with exit code monitoring.

### Phase 8: Post-Install Verification
Waits 60 seconds for services to stabilize, then verifies CcmExec service, client version, site assignment, and triggers machine policy + hardware inventory cycles.

### Phase 9: Summary Report
(Interactive edition only) Displays before/after health scores with color-coded results.

## Requirements

- **OS:** Windows 7 SP1+ / Server 2008 R2+
- **PowerShell:** 3.0+
- **Privileges:** Administrator (interactive) or SYSTEM (GPO/Task)
- **Network:** Access to the `ccmsetup.exe` source share and management point (TCP 80/443)
- **Dependencies:** None — uses only built-in PowerShell cmdlets and Windows native tools

## Configuration

All three editions require these values to be set before use:

```powershell
$SiteCode        = "YOURSITECODE"        # Your SCCM site code
$ManagementPoint = "YOURMP.domain.com"   # Management point FQDN
$ClientSource    = "\\server\share\path" # UNC path to ccmsetup.exe
```

The interactive edition accepts these as command-line parameters. The GPO and Task editions use variables at the top of the script.

## Logging

All editions produce timestamped log files:

```
[2026-02-15 10:30:45] [PHASE] ========== Phase 2: Diagnostic Assessment ==========
[2026-02-15 10:30:45] [INFO]  Checking CcmExec service...
[2026-02-15 10:30:45] [SUCCESS] CcmExec service is running
[2026-02-15 10:30:46] [WARN]  SCCM WMI namespace root\ccm not accessible
[2026-02-15 10:30:46] [ERROR] Client site assignment mismatch: expected ABC, got ""
```

Default log locations:

| Edition | Path |
|---------|------|
| Interactive | `%SystemRoot%\Temp\SCCMHealing.log` |
| GPO | `%SystemRoot%\Temp\SCCMHealing-GPO.log` |
| Task | `C:\Support\SCCMHealing-Task.log` |

## License

This project is provided as-is for use in enterprise SCCM environments.
