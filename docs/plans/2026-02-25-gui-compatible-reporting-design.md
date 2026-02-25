# GUI-Compatible Reporting for ClientHealing-Task.ps1

**Date:** 2026-02-25
**Status:** Approved

## Goal

Modify `ClientHealing-Task.ps1` to produce `HealthStatus.json` and `HealthHistory.jsonl` files compatible with the ConfigMgrHealthAgent-GUI Fleet Dashboard, enabling centralized monitoring of SCCM client health via the existing WPF management console.

## Decisions

- **Equal weights**: All 13 checks keep equal weight (10 each), preserving existing score behavior.
- **History enabled**: Append a JSONL line per run for trend charts and history tables.
- **Remediation mapping**: Tier 0 when healthy, Tier 3 when full rebuild runs (all-or-nothing).
- **Approach**: Add reporting functions directly into the existing script (no separate modules).

## Changes

### 1. Modify `Get-SCCMHealthScore`

Currently returns `@{ Score; Passed; Total }`. Add a `CheckDetails` array to the return value.

Each of the 13 checks produces:

| Property | Value |
|----------|-------|
| Name | Descriptive name |
| Category | Grouping |
| Status | "Pass" or "Fail" |
| Weight | 10 |
| Detail | Human-readable result message |
| RemediationTier | 0 |

Check-to-category mapping:

| # | Name | Category |
|---|------|----------|
| 1 | CcmExec Service | Client Service |
| 2 | Client Version | Client Installation |
| 3 | WMI Health | System Health |
| 4 | SCCM WMI Namespaces | System Health |
| 5 | BITS Service | System Services |
| 6 | Windows Update Service | System Services |
| 7 | Cryptographic Services | System Services |
| 8 | SMS Certificates | Security |
| 9 | DNS Resolution | Network |
| 10 | ccmsetup.log Exit Code | Client Installation |
| 11 | MP Communication | Network |
| 12 | Site Assignment (Registry) | Site Configuration |
| 13 | Site Assignment (WMI) | Site Configuration |

### 2. New Function: `Write-HealthStatus`

Writes `HealthStatus.json` to the network share machine folder:

```json
{
  "ComputerName": "<hostname>",
  "HealthScore": 0-100,
  "HealthStatus": "Healthy|Degraded|Critical",
  "ChecksPassed": <int>,
  "ChecksFailed": <int>,
  "ChecksTotal": 13,
  "RemediationTier": 0 or 3,
  "RemediationResult": "None" or "Full client rebuild",
  "ClientVersion": "<from WMI>",
  "SiteCode": "<configured>",
  "AgentVersion": "1.0.0-SCCMHealing",
  "LastCheckTime": "<ISO 8601>",
  "CheckDetails": [...]
}
```

Thresholds: 100% = Healthy, 75-99% = Degraded, <75% = Critical.

Also writes a local copy to `$LocalStagingDir\HealthStatus.json`.

### 3. New Function: `Write-HealthHistory`

Appends one JSON line to `HealthHistory.jsonl` on the network share:

```json
{"Timestamp":"<ISO>","HealthScore":<n>,"HealthStatus":"<status>","RemediationTier":<0|3>,"RemediationResult":"<result>"}
```

### 4. Integration Points

- **After health check (healthy path)**: Call both functions with Tier 0, "None".
- **After healing (post-verification)**: Call both functions with Tier 3, result message.
- **Write location**: `$NetworkLogShare\$env:COMPUTERNAME\` (same folder as existing logs).

### 5. What Stays the Same

- State file (`SCCMHealing-Task.state`) — drives auto-removal, unchanged.
- Log and transcript files — unchanged.
- All healing phases — untouched.
- Score calculation math — unchanged.
- `Copy-LogToNetworkShare` — extended to also copy `HealthStatus.json`.
