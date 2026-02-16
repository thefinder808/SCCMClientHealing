#Requires -Modules ActiveDirectory, ConfigurationManager
<#
.SYNOPSIS
    Identifies NO CLIENT workstations in SCCM and cross-references AD to separate
    retired machines from active machines with broken SCCM clients.

.DESCRIPTION
    Queries SCCM for all devices with Client = 0 or NULL, then checks Active Directory
    for last logon timestamp, password age, and OU location. Produces a triaged report
    with three buckets: Broken (active in AD), Likely Retired (stale in AD), and Unknown.

.PARAMETER SiteCode
    SCCM site code (e.g., "ABC").

.PARAMETER SiteServer
    FQDN of the SCCM site server / SMS Provider.

.PARAMETER StaleThresholdDays
    Number of days since last AD logon before a machine is considered likely retired.
    Default: 25

.PARAMETER ExportCsv
    Optional path to export the full results as CSV.

.PARAMETER PingTest
    If specified, performs a quick connectivity test on machines classified as Broken.
    Adds an "Online" column to results but takes longer to run.

.EXAMPLE
    .\Get-NoClientTriage.ps1 -SiteCode "ABC" -SiteServer "sccm.domain.com"

.EXAMPLE
    .\Get-NoClientTriage.ps1 -SiteCode "ABC" -SiteServer "sccm.domain.com" -ExportCsv "C:\Temp\NoClientReport.csv" -PingTest
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SiteCode,

    [Parameter(Mandatory)]
    [string]$SiteServer,

    [ValidateRange(1, 365)]
    [int]$StaleThresholdDays = 25,

    [string]$ExportCsv,

    [switch]$PingTest
)

# ── Connect to SCCM ──────────────────────────────────────────────────────────

try {
    Import-Module "$($env:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" -ErrorAction Stop
} catch {
    Write-Error "Could not load the ConfigurationManager module. Run this from a machine with the SCCM admin console installed."
    exit 1
}

$originalLocation = Get-Location
Set-Location "$($SiteCode):\"

# ── Query SCCM for NO CLIENT devices ─────────────────────────────────────────

Write-Host "`n[1/4] Querying SCCM for devices with no client..." -ForegroundColor Cyan

$wqlQuery = @"
select
    ResourceID,
    Name,
    LastLogonTimestamp,
    ADSiteName,
    IPAddresses,
    MACAddresses,
    CreationDate
from SMS_R_System
where Client = 0 or Client is null
"@

try {
    $noClientDevices = Get-CimInstance -Namespace "root\sms\site_$SiteCode" -ComputerName $SiteServer -Query $wqlQuery -ErrorAction Stop
} catch {
    Write-Error "Failed to query SCCM: $_"
    Set-Location $originalLocation
    exit 1
}

$totalCount = ($noClientDevices | Measure-Object).Count
Write-Host "  Found $totalCount devices with no SCCM client." -ForegroundColor White

if ($totalCount -eq 0) {
    Write-Host "`nNo devices to triage. Exiting." -ForegroundColor Green
    Set-Location $originalLocation
    exit 0
}

# ── Cross-reference Active Directory ──────────────────────────────────────────

Write-Host "`n[2/4] Cross-referencing Active Directory..." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSObject]]::new()
$now = Get-Date
$adLookupFailures = 0

foreach ($device in $noClientDevices) {
    $name = $device.Name

    # Query AD for this computer
    try {
        $adComputer = Get-ADComputer -Identity $name -Properties `
            lastLogonTimestamp, PasswordLastSet, whenCreated, DistinguishedName, Enabled `
            -ErrorAction Stop

        $lastLogon       = if ($adComputer.lastLogonTimestamp) {
                               [DateTime]::FromFileTime($adComputer.lastLogonTimestamp)
                           } else { $null }
        $daysSinceLogon  = if ($lastLogon) { ($now - $lastLogon).Days } else { $null }
        $passwordAge     = if ($adComputer.PasswordLastSet) { ($now - $adComputer.PasswordLastSet).Days } else { $null }

        # Determine triage bucket
        $status = if (-not $adComputer.Enabled) {
            "Disabled in AD"
        } elseif ($null -eq $lastLogon) {
            "Unknown (no logon data)"
        } elseif ($daysSinceLogon -le $StaleThresholdDays) {
            "Broken Client"
        } else {
            "Likely Retired"
        }

        # Parse OU from distinguished name
        $dn = $adComputer.DistinguishedName
        $ou = if ($dn -match ',(.+)$') { $Matches[1] } else { $dn }

        $results.Add([PSCustomObject]@{
            ComputerName    = $name
            Status          = $status
            ADEnabled       = $adComputer.Enabled
            LastADLogon     = $lastLogon
            DaysSinceLogon  = $daysSinceLogon
            PasswordAgeDays = $passwordAge
            OU              = $ou
            ADCreated       = $adComputer.whenCreated
            SCCMCreated     = $device.CreationDate
            IPAddresses     = ($device.IPAddresses -join "; ")
            Online          = $null
        })
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Machine exists in SCCM but not AD — definitely retired or orphaned record
        $results.Add([PSCustomObject]@{
            ComputerName    = $name
            Status          = "Not in AD (orphaned SCCM record)"
            ADEnabled       = $null
            LastADLogon     = $null
            DaysSinceLogon  = $null
            PasswordAgeDays = $null
            OU              = $null
            ADCreated       = $null
            SCCMCreated     = $device.CreationDate
            IPAddresses     = ($device.IPAddresses -join "; ")
            Online          = $null
        })
    } catch {
        $adLookupFailures++
        $results.Add([PSCustomObject]@{
            ComputerName    = $name
            Status          = "AD query failed"
            ADEnabled       = $null
            LastADLogon     = $null
            DaysSinceLogon  = $null
            PasswordAgeDays = $null
            OU              = $null
            ADCreated       = $null
            SCCMCreated     = $device.CreationDate
            IPAddresses     = ($device.IPAddresses -join "; ")
            Online          = $null
        })
    }
}

if ($adLookupFailures -gt 0) {
    Write-Host "  Warning: $adLookupFailures AD lookups failed (permissions or connectivity)." -ForegroundColor Yellow
}

# ── Optional: Ping test broken clients ────────────────────────────────────────

if ($PingTest) {
    $brokenClients = $results | Where-Object { $_.Status -eq "Broken Client" }
    $brokenCount = ($brokenClients | Measure-Object).Count

    if ($brokenCount -gt 0) {
        Write-Host "`n[3/4] Ping testing $brokenCount broken clients..." -ForegroundColor Cyan

        $i = 0
        foreach ($machine in $brokenClients) {
            $i++
            Write-Progress -Activity "Ping testing broken clients" -Status $machine.ComputerName -PercentComplete (($i / $brokenCount) * 100)

            $machine.Online = Test-Connection -ComputerName $machine.ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
        Write-Progress -Activity "Ping testing" -Completed
    }
} else {
    Write-Host "`n[3/4] Ping test skipped (use -PingTest to enable)." -ForegroundColor DarkGray
}

# ── Report ────────────────────────────────────────────────────────────────────

Write-Host "`n[4/4] Results Summary" -ForegroundColor Cyan
Write-Host ("=" * 65)

$groups = $results | Group-Object Status | Sort-Object Count -Descending

foreach ($group in $groups) {
    $color = switch ($group.Name) {
        "Broken Client"                 { "Red" }
        "Likely Retired"                { "DarkYellow" }
        "Disabled in AD"                { "DarkGray" }
        "Not in AD (orphaned SCCM record)" { "DarkGray" }
        default                         { "White" }
    }
    Write-Host ("  {0,-45} {1,5}" -f $group.Name, $group.Count) -ForegroundColor $color
}

Write-Host ("  {0,-45} {1,5}" -f "TOTAL", $results.Count) -ForegroundColor White
Write-Host ("=" * 65)

# Show broken clients detail
$broken = $results | Where-Object { $_.Status -eq "Broken Client" } | Sort-Object DaysSinceLogon

if ($broken) {
    Write-Host "`nBroken Clients (active in AD, no SCCM client):" -ForegroundColor Red
    $displayProps = @('ComputerName', 'DaysSinceLogon', 'PasswordAgeDays', 'OU')
    if ($PingTest) { $displayProps += 'Online' }
    $broken | Format-Table $displayProps -AutoSize
}

# ── Export ────────────────────────────────────────────────────────────────────

if ($ExportCsv) {
    try {
        $results | Sort-Object Status, ComputerName | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Full report exported to: $ExportCsv" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export CSV: $_"
    }
}

# ── Cleanup ───────────────────────────────────────────────────────────────────

Set-Location $originalLocation

Write-Host "`nRecommended next steps:" -ForegroundColor Cyan
Write-Host "  1. Deploy ClientHealing-Task.ps1 to the 'Broken Client' machines"
Write-Host "  2. Delete SCCM records for 'Not in AD' machines (orphaned)"
Write-Host "  3. Review 'Disabled in AD' — disable or delete their SCCM records"
Write-Host "  4. 'Likely Retired' machines will age out, or delete manually if confident"
Write-Host ""
