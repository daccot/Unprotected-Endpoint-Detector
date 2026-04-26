#requires -version 5.1
<#
.SYNOPSIS
    Unprotected Endpoint Detector Pro v2.1

.DESCRIPTION
    Vendor-agnostic Windows endpoint security audit script.
    Detects endpoints with no active antivirus protection and outputs log, CSV, JSON, and HTML reports.

.VERSION
    2.1

.NOTES
    Product: Unprotected Endpoint Detector Pro
    Designed for IT admins, MSP engineers, RMM workflows, Intune scripts, and manual execution.

.USAGE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecurityAudit-Pro.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecurityAudit-Pro.ps1 -Quiet -NoBrowserOpen
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecurityAudit-Pro.ps1 -OutputDir "C:\AuditReports" -NoBrowserOpen

.EXITCODES
    0  = SAFE
    1  = WARNING
    2  = CRITICAL
    3  = UNKNOWN
    90 = SCRIPT ERROR
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Temp\UnprotectedEndpointDetector",
    [switch]$NoBrowserOpen,
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$ScriptName = "Unprotected Endpoint Detector Pro"
$ScriptVersion = "2.1"
$StartTime = Get-Date
$TimestampForFile = $StartTime.ToString("yyyyMMdd_HHmmss")
$TimestampHuman = $StartTime.ToString("yyyy-MM-dd HH:mm:ss")
$Hostname = $env:COMPUTERNAME
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Get-AdminState {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

$IsAdmin = Get-AdminState

try {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
} catch {
    Write-Error "Failed to create output directory: $OutputDir. Error: $($_.Exception.Message)"
    exit 90
}

$BaseName = "EndpointSecurityAudit_${Hostname}_${TimestampForFile}"
$LogPath = Join-Path $OutputDir "$BaseName.log"
$CsvPath = Join-Path $OutputDir "$BaseName.csv"
$JsonPath = Join-Path $OutputDir "$BaseName.json"
$HtmlPath = Join-Path $OutputDir "$BaseName.html"

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$now][$Level][$Hostname][$CurrentUser] $Message"

    if (-not $Quiet) {
        switch ($Level) {
            "ERROR" { Write-Host $line -ForegroundColor Red }
            "WARN"  { Write-Host $line -ForegroundColor Yellow }
            default { Write-Host $line }
        }
    }

    try {
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    } catch {
        if (-not $Quiet) {
            Write-Warning "Failed to write log: $($_.Exception.Message)"
        }
    }
}

function Convert-ToHtmlEncoded {
    param([AllowNull()][object]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-ProductStateMeaning {
    param([AllowNull()][object]$ProductState)
    if ($null -eq $ProductState) { return "Unknown" }
    return "RawState=$ProductState"
}

function Convert-BooleanToText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "Unknown" }
    return [string]$Value
}

function Get-OsInfoSafe {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return [PSCustomObject]@{
            Caption = $os.Caption
            Version = $os.Version
            BuildNumber = $os.BuildNumber
            Architecture = $os.OSArchitecture
            CheckSucceeded = $true
            Error = $null
        }
    } catch {
        return [PSCustomObject]@{
            Caption = "Unknown"
            Version = "Unknown"
            BuildNumber = "Unknown"
            Architecture = "Unknown"
            CheckSucceeded = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-DefenderStatusSafe {
    $result = [ordered]@{
        CheckSucceeded = $false
        AntivirusEnabled = $null
        RealTimeProtectionEnabled = $null
        AMServiceEnabled = $null
        AntispywareEnabled = $null
        AntivirusSignatureAge = $null
        NISSignatureAge = $null
        FullScanAge = $null
        QuickScanAge = $null
        Error = $null
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.CheckSucceeded = $true
        $result.AntivirusEnabled = [bool]$status.AntivirusEnabled
        $result.RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        $result.AMServiceEnabled = [bool]$status.AMServiceEnabled
        $result.AntispywareEnabled = [bool]$status.AntispywareEnabled
        if ($null -ne $status.AntivirusSignatureAge) { $result.AntivirusSignatureAge = [int]$status.AntivirusSignatureAge }
        if ($null -ne $status.NISSignatureAge) { $result.NISSignatureAge = [int]$status.NISSignatureAge }
        if ($null -ne $status.FullScanAge) { $result.FullScanAge = [int]$status.FullScanAge }
        if ($null -ne $status.QuickScanAge) { $result.QuickScanAge = [int]$status.QuickScanAge }
    } catch {
        $result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$result
}

function Get-AntivirusProductsSafe {
    $products = @()
    $errorMessage = $null

    try {
        $items = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct -ErrorAction Stop
        foreach ($item in $items) {
            $products += [PSCustomObject]@{
                DisplayName = [string]$item.displayName
                InstanceGuid = [string]$item.instanceGuid
                PathToSignedProductExe = [string]$item.pathToSignedProductExe
                PathToSignedReportingExe = [string]$item.pathToSignedReportingExe
                ProductState = $item.productState
                ProductStateMeaning = Get-ProductStateMeaning -ProductState $item.productState
            }
        }
    } catch {
        $errorMessage = $_.Exception.Message
    }

    return [PSCustomObject]@{
        Products = $products
        Error = $errorMessage
        CheckSucceeded = ($null -eq $errorMessage)
    }
}

function Get-ServiceStateSafe {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            Name = $Name
            DisplayName = $service.DisplayName
            Status = $service.Status.ToString()
            StartType = $service.StartType.ToString()
            CheckSucceeded = $true
            Error = $null
        }
    } catch {
        return [PSCustomObject]@{
            Name = $Name
            DisplayName = "Unknown"
            Status = "Unknown"
            StartType = "Unknown"
            CheckSucceeded = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-RelevantServicesSafe {
    $serviceNames = @("WinDefend", "SecurityHealthService", "wscsvc")
    $services = @()
    foreach ($serviceName in $serviceNames) {
        $services += Get-ServiceStateSafe -Name $serviceName
    }
    return $services
}

function Get-RiskClassification {
    param(
        [Parameter(Mandatory = $true)]$DefenderStatus,
        [Parameter(Mandatory = $true)]$AvDetection
    )

    $allAvNames = @()
    $thirdPartyAvNames = @()

    foreach ($product in $AvDetection.Products) {
        if ($product.DisplayName) {
            $allAvNames += $product.DisplayName
            if ($product.DisplayName -notmatch "Windows Defender|Microsoft Defender") {
                $thirdPartyAvNames += $product.DisplayName
            }
        }
    }

    $anyAvDetected = ($allAvNames.Count -gt 0)
    $thirdPartyAvDetected = ($thirdPartyAvNames.Count -gt 0)
    $defenderKnown = [bool]$DefenderStatus.CheckSucceeded
    $defenderEnabled = ($DefenderStatus.AntivirusEnabled -eq $true)
    $realTimeEnabled = ($DefenderStatus.RealTimeProtectionEnabled -eq $true)

    $status = "UNKNOWN"
    $reason = "Unable to determine endpoint protection state reliably."
    $exitCode = 3

    if (-not $defenderKnown -and -not $AvDetection.CheckSucceeded) {
        $status = "UNKNOWN"
        $reason = "Defender and antivirus inventory checks failed."
        $exitCode = 3
    }
    elseif (-not $defenderEnabled -and -not $anyAvDetected) {
        $status = "CRITICAL"
        $reason = "No active antivirus signal was detected."
        $exitCode = 2
    }
    elseif (-not $defenderEnabled -and $thirdPartyAvDetected) {
        $status = "WARNING"
        $reason = "Microsoft Defender is OFF. Third-party antivirus was detected, but active state should be verified."
        $exitCode = 1
    }
    elseif ($defenderEnabled -and -not $realTimeEnabled) {
        $status = "WARNING"
        $reason = "Microsoft Defender is enabled, but real-time protection is OFF."
        $exitCode = 1
    }
    elseif ($defenderEnabled -and $realTimeEnabled) {
        $status = "SAFE"
        $reason = "Microsoft Defender antivirus and real-time protection are enabled."
        $exitCode = 0
    }
    elseif ($anyAvDetected) {
        $status = "WARNING"
        $reason = "Antivirus product was detected, but active protection state is not fully confirmed."
        $exitCode = 1
    }

    return [PSCustomObject]@{
        Status = $status
        Reason = $reason
        ExitCode = $exitCode
        AnyAvDetected = $anyAvDetected
        ThirdPartyAvDetected = $thirdPartyAvDetected
        AllAvNames = $allAvNames
        ThirdPartyAvNames = $thirdPartyAvNames
    }
}

function Get-StatusCssClass {
    param([string]$Status)
    switch ($Status) {
        "SAFE" { return "safe" }
        "WARNING" { return "warning" }
        "CRITICAL" { return "critical" }
        default { return "unknown" }
    }
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]$Audit,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $statusClass = Get-StatusCssClass -Status $Audit.Status
    $avRows = ""
    if ($Audit.AntivirusProducts.Count -gt 0) {
        foreach ($av in $Audit.AntivirusProducts) {
            $avRows += "<tr><td>$(Convert-ToHtmlEncoded $av.DisplayName)</td><td>$(Convert-ToHtmlEncoded $av.ProductStateMeaning)</td><td>$(Convert-ToHtmlEncoded $av.PathToSignedProductExe)</td></tr>`n"
        }
    } else {
        $avRows = "<tr><td colspan='3'>No antivirus product reported by Windows Security Center</td></tr>"
    }

    $serviceRows = ""
    foreach ($svc in $Audit.Services) {
        $serviceRows += "<tr><td>$(Convert-ToHtmlEncoded $svc.Name)</td><td>$(Convert-ToHtmlEncoded $svc.DisplayName)</td><td>$(Convert-ToHtmlEncoded $svc.Status)</td><td>$(Convert-ToHtmlEncoded $svc.StartType)</td></tr>`n"
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Unprotected Endpoint Detector Pro Report</title>
<style>
body { margin: 0; padding: 28px; font-family: Arial, Helvetica, sans-serif; background: #f5f7fb; color: #1f2937; }
.container { max-width: 1080px; margin: 0 auto; }
.header, .section, .metric { background: #ffffff; box-shadow: 0 4px 14px rgba(15, 23, 42, 0.08); }
.header { border-radius: 14px; padding: 24px; margin-bottom: 18px; }
h1 { margin: 0 0 8px 0; font-size: 28px; }
.subtitle { color: #4b5563; margin: 0; }
.status-card { border-radius: 14px; padding: 24px; margin-bottom: 18px; color: #ffffff; box-shadow: 0 4px 14px rgba(15, 23, 42, 0.08); }
.safe { background: #15803d; }
.warning { background: #b45309; }
.critical { background: #b91c1c; }
.unknown { background: #4b5563; }
.status-label { font-size: 14px; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.9; }
.status-value { font-size: 42px; font-weight: 700; margin: 6px 0; }
.reason { font-size: 17px; margin-top: 8px; }
.grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
.metric { border-radius: 12px; padding: 16px; }
.metric .label { font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.08em; }
.metric .value { margin-top: 8px; font-size: 20px; font-weight: 700; }
.section { border-radius: 14px; padding: 20px; margin-bottom: 18px; }
h2 { margin-top: 0; font-size: 20px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { border-bottom: 1px solid #e5e7eb; text-align: left; padding: 10px; vertical-align: top; word-break: break-word; }
th { background: #f9fafb; color: #374151; }
.footer { color: #6b7280; font-size: 12px; margin-top: 18px; }
@media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 560px) { body { padding: 14px; } .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Unprotected Endpoint Detector Pro Report</h1>
        <p class="subtitle">Generated at $(Convert-ToHtmlEncoded $Audit.Timestamp) / Version $(Convert-ToHtmlEncoded $Audit.ScriptVersion)</p>
    </div>

    <div class="status-card $statusClass">
        <div class="status-label">Endpoint Risk Status</div>
        <div class="status-value">$(Convert-ToHtmlEncoded $Audit.Status)</div>
        <div class="reason">$(Convert-ToHtmlEncoded $Audit.Reason)</div>
    </div>

    <div class="grid">
        <div class="metric"><div class="label">Hostname</div><div class="value">$(Convert-ToHtmlEncoded $Audit.Hostname)</div></div>
        <div class="metric"><div class="label">User</div><div class="value">$(Convert-ToHtmlEncoded $Audit.User)</div></div>
        <div class="metric"><div class="label">Defender</div><div class="value">$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.DefenderEnabled))</div></div>
        <div class="metric"><div class="label">Real-Time Protection</div><div class="value">$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.RealTimeProtectionEnabled))</div></div>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <table>
            <tr><th>Item</th><th>Value</th></tr>
            <tr><td>Any antivirus detected</td><td>$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.AnyAvDetected))</td></tr>
            <tr><td>Third-party antivirus detected</td><td>$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.ThirdPartyAvDetected))</td></tr>
            <tr><td>Third-party antivirus names</td><td>$(Convert-ToHtmlEncoded (($Audit.ThirdPartyAvNames) -join ", "))</td></tr>
            <tr><td>Defender check succeeded</td><td>$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.DefenderCheckSucceeded))</td></tr>
            <tr><td>Antivirus inventory check succeeded</td><td>$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.AntivirusInventoryCheckSucceeded))</td></tr>
            <tr><td>Exit code</td><td>$(Convert-ToHtmlEncoded $Audit.ExitCode)</td></tr>
        </table>
    </div>

    <div class="section"><h2>Detected Antivirus Products</h2><table><tr><th>Product</th><th>State</th><th>Executable Path</th></tr>$avRows</table></div>
    <div class="section"><h2>Relevant Windows Services</h2><table><tr><th>Name</th><th>Display Name</th><th>Status</th><th>Start Type</th></tr>$serviceRows</table></div>
    <div class="section"><h2>System Context</h2><table>
        <tr><th>Item</th><th>Value</th></tr>
        <tr><td>OS</td><td>$(Convert-ToHtmlEncoded $Audit.OS.Caption)</td></tr>
        <tr><td>OS Version</td><td>$(Convert-ToHtmlEncoded $Audit.OS.Version)</td></tr>
        <tr><td>Build Number</td><td>$(Convert-ToHtmlEncoded $Audit.OS.BuildNumber)</td></tr>
        <tr><td>Architecture</td><td>$(Convert-ToHtmlEncoded $Audit.OS.Architecture)</td></tr>
        <tr><td>Running as Administrator</td><td>$(Convert-ToHtmlEncoded (Convert-BooleanToText $Audit.IsAdmin))</td></tr>
    </table></div>
    <div class="footer">This report is an endpoint visibility aid. Third-party antivirus active state may require vendor console verification.</div>
</div>
</body>
</html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
}

$FinalExitCode = 3
try {
    Write-AuditLog "=== $ScriptName v$ScriptVersion Start ==="
    Write-AuditLog "Output directory: $OutputDir"
    Write-AuditLog "Running as administrator: $IsAdmin"

    $osInfo = Get-OsInfoSafe
    Write-AuditLog "OS: $($osInfo.Caption) / Version: $($osInfo.Version) / Build: $($osInfo.BuildNumber)"

    $defenderStatus = Get-DefenderStatusSafe
    if ($defenderStatus.CheckSucceeded) { Write-AuditLog "Defender status check succeeded" } else { Write-AuditLog "Defender status check failed: $($defenderStatus.Error)" "WARN" }

    $avDetection = Get-AntivirusProductsSafe
    if ($avDetection.CheckSucceeded) { Write-AuditLog "Antivirus inventory check succeeded" } else { Write-AuditLog "Antivirus inventory check failed: $($avDetection.Error)" "WARN" }

    $classification = Get-RiskClassification -DefenderStatus $defenderStatus -AvDetection $avDetection
    $services = Get-RelevantServicesSafe

    $audit = [PSCustomObject]@{
        ScriptName = $ScriptName
        ScriptVersion = $ScriptVersion
        Timestamp = $TimestampHuman
        Hostname = $Hostname
        User = $CurrentUser
        IsAdmin = $IsAdmin
        OS = $osInfo
        DefenderCheckSucceeded = $defenderStatus.CheckSucceeded
        DefenderEnabled = $defenderStatus.AntivirusEnabled
        RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
        AMServiceEnabled = $defenderStatus.AMServiceEnabled
        AntispywareEnabled = $defenderStatus.AntispywareEnabled
        AntivirusSignatureAge = $defenderStatus.AntivirusSignatureAge
        NISSignatureAge = $defenderStatus.NISSignatureAge
        FullScanAge = $defenderStatus.FullScanAge
        QuickScanAge = $defenderStatus.QuickScanAge
        DefenderStatusError = $defenderStatus.Error
        AntivirusInventoryCheckSucceeded = $avDetection.CheckSucceeded
        AntivirusInventoryError = $avDetection.Error
        AntivirusProducts = $avDetection.Products
        AnyAvDetected = $classification.AnyAvDetected
        ThirdPartyAvDetected = $classification.ThirdPartyAvDetected
        AllAvNames = $classification.AllAvNames
        ThirdPartyAvNames = $classification.ThirdPartyAvNames
        Services = $services
        Status = $classification.Status
        Reason = $classification.Reason
        ExitCode = $classification.ExitCode
        LogPath = $LogPath
        CsvPath = $CsvPath
        JsonPath = $JsonPath
        HtmlPath = $HtmlPath
    }

    Write-AuditLog "Status: $($audit.Status)"
    Write-AuditLog "Reason: $($audit.Reason)"
    Write-AuditLog "Detected AV products: $((($audit.AntivirusProducts | ForEach-Object { $_.DisplayName }) -join ', '))"

    $csvObject = [PSCustomObject]@{
        Timestamp = $audit.Timestamp
        Hostname = $audit.Hostname
        User = $audit.User
        OS = $audit.OS.Caption
        OSVersion = $audit.OS.Version
        BuildNumber = $audit.OS.BuildNumber
        IsAdmin = $audit.IsAdmin
        DefenderCheckSucceeded = $audit.DefenderCheckSucceeded
        DefenderEnabled = $audit.DefenderEnabled
        RealTimeProtectionEnabled = $audit.RealTimeProtectionEnabled
        AMServiceEnabled = $audit.AMServiceEnabled
        AntispywareEnabled = $audit.AntispywareEnabled
        AntivirusSignatureAge = $audit.AntivirusSignatureAge
        NISSignatureAge = $audit.NISSignatureAge
        FullScanAge = $audit.FullScanAge
        QuickScanAge = $audit.QuickScanAge
        AntivirusInventoryCheckSucceeded = $audit.AntivirusInventoryCheckSucceeded
        AnyAvDetected = $audit.AnyAvDetected
        ThirdPartyAvDetected = $audit.ThirdPartyAvDetected
        AllAvNames = (($audit.AllAvNames) -join ";")
        ThirdPartyAvNames = (($audit.ThirdPartyAvNames) -join ";")
        AntivirusProducts = (($audit.AntivirusProducts | ForEach-Object { $_.DisplayName }) -join ";")
        Status = $audit.Status
        Reason = $audit.Reason
        ExitCode = $audit.ExitCode
        LogPath = $audit.LogPath
        CsvPath = $audit.CsvPath
        JsonPath = $audit.JsonPath
        HtmlPath = $audit.HtmlPath
    }

    $csvObject | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-AuditLog "CSV report generated: $CsvPath"
    $audit | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonPath -Encoding UTF8
    Write-AuditLog "JSON report generated: $JsonPath"
    New-HtmlReport -Audit $audit -Path $HtmlPath
    Write-AuditLog "HTML report generated: $HtmlPath"

    if (-not $NoBrowserOpen -and -not $Quiet) {
        try { Start-Process $HtmlPath } catch { Write-AuditLog "Failed to open HTML report automatically: $($_.Exception.Message)" "WARN" }
    }

    $FinalExitCode = $audit.ExitCode
    Write-AuditLog "=== $ScriptName v$ScriptVersion End / ExitCode=$FinalExitCode ==="
} catch {
    Write-AuditLog "Unhandled error: $($_.Exception.Message)" "ERROR"
    $FinalExitCode = 90
} finally {
    exit $FinalExitCode
}
