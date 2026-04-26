#requires -version 5.1
<#
.SYNOPSIS
    Unprotected Endpoint Detector Free v1.0

.DESCRIPTION
    Free PowerShell script to detect whether a Windows endpoint appears to have active antivirus protection.
    This free version prints results to the console only.

    Pro version includes:
    - CSV report
    - JSON report
    - Color-coded HTML report
    - Execution log
    - RMM / Intune friendly exit codes
    - Quiet mode
    - Custom output directory

.NOTES
    Product: Unprotected Endpoint Detector Free
    Version: 1.0
    Target: Windows PowerShell 5.1+
    Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\SecurityAudit-Free.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$ScriptName = "Unprotected Endpoint Detector Free"
$ScriptVersion = "1.0"
$RunTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Hostname = $env:COMPUTERNAME
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Title
    Write-Host "============================================================"
}

function Write-ResultLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or $Value -eq "") {
        $displayValue = "Unknown"
    } else {
        $displayValue = [string]$Value
    }

    Write-Host ("{0,-32}: {1}" -f $Label, $displayValue)
}

function Get-AdminState {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
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
        Error = $null
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.CheckSucceeded = $true
        $result.AntivirusEnabled = [bool]$status.AntivirusEnabled
        $result.RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        $result.AMServiceEnabled = [bool]$status.AMServiceEnabled
        $result.AntispywareEnabled = [bool]$status.AntispywareEnabled

        if ($null -ne $status.AntivirusSignatureAge) {
            $result.AntivirusSignatureAge = [int]$status.AntivirusSignatureAge
        }
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
                ProductState = $item.productState
                PathToSignedProductExe = [string]$item.pathToSignedProductExe
            }
        }
    } catch {
        $errorMessage = $_.Exception.Message
    }

    return [PSCustomObject]@{
        Products = $products
        CheckSucceeded = ($null -eq $errorMessage)
        Error = $errorMessage
    }
}

function Get-ServiceStateSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

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

function Get-RiskClassification {
    param(
        [Parameter(Mandatory = $true)]
        $DefenderStatus,

        [Parameter(Mandatory = $true)]
        $AvDetection
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

    if (-not $defenderKnown -and -not $AvDetection.CheckSucceeded) {
        $status = "UNKNOWN"
        $reason = "Defender and antivirus inventory checks failed."
    }
    elseif (-not $defenderEnabled -and -not $anyAvDetected) {
        $status = "CRITICAL"
        $reason = "No active antivirus signal was detected."
    }
    elseif (-not $defenderEnabled -and $thirdPartyAvDetected) {
        $status = "WARNING"
        $reason = "Microsoft Defender is OFF. Third-party antivirus was detected, but active state should be verified."
    }
    elseif ($defenderEnabled -and -not $realTimeEnabled) {
        $status = "WARNING"
        $reason = "Microsoft Defender is enabled, but real-time protection is OFF."
    }
    elseif ($defenderEnabled -and $realTimeEnabled) {
        $status = "SAFE"
        $reason = "Microsoft Defender antivirus and real-time protection are enabled."
    }
    elseif ($anyAvDetected) {
        $status = "WARNING"
        $reason = "Antivirus product was detected, but active protection state is not fully confirmed."
    }

    return [PSCustomObject]@{
        Status = $status
        Reason = $reason
        AnyAvDetected = $anyAvDetected
        ThirdPartyAvDetected = $thirdPartyAvDetected
        AllAvNames = $allAvNames
        ThirdPartyAvNames = $thirdPartyAvNames
    }
}

function Write-StatusBanner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    Write-Host ""

    switch ($Status) {
        "SAFE" {
            Write-Host "[SAFE]" -ForegroundColor Green
            Write-Host $Reason -ForegroundColor Green
        }
        "WARNING" {
            Write-Host "[WARNING]" -ForegroundColor Yellow
            Write-Host $Reason -ForegroundColor Yellow
        }
        "CRITICAL" {
            Write-Host "[CRITICAL]" -ForegroundColor Red
            Write-Host $Reason -ForegroundColor Red
        }
        default {
            Write-Host "[UNKNOWN]" -ForegroundColor Gray
            Write-Host $Reason -ForegroundColor Gray
        }
    }
}

try {
    $isAdmin = Get-AdminState
    $osInfo = Get-OsInfoSafe
    $defenderStatus = Get-DefenderStatusSafe
    $avDetection = Get-AntivirusProductsSafe
    $winDefendService = Get-ServiceStateSafe -Name "WinDefend"
    $securityCenterService = Get-ServiceStateSafe -Name "wscsvc"
    $classification = Get-RiskClassification -DefenderStatus $defenderStatus -AvDetection $avDetection

    Write-Section "$ScriptName v$ScriptVersion"
    Write-ResultLine "Run time" $RunTime
    Write-ResultLine "Hostname" $Hostname
    Write-ResultLine "User" $CurrentUser
    Write-ResultLine "Running as Administrator" $isAdmin
    Write-ResultLine "OS" $osInfo.Caption
    Write-ResultLine "OS Version" $osInfo.Version
    Write-ResultLine "Build Number" $osInfo.BuildNumber
    Write-ResultLine "Architecture" $osInfo.Architecture

    Write-Section "Protection Summary"
    Write-StatusBanner -Status $classification.Status -Reason $classification.Reason

    Write-Section "Microsoft Defender"
    Write-ResultLine "Check succeeded" $defenderStatus.CheckSucceeded
    Write-ResultLine "Antivirus enabled" $defenderStatus.AntivirusEnabled
    Write-ResultLine "Real-time protection" $defenderStatus.RealTimeProtectionEnabled
    Write-ResultLine "AM service enabled" $defenderStatus.AMServiceEnabled
    Write-ResultLine "Antispyware enabled" $defenderStatus.AntispywareEnabled
    Write-ResultLine "Signature age" $defenderStatus.AntivirusSignatureAge

    if (-not $defenderStatus.CheckSucceeded) {
        Write-ResultLine "Defender check error" $defenderStatus.Error
    }

    Write-Section "Antivirus Products Reported by Windows Security Center"
    Write-ResultLine "Check succeeded" $avDetection.CheckSucceeded
    Write-ResultLine "Any AV detected" $classification.AnyAvDetected
    Write-ResultLine "Third-party AV detected" $classification.ThirdPartyAvDetected

    if ($avDetection.Products.Count -gt 0) {
        foreach ($product in $avDetection.Products) {
            Write-Host ""
            Write-ResultLine "Product" $product.DisplayName
            Write-ResultLine "Product state raw" $product.ProductState
            Write-ResultLine "Executable path" $product.PathToSignedProductExe
        }
    } else {
        Write-Host "No antivirus product was reported by Windows Security Center."
    }

    if (-not $avDetection.CheckSucceeded) {
        Write-ResultLine "AV inventory error" $avDetection.Error
    }

    Write-Section "Relevant Windows Services"
    Write-ResultLine "WinDefend status" $winDefendService.Status
    Write-ResultLine "WinDefend start type" $winDefendService.StartType
    Write-ResultLine "wscsvc status" $securityCenterService.Status
    Write-ResultLine "wscsvc start type" $securityCenterService.StartType

    Write-Section "Free vs Pro"
    Write-Host "This Free version prints results to the console only."
    Write-Host "Pro version includes CSV, JSON, HTML report, log file, exit codes, Quiet mode, and custom output directory."
    Write-Host ""
    Write-Host "Pro product page: [Add your Gumroad link here]"
    Write-Host ""
    Write-Host "Run complete."
} catch {
    Write-Host ""
    Write-Host "[SCRIPT ERROR]" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "This error was not written to a file because the Free version does not generate logs."
}
