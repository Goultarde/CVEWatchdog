param(
    [string]$ApiUrl = "http://localhost:8001",
    [string]$ServerUrl,
    [string]$HtmlReport,
    [switch]$NoSploitScan,
    [switch]$Wildcards,
    [switch]$DebugMatching
)

$ErrorActionPreference = "Stop"

$CVSS_LEVELS = @{
    "Critical" = 9.0
    "High"     = 7.0
    "Medium"   = 4.0
    "Low"      = 0.1
}

function Get-ServiceExecutablePath {
    param([string]$PathName)

    if ($PathName -match '^\s*"?(.+?\.exe)"?(?:\s|$)') {
        return [Environment]::ExpandEnvironmentVariables($Matches[1])
    }
    return $null
}

function Get-InstalledSoftware {
    Write-Host "📦 Scanning installed software..." -ForegroundColor Cyan
    
    $software = @()
    $ignored = 0

    $path64 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstall64 = Get-ItemProperty $path64 | Where-Object { $_.DisplayName -and $_.DisplayVersion }

    $path32 = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstall32 = Get-ItemProperty $path32 -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayVersion }

    foreach ($item in $uninstall64 + $uninstall32) {
        $software += [PSCustomObject]@{
            Name    = $item.DisplayName
            Version = $item.DisplayVersion
            Context = "$($item.Publisher) $($item.URLInfoAbout)"
        }
    }

    $windowsPath = [Environment]::ExpandEnvironmentVariables("%SystemRoot%")
    foreach ($service in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
        $executable = Get-ServiceExecutablePath $service.PathName
        if (-not $executable) { continue }
        if ($executable.StartsWith($windowsPath, [StringComparison]::OrdinalIgnoreCase)) {
            $ignored++
            continue
        }

        try {
            $versionInfo = (Get-Item -LiteralPath $executable -ErrorAction Stop).VersionInfo
        }
        catch {
            continue
        }
        if (-not $versionInfo.ProductName -or -not $versionInfo.ProductVersion) { continue }

        $software += [PSCustomObject]@{
            Name    = $versionInfo.ProductName
            Version = $versionInfo.ProductVersion
            Context = "$($versionInfo.CompanyName) $($versionInfo.FileDescription) $executable"
        }
    }

    $software = $software | Sort-Object -Property Name, Version -Unique
    
    Write-Host "✅ Found $($software.Count) installed software entries" -ForegroundColor Green
    return @{ 
        software = @($software)
        ignored = $ignored
    }
}

function Resolve-Software {
    param(
        [string]$SoftwareName,
        [string]$Version,
        [string]$Context = ""
    )
    
    try {
        $body = @{
            software = $SoftwareName
            version = $Version
            context = $Context
            platform = "windows"
        } | ConvertTo-Json
        return Invoke-RestMethod `
            -Uri "$($ApiUrl.TrimEnd('/'))/api/resolve" `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body $body `
            -TimeoutSec 10
    }
    catch {
        return [PSCustomObject]@{
            error = $_.Exception.Message
            matched_cpe = $null
            results = @()
        }
    }
}

function Get-CVSSSeverity {
    param([float]$Score)

    if ($null -eq $Score) { return "Unknown" }
    if ($Score -ge $CVSS_LEVELS.Critical) { return "Critical" }
    elseif ($Score -ge $CVSS_LEVELS.High) { return "High" }
    elseif ($Score -ge $CVSS_LEVELS.Medium) { return "Medium" }
    elseif ($Score -ge $CVSS_LEVELS.Low) { return "Low" }
    else { return "None" }
}

function Format-CVETable {
    param([array]$CVEs)

    if (-not $CVEs) { return }

    $CVEs | ForEach-Object {
        [PSCustomObject]@{
            "CVE ID"      = $_.cve_id
            "Severity"    = Get-CVSSSeverity -Score $_.cvss_score
            "CVSS Score"  = if ($_.cvss_score) { "{0:F1}" -f $_.cvss_score } else { "N/A" }
            "Version"     = $_.version
            "Published"   = ($_.published -split "T")[0]
            "Description" = if ($_.description.Length -gt 80) {
                $_.description.Substring(0,77) + "..."
            } else {
                $_.description
            }
        }
    }
}

function Request-ServerReport {
    param(
        [array]$Software,
        [string]$OutputPath
    )

    $payload = @{
        hostname = $env:COMPUTERNAME
        platform = "windows"
        software = @($Software | ForEach-Object {
            @{
                name = $_.Name
                version = $_.Version
                context = $_.Context
            }
        })
        options = @{ sploitscan = -not $NoSploitScan.IsPresent }
    } | ConvertTo-Json -Depth 5

    $job = Invoke-RestMethod `
        -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports" `
        -Method Post `
        -ContentType "application/json; charset=utf-8" `
        -Body $payload `
        -TimeoutSec 30

    $lastProgress = $null
    do {
        Start-Sleep -Seconds 2
        $status = Invoke-RestMethod `
            -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/$($job.id)" `
            -Method Get `
            -TimeoutSec 10
        $progress = "$($status.stage):$($status.processed):$($status.total)"
        if ($progress -ne $lastProgress) {
            Write-Host "  $($status.stage): $($status.processed)/$($status.total)"
            $lastProgress = $progress
        }
        if ($status.status -eq "failed") {
            throw "CVEWatchdog Server failed: $($status.error)"
        }
    } until ($status.status -eq "completed")

    if (-not $OutputPath) {
        return $null
    }

    $fullPath = [IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $fullPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Invoke-WebRequest `
        -Uri "$($ServerUrl.TrimEnd('/'))/api/v1/reports/$($job.id)/html" `
        -OutFile $fullPath `
        -UseBasicParsing `
        -TimeoutSec 60
    return $fullPath
}

if ($MyInvocation.InvocationName -eq '.') { return }

Write-Host "`n═════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                CVEWatchdog                "
Write-Host "═════════════════════════════════════════`n" -ForegroundColor Cyan

if ($ServerUrl) {
    Write-Host "🌐 Checking CVEWatchdog Server..." -ForegroundColor Cyan
    try {
        $health = Invoke-RestMethod -Uri "$($ServerUrl.TrimEnd('/'))/health" -Method Get -TimeoutSec 5
        Write-Host "✅ Server connected - FastCVE: $($health.fastcve)`n" -ForegroundColor Green
        $softwareData = Get-InstalledSoftware
        Write-Host "`n📡 Sending inventory to CVEWatchdog Server..." -ForegroundColor Cyan
        $reportPath = Request-ServerReport -Software $softwareData.software -OutputPath $HtmlReport
        if ($reportPath) {
            Write-Host "✅ HTML report downloaded to $reportPath" -ForegroundColor Green
        }
        else {
            Write-Host "✅ Server scan completed" -ForegroundColor Green
        }
        exit 0
    }
    catch {
        Write-Host "❌ Server report error: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "🌐 Checking API connectivity..." -ForegroundColor Cyan
try {
    $health = Invoke-RestMethod -Uri "$($ApiUrl.TrimEnd('/'))/health" -Method Get -TimeoutSec 5
    Write-Host "✅ API connected - $($health.cves_indexed) CVEs indexed`n" -ForegroundColor Green
}
catch {
    Write-Host "❌ Cannot connect to API at ${ApiUrl}: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$softwareData = Get-InstalledSoftware
$software = $softwareData.software
$ignoredCount = $softwareData.ignored

Write-Host "`n🔍 Searching for vulnerabilities...`n" -ForegroundColor Cyan

$softwareWithCVEs = @()
$allCVEs = @()
$apiMatches = 0
$apiErrors = 0

foreach ($app in $software) {
    $cveResult = Resolve-Software -SoftwareName $app.Name -Version $app.Version -Context $app.Context
    $cves = @($cveResult.results)

    if ($cveResult.error) {
        $apiErrors++
        Write-Host "✗ $($app.Name) ($($app.Version)) - API error: $($cveResult.error)" -ForegroundColor Red
        continue
    }

    if ($cveResult.matched_cpe) {
        $apiMatches++
        if ($DebugMatching) {
            Write-Host "↳ $($app.Name): $($cveResult.matched_cpe.cpe) (confidence $([math]::Round($cveResult.matched_cpe.score, 2)))" -ForegroundColor DarkGray
        }
    }

    if ($cves) {
        Write-Host "⚠️  $($app.Name) ($($app.Version)) - $($cves.Count) CVE(s) detected" -ForegroundColor Yellow

        $softwareWithCVEs += [PSCustomObject]@{
            Name    = $app.Name
            Version = $app.Version
            CPE     = $cveResult.matched_cpe.cpe
            CVEs    = $cves
        }

        $allCVEs += $cves
    }
    else {
        if ($DebugMatching -and -not $cveResult.matched_cpe) {
            Write-Host "? $($app.Name) ($($app.Version)) - Software not resolved" -ForegroundColor DarkGray
        }
        elseif ($DebugMatching) {
            Write-Host "✓ $($app.Name) ($($app.Version)) - No CVEs detected" -ForegroundColor Green
        }
    }
}

Write-Host "`n═════════════════════════════════════════"
Write-Host "            VULNERABILITY REPORT"
Write-Host "═════════════════════════════════════════`n"

if ($softwareWithCVEs.Count -eq 0) {
    Write-Host "✅ No vulnerabilities detected!" -ForegroundColor Green
}
else {
    foreach ($app in $softwareWithCVEs) {
        Write-Host "`n📌 $($app.Name) - Version: $($app.Version)" -ForegroundColor Magenta
        Write-Host "   CPE: $($app.CPE)" -ForegroundColor DarkGray
        Write-Host ("─" * 100)

        Format-CVETable -CVEs $app.CVEs | Format-Table -AutoSize
    }
}

Write-Host "`n═════════════════════════════════════════"
Write-Host "               SUMMARY"
Write-Host "═════════════════════════════════════════`n"

$totalCVEs = $allCVEs.Count
$criticalCount = @($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Critical" }).Count
$highCount     = @($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "High" }).Count
$mediumCount   = @($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Medium" }).Count
$lowCount      = @($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Low" }).Count
$unknownCount  = @($allCVEs | Where-Object { (Get-CVSSSeverity -Score $_.cvss_score) -eq "Unknown" }).Count

Write-Host "Software scanned        : $($software.Count)"
Write-Host "Software ignored        : $ignoredCount"
Write-Host "Software resolved       : $apiMatches"
Write-Host "API errors              : $apiErrors"
Write-Host ""
Write-Host "Total CVEs found        : $totalCVEs" -ForegroundColor Cyan
Write-Host "Critical vulnerabilities: $criticalCount" -ForegroundColor Black
Write-Host "High vulnerabilities     : $highCount" -ForegroundColor Red
Write-Host "Medium vulnerabilities   : $mediumCount" -ForegroundColor Yellow
Write-Host "Low vulnerabilities      : $lowCount" -ForegroundColor Green

if ($unknownCount -gt 0) {
    Write-Host "Unknown vulnerabilities  : $unknownCount" -ForegroundColor Gray
}

Write-Host ""

$riskLevel = "🟢 LOW RISK"
$riskColor = "Green"

if ($criticalCount -gt 0)     { $riskLevel = "⚫️ CRITICAL RISK"; $riskColor = "Black" }
elseif ($highCount -gt 3)     { $riskLevel = "🔴 HIGH RISK";     $riskColor = "Red" }
elseif ($highCount -gt 0)     { $riskLevel = "🟠 MEDIUM RISK";   $riskColor = "Yellow" }

Write-Host "Overall Risk Assessment : " -NoNewline
Write-Host $riskLevel -ForegroundColor $riskColor
Write-Host "`n"
