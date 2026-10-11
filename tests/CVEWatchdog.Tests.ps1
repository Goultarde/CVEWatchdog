$scriptPath = Join-Path $PSScriptRoot "..\CVEWatchdog.ps1"
. $scriptPath

Describe "Get-ServiceExecutablePath" {
    It "extracts quoted and unquoted service executables" {
        Get-ServiceExecutablePath '"C:\Program Files\Agent\agent.exe" service --run' |
            Should -Be 'C:\Program Files\Agent\agent.exe'
        Get-ServiceExecutablePath 'C:\Program Files\Agent\agent.exe service --run' |
            Should -Be 'C:\Program Files\Agent\agent.exe'
    }
}

Describe "Resolve-Software" {
    It "uses the shared FastCVE-API endpoint" {
        Mock Invoke-RestMethod {
            [PSCustomObject]@{ matched_cpe = $null; results = @() }
        }

        Resolve-Software -SoftwareName "VLC media player" -Version "3.0.21" -Context "VideoLAN"

        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq "http://localhost:8001/api/resolve" -and
            $Method -eq "Post" -and
            $ContentType -eq "application/json; charset=utf-8" -and
            ($Body | ConvertFrom-Json).software -eq "VLC media player" -and
            ($Body | ConvertFrom-Json).version -eq "3.0.21" -and
            ($Body | ConvertFrom-Json).context -eq "VideoLAN" -and
            ($Body | ConvertFrom-Json).platform -eq "windows"
        }
    }
}

Describe "Request-ServerReport" {
    It "submits a Windows inventory and downloads the completed report" {
        $script:ServerUrl = "http://server:8002"
        $script:NoSploitScan = $false
        $script:statusCalls = 0
        $script:progressMessages = @()
        Mock Start-Sleep {}
        Mock Test-Path { $true }
        Mock Write-Host { $script:progressMessages += [string]$Object }
        Mock Invoke-RestMethod {
            if ($Uri -like "*/api/v1/reports/*") {
                $script:statusCalls++
                if ($script:statusCalls -lt 3) {
                    return [PSCustomObject]@{
                        id = "job-1"; status = "running"; stage = "SploitScan enrichment"; processed = 0; total = 61
                    }
                }
                return [PSCustomObject]@{
                    id = "job-1"; status = "completed"; stage = "completed"; processed = 61; total = 61
                }
            }
            return [PSCustomObject]@{ id = "job-1" }
        }
        Mock Invoke-WebRequest {}

        Request-ServerReport -Software @([PSCustomObject]@{
            Name = "VLC media player"; Version = "3.0.21"; Context = "VideoLAN"
        }) -OutputPath "report.html"

        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
            $Method -eq "Post" -and
            $Uri -eq "http://server:8002/api/v1/reports" -and
            ($Body | ConvertFrom-Json).platform -eq "windows" -and
            ($Body | ConvertFrom-Json).software[0].name -eq "VLC media player"
        }
        Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
            $Uri -eq "http://server:8002/api/v1/reports/job-1/html"
        }
        @($script:progressMessages | Where-Object { $_ -eq "  SploitScan enrichment: 0/61" }).Count |
            Should -Be 1
        @($script:progressMessages | Where-Object { $_ -eq "  completed: 61/61" }).Count |
            Should -Be 1
    }
}
