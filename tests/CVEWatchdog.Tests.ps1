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
