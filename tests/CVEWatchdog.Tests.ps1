$scriptPath = Join-Path $PSScriptRoot "..\CVEWatchdog.ps1"
. $scriptPath

Describe "Resolve-Software" {
    It "uses the shared FastCVE-API endpoint" {
        Mock Invoke-RestMethod {
            [PSCustomObject]@{ matched_cpe = $null; results = @() }
        }

        Resolve-Software -SoftwareName "VLC media player" -Version "3.0.21"

        Should -Invoke Invoke-RestMethod -Times 1 -ParameterFilter {
            $Uri -eq "http://localhost:8001/api/resolve" -and
            $Method -eq "Post" -and
            ($Body | ConvertFrom-Json).software -eq "VLC media player" -and
            ($Body | ConvertFrom-Json).version -eq "3.0.21"
        }
    }
}
