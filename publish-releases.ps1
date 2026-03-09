# Publish GitHub Releases v2.1.0 and v2.3.0 with the correct assets.
# v2.2.0 may already exist on GitHub; add winrmconfig_v2.2.ps1 manually if needed.
# Requires: $env:GITHUB_TOKEN with repo scope.
# Run from repo root: .\publish-releases.ps1

$ErrorActionPreference = "Stop"
$repo = "Uniao-Geek/WinRM-Log-Collector"
$token = $env:GITHUB_TOKEN
if (-not $token) {
    Write-Host "Set env: `$env:GITHUB_TOKEN = 'your_github_token'" -ForegroundColor Yellow
    Write-Host "Then run again. Or create releases manually at https://github.com/$repo/releases" -ForegroundColor Yellow
    exit 1
}

$headers = @{
    "Authorization" = "token $token"
    "Accept"        = "application/vnd.github.v3+json"
}

function New-GHRelease {
    param([string]$Tag, [string]$Title, [string]$Body, [string[]]$AssetPaths)
    $uri = "https://api.github.com/repos/$repo/releases"
    $body = @{ tag_name = $Tag; name = $Title; body = $Body } | ConvertTo-Json
    try {
        $r = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ContentType "application/json; charset=utf-8"
    } catch {
        if ($_.Exception.Message -match "already_exists") { Write-Host "Release $Tag already exists; skipping." -ForegroundColor Yellow; return }
        throw
    }
    foreach ($path in $AssetPaths) {
        if (-not (Test-Path $path)) { Write-Warning "Asset not found: $path"; continue }
        $name = [System.IO.Path]::GetFileName($path)
        $uploadUri = "https://uploads.github.com/repos/$repo/releases/$($r.id)/assets?name=$name"
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $path))
        Invoke-RestMethod -Uri $uploadUri -Method Post -Headers @{ "Authorization" = "token $token"; "Content-Type" = "application/octet-stream" } -Body $bytes
        Write-Host "Uploaded: $name" -ForegroundColor Green
    }
    Write-Host "Release $Tag created." -ForegroundColor Green
}

New-GHRelease -Tag "v2.1.0" -Title "v2.1.0" -Body "WinRM Log Collector v2.1. Single file: winrmconfig_v2.1.ps1" -AssetPaths @("winrmconfig_v2.1.ps1")
New-GHRelease -Tag "v2.3.0" -Title "v2.3.0" -Body "WinRM Log Collector v2.3. Canonical script: winrmconfig.ps1 (version in script). README.md included. From this release onward, use winrmconfig.ps1 + README.md." -AssetPaths @("winrmconfig.ps1", "README.md")
Write-Host "For v2.2.0: if release exists with no assets, add winrmconfig_v2.2.ps1 via GitHub Releases UI." -ForegroundColor Cyan
