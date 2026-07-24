param(
    [string]$Repo,
    [string]$Steps,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

if (-not $Repo) {
    $Repo = Split-Path -Leaf (Get-Location)
}

if ($env:EXPECTED_REPO -and $env:EXPECTED_REPO -ne $Repo) {
    Write-Error "Contexte invalide : $env:EXPECTED_REPO attendu $Repo"
    exit 1
}

$kivaArgs = @('ci', 'run', $Repo)
if ($DryRun) { $kivaArgs += '--dry-run' }
if ($env:KIVA_CI -eq '1') { $kivaArgs += '--ci' }
if ($Steps) { $kivaArgs += @('--steps', $Steps) }

Write-Host "[KIVA-CLI] Pipeline CI locale pour $Repo"
& python -m kiva_cli.kiva @kivaArgs
exit $LASTEXITCODE
