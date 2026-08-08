#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$VaultDirectory = (Join-Path $PSScriptRoot "Vault"),
    [string]$CredentialId = "DomainJoin",
    [string]$Username = "CONTOSO\svc-domainjoin"
)

. (Join-Path $PSScriptRoot "DeployVault.ps1")
Assert-VaultSafeLogging | Out-Null

$seedPath = Join-Path $VaultDirectory "localseed.bin"
$vaultPath = Join-Path $VaultDirectory "localvault.bin"

if (-not (Test-Path -LiteralPath $vaultPath) -and -not (Test-Path -LiteralPath $seedPath)) {
    Initialize-Vault -VaultPath $vaultPath -SeedPath $seedPath
}
elseif (-not (Test-Path -LiteralPath $vaultPath) -or -not (Test-Path -LiteralPath $seedPath)) {
    throw "DeployVault initialization is incomplete. Both localvault.bin and localseed.bin must exist together."
}

$password = Read-Host "Enter password for '$CredentialId'" -AsSecureString
try {
    Set-VaultCredential -VaultPath $vaultPath -SeedPath $seedPath `
        -CredentialId $CredentialId -Username $Username -Password $password `
        -Description "Deployment credential"
}
finally {
    if ($null -ne $password) { $password.Dispose() }
}

Write-Host "DeployVault initialized successfully." -ForegroundColor Green
Get-VaultSummary -VaultPath $vaultPath -SeedPath $seedPath | Format-Table -AutoSize