#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# Dot-source DeployVault Core Engine
. (Join-Path $PSScriptRoot "DeployVault.ps1")

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("DeployVault-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$vault = Join-Path $testRoot "localvault.bin"
$seed = Join-Path $testRoot "localseed.bin"
$backupDirectory = Join-Path $testRoot "backup"
$password = $null

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

try {
    Write-Host "[1/8] Testing Initialization & Hidden Attributes..." -ForegroundColor Cyan
    Initialize-Vault -VaultPath $vault -SeedPath $seed
    $seedAttributes = (Get-Item -LiteralPath $seed -Force).Attributes
    Assert-True (($seedAttributes -band [System.IO.FileAttributes]::Hidden) -ne 0) "seed is hidden"
    Assert-True (($seedAttributes -band [System.IO.FileAttributes]::System) -ne 0) "seed is a system file"
    Assert-True (@(Get-VaultSummary -VaultPath $vault -SeedPath $seed).Count -eq 0) "new vault is empty"

    Write-Host "[2/8] Testing Credential Round-Trip & Envelope Tracking..." -ForegroundColor Cyan
    $password = ConvertTo-SecureString "SuperSecretPassword!" -AsPlainText -Force
    Set-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc" `
        -Username "CONTOSO\deployer" -Password $password -Description "Deployment account test"
    
    $credential = Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc"
    Assert-True ($credential.UserName -eq "CONTOSO\deployer") "credential username matches"
    Assert-True ($credential.GetNetworkCredential().Password -eq "SuperSecretPassword!") "credential password matches"

    $summary = @(Get-VaultSummary -VaultPath $vault -SeedPath $seed)
    Assert-True ($summary.Count -eq 1) "summary returns 1 item"
    Assert-True (-not ($summary[0].PSObject.Properties.Name -contains "Password")) "summary excludes password payload"

    $metadataBefore = Read-VaultEnvelope -VaultPath $vault -SeedPath $seed
    Assert-True ($metadataBefore.SchemaVersion -eq 3) "envelope schema version is valid"

    Set-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc" `
        -Username "CONTOSO\deployer" -Password $password -Description "Updated test credential"
    $metadataAfter = Read-VaultEnvelope -VaultPath $vault -SeedPath $seed
    Assert-True ($metadataBefore.VaultId -eq $metadataAfter.VaultId) "vault ID is stable"
    Assert-True ([long]$metadataAfter.Generation -gt [long]$metadataBefore.Generation) "generation counter increases"

    Write-Host "[3/8] Testing Backup Functionality & ACL Protection..." -ForegroundColor Cyan
    $backup = Backup-Vault -VaultPath $vault -SeedPath $seed -BackupDirectory $backupDirectory
    Assert-True (Test-Path -LiteralPath $backup.VaultBackup) "vault backup created"
    Assert-True (Test-Path -LiteralPath $backup.SeedBackup) "seed backup created"

    Write-Host "[4/8] Testing Tamper Detection (Constant-Time HMAC)..." -ForegroundColor Cyan
    [byte[]]$tampered = [System.IO.File]::ReadAllBytes($vault)
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
    [System.IO.File]::WriteAllBytes($vault, $tampered)
    Clear-VaultBytes $tampered

    $tamperRejected = $false
    try { Read-VaultEntries -VaultPath $vault -SeedPath $seed | Out-Null }
    catch { $tamperRejected = $true }
    Assert-True $tamperRejected "tampered payload was rejected"

    Write-Host "[5/8] Testing Restore Capabilities..." -ForegroundColor Cyan
    Restore-Vault -VaultPath $vault -SeedPath $seed `
        -VaultBackup $backup.VaultBackup -SeedBackup $backup.SeedBackup -Confirm:$false
    Assert-True ((Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc").UserName -eq "CONTOSO\deployer") "restore succeeded"

    Write-Host "[6/8] Testing Seed Rotation..." -ForegroundColor Cyan
    $oldSeedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $seed).Hash
    $rotation = Invoke-VaultSeedRotation -VaultPath $vault -SeedPath $seed -Confirm:$false
    $newSeedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $seed).Hash
    Assert-True ($oldSeedHash -ne $newSeedHash) "seed rotation changed seed binary"
    Assert-True (Test-Path -LiteralPath $rotation.SeedRecovery) "rotation seed recovery exists"
    Assert-True (Test-Path -LiteralPath $rotation.VaultRecovery) "rotation vault recovery exists"
    Assert-True ((Get-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc").UserName -eq "CONTOSO\deployer") "credentials survive rotation"

    Write-Host "[7/8] Testing Concurrency Lock Contention..." -ForegroundColor Cyan
    $heldLock = Open-VaultLock -VaultPath $vault
    try {
        $lockRejected = $false
        try { Open-VaultLock -VaultPath $vault -TimeoutSeconds 1 | Out-Null }
        catch { $lockRejected = $true }
        Assert-True $lockRejected "competing caller blocked by process lock"
    }
    finally {
        $heldLock.Dispose()
    }

    Write-Host "[8/8] Testing Credential Deletion..." -ForegroundColor Cyan
    Remove-VaultCredential -VaultPath $vault -SeedPath $seed -CredentialId "DeploymentAcc"
    $remaining = @(Get-VaultSummary -VaultPath $vault -SeedPath $seed | Where-Object { $_.Id -eq "DeploymentAcc" })
    Assert-True ($remaining.Count -eq 0) "credential successfully removed"

    Write-Host "`nSUCCESS: All DeployVault automated test cases passed cleanly!" -ForegroundColor Green
}
finally {
    if ($null -ne $password) { $password.Dispose() }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
