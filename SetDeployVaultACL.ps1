#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)][string]$VaultDirectory,
    [Parameter(Mandatory = $true)][string[]]$ReadIdentities,
    [string[]]$AdminIdentities = @("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM")
)

# Require Elevated Administrator Privilege
$principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SetDeployVaultACL.ps1 requires an elevated PowerShell Administrator session."
}

# Resolve Path and Verify Files
$resolvedDirectory = (Resolve-Path -LiteralPath $VaultDirectory).Path
$seedFile = Join-Path $resolvedDirectory "localseed.bin"
$vaultFile = Join-Path $resolvedDirectory "localvault.bin"

foreach ($target in @($resolvedDirectory, $seedFile, $vaultFile)) {
    if (-not (Test-Path -LiteralPath $target)) {
        throw "Target path missing: $target"
    }
}

if (-not $PSCmdlet.ShouldProcess($resolvedDirectory, "replace inherited ACLs on the vault directory and files")) {
    return
}

# Apply Directory ACLs
$dirSec = New-Object System.Security.AccessControl.DirectorySecurity
$dirSec.SetAccessRuleProtection($true, $false) # Break inheritance

foreach ($admin in $AdminIdentities) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $admin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $dirSec.AddAccessRule($rule)
}

foreach ($reader in $ReadIdentities) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $reader, "ReadAndExecute,Synchronize", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $dirSec.AddAccessRule($rule)
}

Set-Acl -LiteralPath $resolvedDirectory -AclObject $dirSec

# Apply Explicit File ACLs (Seed & Vault)
foreach ($file in @($seedFile, $vaultFile)) {
    $fileSec = New-Object System.Security.AccessControl.FileSecurity
    $fileSec.SetAccessRuleProtection($true, $false)

    foreach ($admin in $AdminIdentities) {
        $fileSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $admin, "FullControl", "Allow"
        )))
    }
    foreach ($reader in $ReadIdentities) {
        $fileSec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $reader, "Read,Synchronize", "Allow"
        )))
    }
    Set-Acl -LiteralPath $file -AclObject $fileSec
}

# Maintain Hidden + System Seed File Attributes
$seedItem = Get-Item -LiteralPath $seedFile -Force
$seedItem.Attributes = $seedItem.Attributes `
    -bor [System.IO.FileAttributes]::Hidden `
    -bor [System.IO.FileAttributes]::System

Write-Host "SUCCESS: DeployVault ACLs successfully applied to directory and files." -ForegroundColor Green
Write-Host "  - Administrators (Full Control): $($AdminIdentities -join ', ')" -ForegroundColor Gray
Write-Host "  - Deployment Readers (Read-Only): $($ReadIdentities -join ', ')" -ForegroundColor Gray
