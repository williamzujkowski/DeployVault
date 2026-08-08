#requires -Version 5.1
Set-StrictMode -Version 2.0

# ==============================================================================
# Script: DeployVault.ps1
# Description: Production-grade credential vault engine using AES-256-CBC,
#              HMAC-SHA256, atomic file swaps, process locks, & memory hygiene.
# Binary Magic Tag: VLT3 (0x56, 0x4C, 0x54, 0x33)
# ==============================================================================

# Script Constants
$script:VaultMagic = [byte[]](0x56, 0x4C, 0x54, 0x33)
$script:VaultVersion = 3
$script:VaultHeaderLength = 24 # Magic(4), Version(1), Algorithm(1), Reserved(2), IV(16)
$script:VaultTagLength = 32    # HMAC-SHA256 tag length
$script:VaultMaxBytes = 10MB   # Payload safety cap

# ==============================================================================
# SECTION 1: CRYPTOGRAPHIC CORE & MEMORY HYGIENE
# ==============================================================================

function Clear-VaultBytes {
    # Overwrites sensitive byte arrays in memory with zeroes
    param([byte[]]$Bytes)
    if ($null -ne $Bytes) { [Array]::Clear($Bytes, 0, $Bytes.Length) }
}

function Test-VaultFixedTimeEqual {
    # Performs constant-time byte comparison to prevent HMAC timing side-channel attacks
    param([byte[]]$Left, [byte[]]$Right)
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    [int]$difference = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $difference = $difference -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($difference -eq 0)
}

function Get-VaultMasterBytes {
    # Derives 64 master key bytes (32B AES + 32B HMAC) via PBKDF2 with 100,000 iterations
    param([Parameter(Mandatory = $true)][string]$SeedPath)

    if (-not (Test-Path -LiteralPath $SeedPath -PathType Leaf)) {
        throw "Master seed file is missing at: $SeedPath"
    }
    [byte[]]$rawSeed = [System.IO.File]::ReadAllBytes($SeedPath)
    try {
        if ($rawSeed.Length -ne 64) { throw "Invalid seed length. Expected 64 bytes." }
        [byte[]]$salt = $rawSeed[0..31]
        [byte[]]$secret = $rawSeed[32..63]
        try {
            $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($secret, $salt, 100000)
            try { return $pbkdf2.GetBytes(64) } finally { $pbkdf2.Dispose() }
        }
        finally {
            Clear-VaultBytes $salt
            Clear-VaultBytes $secret
        }
    }
    finally { Clear-VaultBytes $rawSeed }
}

function New-VaultSeedFile {
    # Generates 64 high-entropy random bytes and writes to a new seed file
    param([Parameter(Mandatory = $true)][string]$Path)

    [byte[]]$seed = New-Object byte[] 64
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($seed)
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($seed, 0, $seed.Length)
            $stream.Flush($true)
        }
        finally { $stream.Dispose() }
    }
    finally {
        $rng.Dispose()
        Clear-VaultBytes $seed
    }
}

function Set-VaultSeedAttributes {
    # Sets Hidden and System file attributes to reduce accidental exposure/deletion
    param([Parameter(Mandatory = $true)][string]$SeedPath)

    if (-not (Test-Path -LiteralPath $SeedPath -PathType Leaf)) {
        throw "Cannot set attributes on a missing seed: $SeedPath"
    }
    $item = Get-Item -LiteralPath $SeedPath -Force
    $item.Attributes = $item.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System
}

function Assert-VaultSafeLogging {
    # Inspects registry policy & active global transcripts to prevent credential logging
    [CmdletBinding()] param()

    $policyPaths = @(
        "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription",
        "HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
    )
    foreach ($path in $policyPaths) {
        $policy = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -ne $policy -and [int]$policy.EnableTranscripting -eq 1) {
            throw "PowerShell transcription policy is enabled. Secret operations are blocked."
        }
    }
    $tVar = Get-Variable -Name Transcript -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $tVar -and $tVar.Value) {
        throw "An active transcript indicator was detected. Stop transcription before running vault operations."
    }
    return $true
}

# ==============================================================================
# SECTION 2: CONCURRENCY LOCKING & FILE UTILITIES
# ==============================================================================

function Open-VaultLock {
    # Acquires exclusive .lock file with deadline retries to prevent race conditions
    param([Parameter(Mandatory = $true)][string]$VaultPath, [int]$TimeoutSeconds = 30)

    $lockPath = "$VaultPath.lock"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            return [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out acquiring vault lock: $lockPath" }
            Start-Sleep -Milliseconds 100
        }
    } while ($true)
}

function Write-VaultFileRaw {
    # Writes raw payload bytes to a specified file path with exclusive access
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][byte[]]$Payload)

    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Payload, 0, $Payload.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Protect-VaultBackupDirectory {
    # Locks backup directory ACLs exclusively to Current Identity, SYSTEM, and Administrators
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $sec = New-Object System.Security.AccessControl.DirectorySecurity
    $sec.SetAccessRuleProtection($true, $false)

    foreach ($user in @($identity, "BUILTIN\Administrators", "NT AUTHORITY\SYSTEM") | Select-Object -Unique) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $sec.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $resolved -AclObject $sec
}

# ==============================================================================
# SECTION 3: PAYLOAD ENCRYPTION, DECRYPTION & SCHEMAS
# ==============================================================================

function ConvertTo-VaultPayload {
    # Builds JSON envelope, encrypts AES-256-CBC, and prepends magic header + HMAC tag
    param(
        [AllowEmptyCollection()][array]$Entries = @(),
        [Parameter(Mandatory = $true)][byte[]]$MasterBytes,
        [string]$VaultId = [guid]::NewGuid().ToString("D"),
        [string]$KeyId = [guid]::NewGuid().ToString("D"),
        [long]$Generation = 1
    )

    foreach ($entry in $Entries) {
        if ($entry.PSObject.Properties.Name -contains "ExpiresUtc") {
            $entry.PSObject.Properties.Remove("ExpiresUtc")
        }
    }

    $envelope = [ordered]@{
        SchemaVersion = 3
        VaultId       = $VaultId
        KeyId         = $KeyId
        Generation    = $Generation
        WrittenUtc    = [DateTime]::UtcNow.ToString("o")
        Entries       = @($Entries)
    }

    $json = $envelope | ConvertTo-Json -Depth 8 -Compress
    [byte[]]$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    [byte[]]$aesKey = $MasterBytes[0..31]
    [byte[]]$hmacKey = $MasterBytes[32..63]

    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Key = $aesKey
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()

        $encryptor = $aes.CreateEncryptor()
        try { [byte[]]$cipher = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length) }
        finally { $encryptor.Dispose() }

        # Header Structure: [Magic 4B][Version 1B][Algorithm 1B][Reserved 2B][IV 16B]
        [byte[]]$header = New-Object byte[] $script:VaultHeaderLength
        [Array]::Copy($script:VaultMagic, 0, $header, 0, 4)
        $header[4] = $script:VaultVersion
        $header[5] = 1 # AES-256-CBC + HMAC-SHA256
        [Array]::Copy($aes.IV, 0, $header, 8, 16)

        # Authenticate Header + Ciphertext with HMAC-SHA256
        $authenticated = $header + $cipher
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $hmacKey)
        try { [byte[]]$tag = $hmac.ComputeHash($authenticated) }
        finally {
            $hmac.Dispose()
            Clear-VaultBytes $authenticated
        }

        return ($header + $tag + $cipher)
    }
    finally {
        $aes.Dispose()
        Clear-VaultBytes $plainBytes
        Clear-VaultBytes $aesKey
        Clear-VaultBytes $hmacKey
        $json = $null
    }
}

function ConvertFrom-VaultPayload {
    # Validates magic header, checks HMAC tag in constant time, decrypts AES, & parses envelope
    param([Parameter(Mandatory = $true)][byte[]]$Payload, [Parameter(Mandatory = $true)][byte[]]$MasterBytes, [switch]$ReturnEnvelope)

    if ($Payload.Length -lt ($script:VaultHeaderLength + $script:VaultTagLength + 16)) { throw "Truncated binary payload." }
    if ($Payload.Length -gt $script:VaultMaxBytes) { throw "Payload exceeds 10 MB limit." }
    for ($i = 0; $i -lt 4; $i++) {
        if ($Payload[$i] -ne $script:VaultMagic[$i]) { throw "Magic header mismatch." }
    }
    if ($Payload[4] -ne $script:VaultVersion -or $Payload[5] -ne 1) { throw "Unsupported version/algorithm." }

    [byte[]]$header = $Payload[0..($script:VaultHeaderLength - 1)]
    [byte[]]$storedTag = $Payload[$script:VaultHeaderLength..($script:VaultHeaderLength + 31)]
    [byte[]]$cipher = $Payload[($script:VaultHeaderLength + $script:VaultTagLength)..($Payload.Length - 1)]
    [byte[]]$aesKey = $MasterBytes[0..31]
    [byte[]]$hmacKey = $MasterBytes[32..63]

    try {
        # Verify HMAC tag in constant time
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $hmacKey)
        try { [byte[]]$computedTag = $hmac.ComputeHash($header + $cipher) }
        finally { $hmac.Dispose() }

        try {
            if (-not (Test-VaultFixedTimeEqual $storedTag $computedTag)) {
                throw "Integrity check failed! Key mismatch or payload tampered."
            }
        }
        finally { Clear-VaultBytes $computedTag }

        # Decrypt AES-256-CBC payload
        $aes = [System.Security.Cryptography.Aes]::Create()
        try {
            $aes.Key = $aesKey; $aes.IV = $header[8..23]
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $dec = $aes.CreateDecryptor()
            try { [byte[]]$plainBytes = $dec.TransformFinalBlock($cipher, 0, $cipher.Length) }
            finally { $dec.Dispose() }
        }
        finally { $aes.Dispose() }

        # Parse JSON envelope schema
        try {
            $json = [System.Text.Encoding]::UTF8.GetString($plainBytes)
            $envelope = $json | ConvertFrom-Json

            if ($envelope.SchemaVersion -ne 3 -or $null -eq $envelope.Entries) { throw "Invalid envelope schema." }
            [guid]::Parse([string]$envelope.VaultId) | Out-Null

            if ($envelope.PSObject.Properties.Name -contains "KeyId") { [guid]::Parse([string]$envelope.KeyId) | Out-Null }
            if ($envelope.PSObject.Properties.Name -contains "Generation" -and [long]$envelope.Generation -lt 1) { throw "Invalid generation counter." }

            Test-VaultEntries -Entries @($envelope.Entries) | Out-Null
            if ($ReturnEnvelope) { return $envelope }
            return @($envelope.Entries)
        }
        finally {
            Clear-VaultBytes $plainBytes
            $json = $null
        }
    }
    finally {
        Clear-VaultBytes $header; Clear-VaultBytes $storedTag; Clear-VaultBytes $cipher; Clear-VaultBytes $aesKey; Clear-VaultBytes $hmacKey
    }
}

function Test-VaultEntries {
    # Validates credential entry schema, required fields, and Regex ID patterns
    param([AllowEmptyCollection()][array]$Entries = @())

    $ids = @{}
    foreach ($entry in $Entries) {
        foreach ($required in @("Id", "Username", "Password", "Enabled")) {
            if (-not ($entry.PSObject.Properties.Name -contains $required)) { throw "Entry missing field '$required'." }
        }
        $id = [string]$entry.Id
        if ($id -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw "Invalid ID format: '$id'." }
        if ($ids.ContainsKey($id)) { throw "Duplicate ID: $id" }
        $ids[$id] = $true

        if ([string]::IsNullOrWhiteSpace([string]$entry.Username) -or ([string]$entry.Username).Length -gt 512) { throw "Invalid username for '$id'." }
        if ($null -eq $entry.Password -or ([string]$entry.Password).Length -gt 4096) { throw "Invalid password size for '$id'." }
    }
    return $true
}

function Read-VaultEnvelope {
    param([string]$VaultPath, [string]$SeedPath)
    [byte[]]$master = Get-VaultMasterBytes -SeedPath $SeedPath
    [byte[]]$payload = $null
    try {
        $payload = [System.IO.File]::ReadAllBytes($VaultPath)
        return ConvertFrom-VaultPayload -Payload $payload -MasterBytes $master -ReturnEnvelope
    }
    finally {
        Clear-VaultBytes $payload
        Clear-VaultBytes $master
    }
}

function Read-VaultEntries {
    param([string]$VaultPath, [string]$SeedPath)
    return @((Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath).Entries)
}

function Write-VaultEntries {
    # Atomic temp-write + pre-commit round-trip verification + atomic replace
    param([string]$VaultPath, [string]$SeedPath, [AllowEmptyCollection()][array]$Entries = @(), [switch]$LockAlreadyHeld)

    $lock = $null; [byte[]]$master = $null; [byte[]]$payload = $null
    $temporary = "$VaultPath.$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$VaultPath.bak"

    try {
        if (-not $LockAlreadyHeld) { $lock = Open-VaultLock -VaultPath $VaultPath }
        $master = Get-VaultMasterBytes -SeedPath $SeedPath
        $vId = [guid]::NewGuid().ToString("D"); $kId = [guid]::NewGuid().ToString("D"); [long]$gen = 1

        if (Test-Path -LiteralPath $VaultPath) {
            $curEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath
            $vId = [string]$curEnv.VaultId
            if ($curEnv.PSObject.Properties.Name -contains "KeyId" -and $curEnv.KeyId) { $kId = [string]$curEnv.KeyId }
            $gen = if ($curEnv.PSObject.Properties.Name -contains "Generation") { [long]$curEnv.Generation + 1 } else { 2 }
        }

        Test-VaultEntries -Entries $Entries | Out-Null
        $payload = ConvertTo-VaultPayload -Entries $Entries -MasterBytes $master -VaultId $vId -KeyId $kId -Generation $gen
        Write-VaultFileRaw -Path $temporary -Payload $payload

        # Pre-commit verification: re-read and decrypt temp payload in memory before replacing live file
        [byte[]]$verification = [System.IO.File]::ReadAllBytes($temporary)
        try { ConvertFrom-VaultPayload -Payload $verification -MasterBytes $master | Out-Null }
        finally { Clear-VaultBytes $verification }

        # Atomic File Replace
        if (Test-Path -LiteralPath $VaultPath) { [System.IO.File]::Replace($temporary, $VaultPath, $backup, $true) }
        else { [System.IO.File]::Move($temporary, $VaultPath) }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
        Clear-VaultBytes $payload; Clear-VaultBytes $master
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

# ==============================================================================
# SECTION 4: CREDENTIAL CRUD CMDLETS
# ==============================================================================

function Initialize-Vault {
    # Initializes a new master seed and empty encrypted vault file pair
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath)

    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($VaultPath))
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    if (Test-Path -LiteralPath $SeedPath) { throw "Refusing to overwrite existing seed: $SeedPath" }
    if (Test-Path -LiteralPath $VaultPath) { throw "Refusing to overwrite existing vault: $VaultPath" }

    $seedParent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($SeedPath))
    if (-not (Test-Path -LiteralPath $seedParent -PathType Container)) { New-Item -ItemType Directory -Path $seedParent -Force | Out-Null }

    New-VaultSeedFile -Path $SeedPath
    try {
        Set-VaultSeedAttributes -SeedPath $SeedPath
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries @()
    }
    catch {
        Remove-Item -LiteralPath $SeedPath -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Set-VaultCredential {
    # Adds or updates a credential entry in the vault
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VaultPath,
        [Parameter(Mandatory = $true)][string]$SeedPath,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')][string]$CredentialId,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Password,
        [string]$Description = "",
        [bool]$Enabled = $true
    )

    Assert-VaultSafeLogging | Out-Null
    $lock = Open-VaultLock -VaultPath $VaultPath
    $bstr = [System.IntPtr]::Zero; $plainPassword = $null

    try {
        $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $now = [DateTime]::UtcNow.ToString("o")

        $existing = @($entries | Where-Object { $_.Id -eq $CredentialId })
        if ($existing.Count -gt 1) { throw "Duplicate credential IDs: $CredentialId" }
        if ($existing.Count -eq 1) {
            $existing[0].Username = $Username; $existing[0].Password = $plainPassword; $existing[0].Description = $Description; $existing[0].Enabled = $Enabled; $existing[0].LastUpdatedUtc = $now
        }
        else {
            $entries += [pscustomobject][ordered]@{
                Id = $CredentialId; Username = $Username; Password = $plainPassword; Description = $Description; Enabled = $Enabled; CreatedUtc = $now; LastUpdatedUtc = $now
            }
        }
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries $entries -LockAlreadyHeld
    }
    finally {
        if ($bstr -ne [System.IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $plainPassword = $null; $entries = $null; $lock.Dispose()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-VaultCredential {
    # Retrieves a credential as a PSCredential object
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$CredentialId)

    Assert-VaultSafeLogging | Out-Null
    $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
    try {
        $matches = @($entries | Where-Object { $_.Id -eq $CredentialId })
        if ($matches.Count -ne 1) { throw "Credential '$CredentialId' was not found or is duplicated." }
        if (-not [bool]$matches[0].Enabled) { throw "Credential '$CredentialId' is disabled." }
        $securePassword = ConvertTo-SecureString ([string]$matches[0].Password) -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential([string]$matches[0].Username, $securePassword)
    }
    finally {
        $entries = $null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

function Get-VaultSummary {
    # Returns a list of non-sensitive credential metadata (excluding password values)
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath)

    $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
    try { return $entries | Select-Object Id, Username, Description, Enabled, CreatedUtc, LastUpdatedUtc }
    finally { $entries = $null }
}

function Remove-VaultCredential {
    # Removes a credential entry from the vault by ID
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$CredentialId)

    $lock = Open-VaultLock -VaultPath $VaultPath
    try {
        $entries = @(Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath)
        $filtered = @($entries | Where-Object { $_.Id -ne $CredentialId })
        if ($filtered.Count -eq $entries.Count) { throw "Credential '$CredentialId' was not found." }
        Write-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath -Entries $filtered -LockAlreadyHeld
    }
    finally { $entries = $null; $filtered = $null; $lock.Dispose() }
}

# ==============================================================================
# SECTION 5: LIFECYCLE OPERATIONS (BACKUP, SEED ROTATION & RESTORE)
# ==============================================================================

function Backup-Vault {
    # Creates a timestamped backup pair with ACL lockdown and retention purging
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$BackupDirectory, [ValidateRange(1, 100)][int]$RetentionCount = 10)

    $lock = Open-VaultLock -VaultPath $VaultPath
    try {
        Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath | Out-Null
        if (-not (Test-Path -LiteralPath $BackupDirectory)) { New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null }
        Protect-VaultBackupDirectory -Path $BackupDirectory

        $stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
        $vaultBackup = Join-Path $BackupDirectory "vault-$stamp.bin"
        $seedBackup = Join-Path $BackupDirectory "seed-$stamp.bin"

        Copy-Item -LiteralPath $VaultPath -Destination $vaultBackup
        Copy-Item -LiteralPath $SeedPath -Destination $seedBackup
        Set-VaultSeedAttributes -SeedPath $seedBackup

        # Enforce retention policy
        $pairs = @(Get-ChildItem -LiteralPath $BackupDirectory -Filter "vault-*.bin" | Sort-Object Name -Descending)
        foreach ($oldVault in @($pairs | Select-Object -Skip $RetentionCount)) {
            $oldStamp = $oldVault.BaseName.Substring(6)
            $oldSeed = Join-Path $BackupDirectory "seed-$oldStamp.bin"
            Remove-Item -LiteralPath $oldVault.FullName -Force
            if (Test-Path -LiteralPath $oldSeed) { Remove-Item -LiteralPath $oldSeed -Force }
        }
        return [pscustomobject]@{ VaultBackup = $vaultBackup; SeedBackup = $seedBackup }
    }
    finally { $lock.Dispose() }
}

function Invoke-VaultAtomicSwap {
    # Helper for atomic replacement & rollback of vault & seed pairs
    param(
        [string]$VaultPath, [string]$SeedPath,
        [string]$CandVault, [string]$CandSeed,
        [string]$VaultBakExt, [string]$SeedBakExt
    )
    $sRec = "$SeedPath.$SeedBakExt"; $vRec = "$VaultPath.$VaultBakExt"
    Remove-Item -LiteralPath $sRec, $vRec -Force -ErrorAction SilentlyContinue
    try {
        [System.IO.File]::Replace($CandSeed, $SeedPath, $sRec, $true)
        [System.IO.File]::Replace($CandVault, $VaultPath, $vRec, $true)
        Set-VaultSeedAttributes -SeedPath $SeedPath
        Set-VaultSeedAttributes -SeedPath $sRec
        Read-VaultEntries -VaultPath $VaultPath -SeedPath $SeedPath | Out-Null
        return [pscustomobject]@{ SeedRecovery = $sRec; VaultRecovery = $vRec }
    }
    catch {
        if (Test-Path -LiteralPath $sRec) { Copy-Item -LiteralPath $sRec -Destination $SeedPath -Force }
        if (Test-Path -LiteralPath $vRec) { Copy-Item -LiteralPath $vRec -Destination $VaultPath -Force }
        throw
    }
}

function Invoke-VaultSeedRotation {
    # Zero-downtime seed rotation under exclusive lock with automatic safety rollback
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath)

    if (-not $PSCmdlet.ShouldProcess($VaultPath, "rotate seed and re-encrypt vault")) { return }

    $lock = Open-VaultLock -VaultPath $VaultPath
    $candSeed = "$SeedPath.$([guid]::NewGuid().ToString('N')).tmp"
    $candVault = "$VaultPath.$([guid]::NewGuid().ToString('N')).tmp"
    [byte[]]$newMaster = $null; [byte[]]$newPayload = $null

    try {
        $curEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath
        New-VaultSeedFile -Path $candSeed
        $newMaster = Get-VaultMasterBytes -SeedPath $candSeed
        $nextGen = if ($curEnv.PSObject.Properties.Name -contains "Generation") { [long]$curEnv.Generation + 1 } else { 2 }

        $newPayload = ConvertTo-VaultPayload -Entries @($curEnv.Entries) -MasterBytes $newMaster -VaultId ([string]$curEnv.VaultId) -KeyId ([guid]::NewGuid().ToString("D")) -Generation $nextGen
        Write-VaultFileRaw -Path $candVault -Payload $newPayload

        # Pre-commit verify candidate pair
        [byte[]]$verification = [System.IO.File]::ReadAllBytes($candVault)
        try { ConvertFrom-VaultPayload -Payload $verification -MasterBytes $newMaster | Out-Null }
        finally { Clear-VaultBytes $verification }

        return Invoke-VaultAtomicSwap -VaultPath $VaultPath -SeedPath $SeedPath -CandVault $candVault -CandSeed $candSeed -VaultBakExt "rotation.bak" -SeedBakExt "rotation.bak"
    }
    finally {
        foreach ($t in @($candSeed, $candVault)) { if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } }
        Clear-VaultBytes $newMaster; Clear-VaultBytes $newPayload; $lock.Dispose()
    }
}

function Restore-Vault {
    # Restores a validated vault and seed backup pair after verifying schema identity and generation
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param([Parameter(Mandatory = $true)][string]$VaultPath, [Parameter(Mandatory = $true)][string]$SeedPath, [Parameter(Mandatory = $true)][string]$VaultBackup, [Parameter(Mandatory = $true)][string]$SeedBackup)

    if (-not $PSCmdlet.ShouldProcess($VaultPath, "restore vault and seed backup")) { return }

    $lock = Open-VaultLock -VaultPath $VaultPath
    $candVault = "$VaultPath.$([guid]::NewGuid().ToString('N')).restore.tmp"
    $candSeed = "$SeedPath.$([guid]::NewGuid().ToString('N')).restore.tmp"

    try {
        Copy-Item -LiteralPath $VaultBackup -Destination $candVault
        Copy-Item -LiteralPath $SeedBackup -Destination $candSeed
        $candEnv = Read-VaultEnvelope -VaultPath $candVault -SeedPath $candSeed

        $swap = Invoke-VaultAtomicSwap -VaultPath $VaultPath -SeedPath $SeedPath -CandVault $candVault -CandSeed $candSeed -VaultBakExt "pre-restore" -SeedBakExt "pre-restore"
        $liveEnv = Read-VaultEnvelope -VaultPath $VaultPath -SeedPath $SeedPath
        if ([string]$liveEnv.VaultId -ne [string]$candEnv.VaultId -or [long]$liveEnv.Generation -ne [long]$candEnv.Generation) {
            throw "Restored vault metadata does not match candidate envelope."
        }
        return $swap
    }
    finally {
        foreach ($t in @($candVault, $candSeed)) { if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue } }
        $lock.Dispose()
    }
}
