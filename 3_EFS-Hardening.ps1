#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RDS hardening: one per-user encrypted + private folder (EFS), profile untouched.
.DESCRIPTION
    Creates a single "Private" folder in every user's profile that is:
      * EFS-encrypted with THAT user's key  -> the administrator cannot read the
        content (no Data Recovery Agent = truly unrecoverable by anyone else).
      * Locked down with NTFS: only the user + SYSTEM (Administrators removed).
      * Bound to this server: the EFS key lives in the local profile, so files
        copied off the box cannot be opened elsewhere.

    HOW IT WORKS
    EFS encrypts with the key of whoever performs the encryption, so it MUST run
    in the user's own context. This script therefore installs a per-user logon
    scheduled task (runs as the logging-on user) that creates/encrypts/locks the
    Private folder on each logon. The admin script itself only deploys that task;
    it does not (and cannot) encrypt other users' data from an admin context.

    PASSWORD RULE (important, by design):
      * Users MUST change their own password (Ctrl+Alt+End -> Change a password,
        they type the OLD one) -> DPAPI re-keys -> Private folder stays readable.
      * An ADMIN reset of a user's password DESTROYS that user's access to the
        Private folder (EFS key unrecoverable). Reset only for brand-new users or
        as an accepted-data-loss emergency.
.NOTES
    Run as Administrator on the RD Session Host. Windows-native (EFS), no 3rd-party.
    Applies to each user at their NEXT logon.
#>

param(
    # Name of the private folder created in each user profile.
    [string]$PrivateFolderName = "Private",
    # Also create/encrypt the folder for the admin running this script, right now.
    [switch]$ApplyToMeNow
)

$ErrorActionPreference = "Stop"

function Write-Step { param([string]$m) Write-Host "`n==== $m ====" -ForegroundColor Cyan }

# ------------------------------------------------------------------
# 0. Pre-flight
# ------------------------------------------------------------------
Write-Step "Pre-flight checks"

$sysDrive = $env:SystemDrive
$fs = (Get-Volume -DriveLetter $sysDrive.TrimEnd(':')).FileSystem
if ($fs -ne "NTFS") {
    Write-Host "[ERR] System drive is $fs, not NTFS - EFS requires NTFS. Aborting." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] System drive is NTFS." -ForegroundColor Green

# Ensure EFS is not disabled (EfsConfiguration: 1 = disabled)
$efsKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS"
if (-not (Test-Path $efsKey)) { New-Item -Path $efsKey -Force | Out-Null }
Set-ItemProperty -Path $efsKey -Name "EfsConfiguration" -Value 0 -Type DWord -Force
Write-Host "[OK] EFS enabled (EfsConfiguration=0)." -ForegroundColor Green

# ------------------------------------------------------------------
# 1. Report Data Recovery Agent (DRA) status
#    No DRA = the admin genuinely cannot recover/read. That is the goal.
# ------------------------------------------------------------------
Write-Step "EFS Data Recovery Agent (DRA) status"

$draPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\EFS\Certificates"
if (Test-Path $draPolicy -PathType Container) {
    $draCerts = @(Get-ChildItem $draPolicy -ErrorAction SilentlyContinue)
    if ($draCerts.Count -gt 0) {
        Write-Host "[WARN] A Data Recovery Agent is configured ($($draCerts.Count) cert(s))." -ForegroundColor Yellow
        Write-Host "       Whoever holds that DRA key CAN read every user's EFS files." -ForegroundColor Yellow
        Write-Host "       To make data truly private from admins, remove it:" -ForegroundColor Yellow
        Write-Host "       secpol.msc -> Public Key Policies -> Encrypting File System -> delete the agent." -ForegroundColor White
    } else {
        Write-Host "[OK] No DRA configured - EFS data is unrecoverable by admins (as intended)." -ForegroundColor Green
    }
} else {
    Write-Host "[OK] No DRA policy present - EFS data is unrecoverable by admins (as intended)." -ForegroundColor Green
}

# ------------------------------------------------------------------
# 2. Deploy the per-user logon script
# ------------------------------------------------------------------
Write-Step "Deploying per-user logon script"

$scriptDir  = "$env:ProgramData\RDS-Harden"
$userScript = Join-Path $scriptDir "Setup-PrivateFolder.ps1"
if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }

# This runs in EACH USER'S OWN CONTEXT (via the scheduled task below), so cipher
# uses that user's EFS key and icacls acts as the folder owner.
$perUser = @'
$ErrorActionPreference = "SilentlyContinue"
$folderName = "__PRIVATE_NAME__"
$priv = Join-Path $env:USERPROFILE $folderName

# 1. Create the folder if missing
if (-not (Test-Path $priv)) { New-Item -ItemType Directory -Path $priv -Force | Out-Null }

# 2. EFS-encrypt with THIS user's key (folder attribute + existing files).
#    Any new file dropped inside is auto-encrypted with the user's key.
cipher /e /s:"$priv" | Out-Null

# 3. Lock NTFS: break inheritance, grant only the user + SYSTEM (no Administrators).
$me = "$env:USERDOMAIN\$env:USERNAME"
icacls "$priv" /inheritance:r /grant:r "$me:(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
icacls "$priv" /setowner "$me" | Out-Null

# 4. One-time hint file (only on first run)
$readme = Join-Path $priv "_README.txt"
if (-not (Test-Path $readme)) {
@"
This folder is private and encrypted (Windows EFS) with YOUR account key.
- The administrator cannot read files placed here.
- Files here open ONLY on this server, under YOUR account.

CHANGE YOUR PASSWORD THE RIGHT WAY:
  Press Ctrl+Alt+End -> Change a password (you must know your current one).
  This keeps your encrypted files working.

WARNING: if an administrator RESETS your password (you forgot it), or your
profile is deleted, the files in this folder are lost forever - by design.
"@ | Set-Content -Path $readme -Encoding UTF8
}
'@
$perUser = $perUser.Replace("__PRIVATE_NAME__", $PrivateFolderName)

# Save the per-user script as UTF-8 with BOM (safe for Windows PowerShell 5.1)
$enc = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($userScript, $perUser, $enc)
Write-Host "[OK] Per-user script written: $userScript" -ForegroundColor Green

# Lock the script dir so users cannot tamper with it (read+execute only)
icacls "$scriptDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null

# ------------------------------------------------------------------
# 3. Register the per-user logon scheduled task (runs as each user)
# ------------------------------------------------------------------
Write-Step "Registering logon task (runs in each user's context)"

$taskName = "RDS-PrivateFolder"
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$userScript`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
# GroupId BUILTIN\Users => the task runs as whichever user logs on (their context).
$principal = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Create/encrypt/lock the per-user Private folder at logon (EFS)." | Out-Null
Write-Host "[OK] Scheduled task '$taskName' registered (trigger: At logon, run as: the user)." -ForegroundColor Green

# ------------------------------------------------------------------
# 4. Optionally apply to the current admin right now
# ------------------------------------------------------------------
if ($ApplyToMeNow) {
    Write-Step "Applying to current account now ($env:USERNAME)"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$userScript"
    Write-Host "[OK] Private folder created for $env:USERNAME at $env:USERPROFILE\$PrivateFolderName" -ForegroundColor Green
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Step "DONE"
Write-Host ""
Write-Host "  Each user gets: %USERPROFILE%\$PrivateFolderName" -ForegroundColor White
Write-Host "    - EFS-encrypted with their own key (admin cannot read content)" -ForegroundColor Green
Write-Host "    - NTFS locked to the user + SYSTEM (Administrators removed)" -ForegroundColor Green
Write-Host "    - Created automatically at each user's NEXT logon" -ForegroundColor Green
Write-Host ""
Write-Host "  PASSWORD RULES:" -ForegroundColor White
Write-Host "    - Users change their OWN password: Ctrl+Alt+End -> Change a password" -ForegroundColor Green
Write-Host "      (they must know the old one) -> encrypted files stay accessible." -ForegroundColor Gray
Write-Host "    - ADMIN password RESET destroys that user's Private folder access." -ForegroundColor Yellow
Write-Host "      Use reset only for new users or accepted-data-loss emergencies." -ForegroundColor Gray
Write-Host ""
Write-Host "  Tip: run with -ApplyToMeNow to create the folder for the current admin immediately." -ForegroundColor Gray
Write-Host ""
