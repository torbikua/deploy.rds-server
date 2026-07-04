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
    in the user's own context. This script therefore installs an HKLM\...\Run
    entry (runs at logon as the logging-on user) that creates/encrypts/locks the
    Private folder on each logon. The admin script itself only deploys it; it
    does not (and cannot) encrypt other users' data from an admin context.
    NOTE: only the Private folder is protected - the rest of the profile stays
    accessible to administrators by design.

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
    # Icon for the folder + desktop shortcut ("<dll>,<index>"). Default = padlock in shell32.
    [string]$IconResource = "%SystemRoot%\System32\SHELL32.dll,48",
    # Remove the Administrators group from each user's profile ROOT so admins get
    # "Access Denied" opening C:\Users\<user> by default (existing + new users).
    # ON by default (this is the behaviour you asked for). Disable with:
    #   -LockProfileFromAdmins:$false
    # NOTE: a local admin can still TAKE OWNERSHIP to get in (a visible action) -
    # this removes default access, it is not a cryptographic wall.
    [bool]$LockProfileFromAdmins = $true,
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

# This runs in EACH USER'S OWN CONTEXT (via the HKLM\Run entry below), so cipher
# uses that user's EFS key and icacls acts as the folder owner.
$perUser = @'
$ErrorActionPreference = "Continue"
$log = Join-Path $env:TEMP "RDS-PrivateFolder.log"
function L($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m" | Out-File -FilePath $log -Append -Encoding UTF8 }
L "=== start; user=$env:USERNAME profile=$env:USERPROFILE ==="

$folderName = "__PRIVATE_NAME__"
$priv = Join-Path $env:USERPROFILE $folderName
$lockProfile = __LOCKPROFILE__

try {
    # 1. Create the folder if missing
    if (-not (Test-Path $priv)) {
        New-Item -ItemType Directory -Path $priv -Force | Out-Null
        L "created folder: $priv"
    } else {
        L "folder already exists: $priv"
    }

    # 2. EFS-encrypt with THIS user's key (folder attribute + existing files).
    #    Any new file dropped inside is auto-encrypted with the user's key.
    $c = (cipher /e /s:"$priv" 2>&1 | Out-String)
    L "cipher /e -> $($c.Trim())"

    # 3. Lock NTFS: break inheritance, grant only the user + SYSTEM (no Administrators).
    #    NOTE: ${me} braces are required - "$me:(..." would be parsed as a $me: drive ref.
    $me = "$env:USERDOMAIN\$env:USERNAME"
    $a1 = (icacls "$priv" /inheritance:r /grant:r "${me}:(OI)(CI)F" "SYSTEM:(OI)(CI)F" 2>&1 | Out-String)
    L "icacls grant -> $($a1.Trim())"

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

    # 5. Desktop shortcut to the Private folder
    $desktop = [Environment]::GetFolderPath('Desktop')
    $lnk = Join-Path $desktop "$folderName.lnk"
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath   = $priv
    $sc.IconLocation = "__ICON__"
    $sc.Description   = "My private encrypted folder"
    $sc.Save()
    L "desktop shortcut -> $lnk"

    # 6. Custom folder icon via desktop.ini (folder needs system/readonly flag)
    $ini = Join-Path $priv "desktop.ini"
    $iniText = @"
[.ShellClassInfo]
IconResource=__ICON__
[ViewState]
Mode=
Vid=
FolderType=Generic
"@
    Set-Content -Path $ini -Value $iniText -Encoding Unicode -Force
    attrib +s +h "$ini"
    attrib +r "$priv"
    L "folder icon set via desktop.ini"

    # 7. Pin the folder to Quick Access (Home / Favorites)
    try {
        $shApp  = New-Object -ComObject Shell.Application
        $parent = $shApp.Namespace((Split-Path $priv -Parent))
        $item   = $parent.ParseName((Split-Path $priv -Leaf))
        $item.InvokeVerb("pintohome")
        L "pinned to Quick Access"
    } catch {
        L "pin to Quick Access failed: $($_.Exception.Message)"
    }

    # 8. Remove the Administrators group from the profile ROOT (deterrent):
    #    admins get "Access Denied" opening C:\Users\<user> by default.
    #    S-1-5-32-544 = BUILTIN\Administrators (locale-independent).
    if ($lockProfile) {
        $p = $env:USERPROFILE
        icacls "$p" /inheritance:d 2>&1 | Out-Null           # freeze inherited ACEs as explicit
        $r = (icacls "$p" /remove:g "*S-1-5-32-544" 2>&1 | Out-String)
        L "profile lock (remove Administrators from $p) -> $($r.Trim())"
    }

    L "=== done OK ==="
} catch {
    L "ERROR: $($_.Exception.Message)"
}
'@
$perUser = $perUser.Replace("__PRIVATE_NAME__", $PrivateFolderName)
$perUser = $perUser.Replace("__ICON__", $IconResource)
$perUser = $perUser.Replace("__LOCKPROFILE__", $(if ($LockProfileFromAdmins) { '$true' } else { '$false' }))

# Save the per-user script as UTF-8 with BOM (safe for Windows PowerShell 5.1)
$enc = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($userScript, $perUser, $enc)
Write-Host "[OK] Per-user script written: $userScript" -ForegroundColor Green

# Lock the script dir so users cannot tamper with it (read+execute only)
icacls "$scriptDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null

# ------------------------------------------------------------------
# 3. Register per-user logon autorun via HKLM\...\Run
#    (this is reliable: entries here run at logon IN THE USER'S OWN CONTEXT,
#    which is exactly what EFS needs. A scheduled task with a group principal
#    proved unreliable for RDP logons.)
# ------------------------------------------------------------------
Write-Step "Registering per-user logon autorun (HKLM\Run)"

$runKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$runName = "RDS-PrivateFolder"
$runCmd  = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$userScript`""
Set-ItemProperty -Path $runKey -Name $runName -Value $runCmd -Type String -Force
Write-Host "[OK] Autorun registered: HKLM\...\Run\$runName" -ForegroundColor Green
Write-Host "     Runs at each user's logon, in that user's context." -ForegroundColor Gray

# Clean up the old (unreliable) scheduled task if a previous run created it.
Unregister-ScheduledTask -TaskName "RDS-PrivateFolder" -Confirm:$false -ErrorAction SilentlyContinue

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
if ($LockProfileFromAdmins) {
    Write-Host "  PROFILE LOCK: Administrators removed from C:\Users\<user> root." -ForegroundColor Green
    Write-Host "    - Admins get 'Access Denied' opening a user's profile by default." -ForegroundColor Green
    Write-Host "    - To get in, an admin must explicitly TAKE OWNERSHIP (a visible act)." -ForegroundColor Gray
    Write-Host "    - Applies to existing AND new users (runs at each logon)." -ForegroundColor Gray
} else {
    Write-Host "  PROFILE LOCK: disabled (-LockProfileFromAdmins:`$false)." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Users ALREADY logged in: have them re-login, OR run once now:" -ForegroundColor Yellow
Write-Host "        powershell -ExecutionPolicy Bypass -File `"$userScript`"" -ForegroundColor White
Write-Host "  Per-user log (for debugging): %TEMP%\RDS-PrivateFolder.log" -ForegroundColor Gray
Write-Host ""
Write-Host "  PASSWORD RULES:" -ForegroundColor White
Write-Host "    - Users change their OWN password: Ctrl+Alt+End -> Change a password" -ForegroundColor Green
Write-Host "      (they must know the old one) -> encrypted files stay accessible." -ForegroundColor Gray
Write-Host "    - ADMIN password RESET destroys that user's Private folder access." -ForegroundColor Yellow
Write-Host "      Use reset only for new users or accepted-data-loss emergencies." -ForegroundColor Gray
Write-Host ""
Write-Host "  Tip: run with -ApplyToMeNow to create the folder for the current admin immediately." -ForegroundColor Gray
Write-Host ""
