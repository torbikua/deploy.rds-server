#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 — Terminal Server (RDS) setup without Active Directory domain.
    INTERACTIVE edition.
.DESCRIPTION
    1. Installs RDS roles (RD Session Host + RD Licensing)
    2. Asks for the Enterprise Agreement number and activates RD Licensing
    3. Asks whether to change the RDP port to a random one
    4. Asks whether to create local users, how many, proposes default names
       (u.01, u.02, ...) and auto-generates strong passwords
    5. Hardens Windows Firewall: blocks everything, allows only ICMP (ping) + RDP port
    6. Prints a full report including generated user credentials
.NOTES
    Run as Administrator. Server will REBOOT after role installation.
    After reboot, run the script again — roles are skipped and the interactive
    setup runs exactly once (questions are asked only when no reboot is pending).

    SAFE FOR RDP: when the port is changed, the current port stays open until you
    reconnect on the new port; a scheduled task locks down the old port afterwards.
#>

# ==============================
#  CONFIGURATION — DEFAULTS
#  (all of these can be overridden by the interactive prompts)
# ==============================

# RDP port range for random generation (high ports to avoid conflicts)
$PortRangeMin = 10000
$PortRangeMax = 59999

# Grace period (minutes) before the OLD RDP port is closed in the firewall.
$FirewallGraceMinutes = 5

# Default prefix and length for auto-generated user names (u.01, u.02, ...)
$DefaultUserPrefix = "u."
$DefaultUserCount  = 3

# Generated password length
$PasswordLength = 16

# Licensing mode: 4 = Per User, 2 = Per Device
$LicensingMode = 4

# ==============================
#  FUNCTIONS
# ==============================

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Read-YesNo {
    # Returns $true / $false. $Default is used on empty input.
    param([string]$Prompt, [bool]$Default = $true)
    $suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $ans = (Read-Host "$Prompt $suffix").Trim().ToLower()
        if ([string]::IsNullOrEmpty($ans)) { return $Default }
        switch ($ans) {
            'y'   { return $true }
            'yes' { return $true }
            'n'   { return $false }
            'no'  { return $false }
            default { Write-Host "  Please answer y or n." -ForegroundColor Yellow }
        }
    }
}

function Read-Default {
    # Prompt with a default value shown; Enter accepts the default.
    param([string]$Prompt, [string]$Default = "")
    if ($Default) {
        $ans = Read-Host "$Prompt [$Default]"
    } else {
        $ans = Read-Host "$Prompt"
    }
    if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
    return $ans.Trim()
}

function Read-IntInRange {
    param([string]$Prompt, [int]$Default, [int]$Min = 1, [int]$Max = 999)
    while ($true) {
        $ans = (Read-Host "$Prompt [$Default]").Trim()
        if ([string]::IsNullOrEmpty($ans)) { return $Default }
        $n = 0
        if ([int]::TryParse($ans, [ref]$n) -and $n -ge $Min -and $n -le $Max) { return $n }
        Write-Host "  Enter a number between $Min and $Max." -ForegroundColor Yellow
    }
}

function New-RandomPassword {
    # Strong password with guaranteed complexity: >=1 upper, lower, digit, symbol.
    # Ambiguous characters (O/0, l/1/I) are excluded for readability.
    param([int]$Length = 16)
    $upper  = "ABCDEFGHJKMNPQRSTUVWXYZ".ToCharArray()
    $lower  = "abcdefghijkmnpqrstuvwxyz".ToCharArray()
    $digit  = "23456789".ToCharArray()
    $symbol = "!@#$%^&*-_=+".ToCharArray()
    $all    = $upper + $lower + $digit + $symbol

    # guarantee one of each class
    $chars = @(
        $upper  | Get-Random
        $lower  | Get-Random
        $digit  | Get-Random
        $symbol | Get-Random
    )
    for ($i = $chars.Count; $i -lt $Length; $i++) { $chars += ($all | Get-Random) }
    # shuffle
    $chars = $chars | Sort-Object { Get-Random }
    return -join $chars
}

function Get-RandomPort {
    param([int]$Min, [int]$Max)
    do {
        $port = Get-Random -Minimum $Min -Maximum $Max
        $inUse = (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue)
    } while ($inUse)
    return $port
}

# ==============================
#  STEP 1: Install RDS Roles
# ==============================

Write-Step "STEP 1: Installing RDS Roles"

$rolesToInstall = @(
    "RDS-RD-Server",        # Remote Desktop Session Host
    "RDS-Licensing",         # Remote Desktop Licensing
    "RDS-Licensing-UI",      # Licensing UI tools
    "RSAT-RDS-Licensing-Diagnosis-UI"  # Licensing diagnostics
)

$needReboot = $false

foreach ($role in $rolesToInstall) {
    $feature = Get-WindowsFeature -Name $role
    if ($feature.Installed) {
        Write-Host "[OK] $role is already installed." -ForegroundColor Green
    }
    else {
        Write-Host "[INSTALLING] $role ..." -ForegroundColor Yellow
        $result = Install-WindowsFeature -Name $role -IncludeManagementTools -ErrorAction Stop
        if ($result.RestartNeeded -eq "Yes") {
            $needReboot = $true
        }
        Write-Host "[DONE] $role installed." -ForegroundColor Green
    }
}

if ($needReboot) {
    Write-Host "`n[!] Reboot required to complete role installation." -ForegroundColor Red
    Write-Host "[!] After reboot, run this script again to continue setup." -ForegroundColor Red
    Write-Host "[!] The interactive questions will be asked AFTER the reboot." -ForegroundColor Yellow
    Write-Host "[!] Rebooting in 15 seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 15
    Restart-Computer -Force
    exit
}

# ==============================
#  INTERACTIVE CONFIGURATION
#  (asked only once — after roles are installed, no reboot pending)
# ==============================

Write-Step "INTERACTIVE SETUP"

Write-Host "Answer the questions below. Press Enter to accept the [default]." -ForegroundColor Gray
Write-Host ""

# --- Q1: Enterprise Agreement number ---
Write-Host "1) RD Licensing — Enterprise Agreement" -ForegroundColor Cyan
$AgreementNumber = Read-Default -Prompt "   Enter Enterprise Agreement number (blank = activate later manually)" -Default ""
$DoActivate = -not [string]::IsNullOrWhiteSpace($AgreementNumber)
if ($DoActivate) {
    Write-Host "   -> Will activate with EA: $AgreementNumber" -ForegroundColor Green
} else {
    Write-Host "   -> Skipping automatic activation (do it later via licmgr.exe)." -ForegroundColor Yellow
}
Write-Host ""

# --- Q2: Change RDP port? ---
Write-Host "2) RDP Port" -ForegroundColor Cyan
$ChangePort = Read-YesNo -Prompt "   Change RDP port to a RANDOM high port?" -Default $true
Write-Host ""

# --- Q3: Create users? ---
Write-Host "3) Local RDP users" -ForegroundColor Cyan
$CreateUsers = Read-YesNo -Prompt "   Create local users for RDP?" -Default $true
$Users = @()
if ($CreateUsers) {
    $userCount = Read-IntInRange -Prompt "   How many users?" -Default $DefaultUserCount -Min 1 -Max 200
    $prefix    = Read-Default   -Prompt "   Username prefix" -Default $DefaultUserPrefix
    Write-Host "   Proposing default names ($prefix01 ...). Press Enter to accept each, or type a different name." -ForegroundColor Gray
    for ($i = 1; $i -le $userCount; $i++) {
        $defaultName = "{0}{1:D2}" -f $prefix, $i
        $name = Read-Default -Prompt "     User #$i name" -Default $defaultName
        $pass = New-RandomPassword -Length $PasswordLength
        $Users += @{ Name = $name; Password = $pass }
    }
    Write-Host "   -> $($Users.Count) user(s) queued; passwords auto-generated." -ForegroundColor Green
} else {
    Write-Host "   -> No users will be created." -ForegroundColor Yellow
}
Write-Host ""

# ==============================
#  STEP 2: Configure RD Licensing
# ==============================

Write-Step "STEP 2: Configuring RD Licensing"

$localhost = $env:COMPUTERNAME

$rdshPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $rdshPath)) {
    New-Item -Path $rdshPath -Force | Out-Null
}
Set-ItemProperty -Path $rdshPath -Name "LicensingMode" -Value $LicensingMode -Type DWord
Set-ItemProperty -Path $rdshPath -Name "LicenseServers" -Value $localhost -Type String

$licModeName = if ($LicensingMode -eq 4) { "Per User" } else { "Per Device" }
Write-Host "[OK] Licensing mode set to $licModeName (local server: $localhost)" -ForegroundColor Green

if ($DoActivate) {
    Write-Step "STEP 2b: Activating License Server (Enterprise Agreement)"
    try {
        $wmiObj = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_TSLicenseServer" -ErrorAction Stop
        if ($wmiObj) {
            $activationStatus = $wmiObj.GetActivationStatus()
            if ($activationStatus.ActivationStatus -eq 0) {
                Write-Host "[OK] License server is already activated." -ForegroundColor Green
            }
            else {
                Write-Host "[ACTIVATING] Using Enterprise Agreement: $AgreementNumber ..." -ForegroundColor Yellow
                $result = $wmiObj.ActivateServerAutomatic()
                if ($result.ReturnValue -eq 0) {
                    Write-Host "[OK] License server activated successfully." -ForegroundColor Green
                }
                else {
                    Write-Host "[WARN] Automatic activation returned code: $($result.ReturnValue)" -ForegroundColor Yellow
                    Write-Host "[INFO] Activate manually: licmgr.exe -> Activate Server -> Enterprise Agreement -> $AgreementNumber" -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "[WARN] WMI object Win32_TSLicenseServer not found." -ForegroundColor Yellow
            Write-Host "[INFO] Activate manually: licmgr.exe -> Activate Server -> Enterprise Agreement -> $AgreementNumber" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "[WARN] Could not query license server WMI: $_" -ForegroundColor Yellow
        Write-Host "[INFO] === MANUAL ACTIVATION ===" -ForegroundColor Yellow
        Write-Host "[INFO] 1. licmgr.exe -> right-click server -> Activate Server" -ForegroundColor White
        Write-Host "[INFO] 2. Method: Automatic; Program: Enterprise Agreement" -ForegroundColor White
        Write-Host "[INFO] 3. Agreement Number: $AgreementNumber" -ForegroundColor White
        Write-Host "[INFO] 4. Install Licenses -> Enterprise Agreement -> RDS Per User CALs" -ForegroundColor White
    }
    Set-ItemProperty -Path $rdshPath -Name "EnterpriseAgreement" -Value $AgreementNumber -Type String
}
else {
    Write-Host "[INFO] Activation skipped. Run licmgr.exe later to activate via Enterprise Agreement." -ForegroundColor Yellow
}

# ==============================
#  STEP 3: Create Local Users
# ==============================

if ($CreateUsers -and $Users.Count -gt 0) {
    Write-Step "STEP 3: Creating Local Users"

    # Localized name of the "Remote Desktop Users" group (well-known SID)
    $rdpGroupSID = "S-1-5-32-555"
    $rdpGroup = (New-Object System.Security.Principal.SecurityIdentifier($rdpGroupSID)).Translate(
        [System.Security.Principal.NTAccount]
    ).Value.Split('\')[-1]
    Write-Host "[INFO] Remote Desktop Users group name: $rdpGroup" -ForegroundColor Gray

    foreach ($user in $Users) {
        $userName = $user.Name
        $userPass = $user.Password

        $existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
        if ($existingUser) {
            Write-Host "[SKIP] User '$userName' already exists — resetting password." -ForegroundColor Yellow
            try {
                $securePass = ConvertTo-SecureString $userPass -AsPlainText -Force
                Set-LocalUser -Name $userName -Password $securePass -ErrorAction Stop
                Write-Host "[OK] Password reset for existing user '$userName'." -ForegroundColor Green
            } catch {
                Write-Host "[WARN] Could not reset password for '$userName': $_" -ForegroundColor Yellow
            }
        }
        else {
            $securePass = ConvertTo-SecureString $userPass -AsPlainText -Force
            New-LocalUser -Name $userName `
                          -Password $securePass `
                          -FullName $userName `
                          -Description "RDS Terminal User" `
                          -PasswordNeverExpires `
                          -UserMayNotChangePassword:$false `
                          -ErrorAction Stop | Out-Null
            Write-Host "[OK] User '$userName' created." -ForegroundColor Green
        }

        try {
            Add-LocalGroupMember -Group $rdpGroup -Member $userName -ErrorAction Stop
            Write-Host "[OK] '$userName' added to '$rdpGroup' group." -ForegroundColor Green
        }
        catch [Microsoft.PowerShell.Commands.MemberExistsException] {
            Write-Host "[SKIP] '$userName' is already in '$rdpGroup'." -ForegroundColor Yellow
        }
        catch {
            try {
                net localgroup "$rdpGroup" "$userName" /add 2>$null
                Write-Host "[OK] '$userName' added to '$rdpGroup' (via net localgroup)." -ForegroundColor Green
            }
            catch {
                Write-Host "[WARN] Could not add '$userName' to RDP group: $_" -ForegroundColor Yellow
            }
        }
    }
}
else {
    Write-Step "STEP 3: Creating Local Users (skipped)"
    Write-Host "[INFO] User creation skipped by choice." -ForegroundColor Yellow
}

# ==============================
#  STEP 4: Change RDP Port
# ==============================

$rdpPortPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$OldPort = (Get-ItemProperty -Path $rdpPortPath -Name "PortNumber").PortNumber

if ($ChangePort) {
    Write-Step "STEP 4: Changing RDP Port"
    Write-Host "[INFO] Current RDP port: $OldPort" -ForegroundColor Gray
    $NewPort = Get-RandomPort -Min $PortRangeMin -Max $PortRangeMax
    Set-ItemProperty -Path $rdpPortPath -Name "PortNumber" -Value $NewPort -Type DWord
    Write-Host "[OK] RDP port will change to: $NewPort (after service restart)" -ForegroundColor Green
}
else {
    Write-Step "STEP 4: Changing RDP Port (skipped)"
    $NewPort = $OldPort
    Write-Host "[INFO] Keeping current RDP port: $NewPort" -ForegroundColor Yellow
}

# ==============================
#  STEP 5: Configure Firewall (RDP-Safe)
# ==============================

Write-Step "STEP 5: Configuring Windows Firewall (RDP-Safe Mode)"

if ($ChangePort) {
    Write-Host "[INFO] Old port $OldPort will stay open for $FirewallGraceMinutes minutes after setup." -ForegroundColor Cyan
}
Write-Host ""

# 5a. Clean up rules from previous runs
foreach ($pattern in @("RDP-Custom-*", "Allow-ICMPv4-In", "Allow-ICMPv6-In", "RDP-Temp-OldPort-*")) {
    $r = Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue
    if ($r) { $r | Remove-NetFirewallRule }
}

# 5b. NEW port allow rules FIRST
New-NetFirewallRule -DisplayName "RDP-Custom-TCP-$NewPort" -Direction Inbound -Protocol TCP -LocalPort $NewPort -Action Allow -Profile Any -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "RDP-Custom-UDP-$NewPort" -Direction Inbound -Protocol UDP -LocalPort $NewPort -Action Allow -Profile Any -Enabled True | Out-Null
Write-Host "[OK] Firewall rules for RDP port $NewPort created (TCP + UDP)." -ForegroundColor Green

# 5c. Temp rule for OLD port only if the port actually changed
if ($ChangePort -and $OldPort -ne $NewPort) {
    New-NetFirewallRule -DisplayName "RDP-Temp-OldPort-TCP-$OldPort" -Direction Inbound -Protocol TCP -LocalPort $OldPort -Action Allow -Profile Any -Enabled True | Out-Null
    Write-Host "[OK] Temporary rule for OLD port $OldPort created (grace: ${FirewallGraceMinutes}min)." -ForegroundColor Yellow
}

# 5d. ICMP ping
New-NetFirewallRule -DisplayName "Allow-ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "Allow-ICMPv6-In" -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -Action Allow -Profile Any -Enabled True | Out-Null
Write-Host "[OK] ICMP Ping (v4 + v6) allowed." -ForegroundColor Green

# 5e. Block all inbound
Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow -Enabled True
Write-Host "[OK] Default policy: Block ALL inbound, Allow outbound." -ForegroundColor Green

# 5f. Disable other inbound rules
Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | Where-Object {
    $_.Enabled -eq 'True' -and
    $_.DisplayName -notlike "RDP-Custom-*" -and
    $_.DisplayName -notlike "RDP-Temp-*" -and
    $_.DisplayName -notlike "Allow-ICMP*"
} | Set-NetFirewallRule -Enabled False
Write-Host "[OK] All other inbound rules disabled." -ForegroundColor Green

# ==============================
#  STEP 6: Additional RDS Settings
# ==============================

Write-Step "STEP 6: Additional Settings"

Set-ItemProperty -Path $rdpPortPath -Name "UserAuthentication" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord
Write-Host "[OK] NLA enabled, Remote Desktop connections enabled." -ForegroundColor Green

Set-ItemProperty -Path $rdshPath -Name "MaxIdleTime"          -Value 3600000  -Type DWord
Set-ItemProperty -Path $rdshPath -Name "MaxDisconnectionTime" -Value 28800000 -Type DWord
Set-ItemProperty -Path $rdshPath -Name "fResetBroken"         -Value 1        -Type DWord
Write-Host "[OK] Session timeouts configured (idle: 60min, disconnected: 8h)." -ForegroundColor Green

# ==============================
#  STEP 7: Save connection info + credentials
# ==============================

$serverIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1).IPAddress

$triggerTime = (Get-Date).AddMinutes($FirewallGraceMinutes)

$userLines = if ($Users.Count -gt 0) {
    ($Users | ForEach-Object { "    {0,-20} {1}" -f $_.Name, $_.Password }) -join "`n"
} else {
    "    (none created)"
}

$oldPortNote = if ($ChangePort -and $OldPort -ne $NewPort) {
    "  Old port $OldPort will be closed automatically at $($triggerTime.ToString('HH:mm:ss'))."
} else {
    "  RDP port was not changed."
}

$infoFile = "$env:PUBLIC\Desktop\RDP-CONNECTION-INFO.txt"
@"
==========================================
  TERMINAL SERVER CONNECTION INFO
  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
==========================================

  Server IP  : $serverIP
  RDP Port   : $NewPort
  Connect to : ${serverIP}:${NewPort}

$oldPortNote

  !!! SENSITIVE — contains passwords. Store securely, then delete. !!!
  Users (login / password):
$userLines

  Firewall:
    - All inbound BLOCKED
    - ICMP Ping ALLOWED
    - TCP/UDP $NewPort ALLOWED

  Licensing:
    - Mode: $licModeName
    - EA: $(if ($DoActivate) { $AgreementNumber } else { "(not activated — do it via licmgr.exe)" })

==========================================
"@ | Set-Content -Path $infoFile -Encoding UTF8

# 7b. Schedule old-port cleanup only if the port changed
if ($ChangePort -and $OldPort -ne $NewPort) {
    $cleanupScript = @"
Start-Sleep -Seconds 10
Get-NetFirewallRule -DisplayName "RDP-Temp-OldPort-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Add-Content -Path "$infoFile" -Value "`n  [`$(Get-Date -Format 'HH:mm:ss')] Old port $OldPort firewall rule removed."
"@
    $cleanupScriptPath = "$env:ProgramData\Scripts\Remove-OldRdpPort.ps1"
    $scriptsDir = Split-Path $cleanupScriptPath
    if (-not (Test-Path $scriptsDir)) { New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null }
    $cleanupScript | Set-Content -Path $cleanupScriptPath -Encoding UTF8

    $taskAction    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScriptPath`""
    $taskTrigger   = New-ScheduledTaskTrigger -Once -At $triggerTime
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $taskSettings  = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter "00:10:00" -StartWhenAvailable

    Unregister-ScheduledTask -TaskName "RDS-RemoveOldPort" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "RDS-RemoveOldPort" `
        -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings `
        -Description "Remove temporary old RDP port ($OldPort) firewall rule after grace period" | Out-Null
    Write-Host "[OK] Old port $OldPort will be auto-closed at $($triggerTime.ToString('HH:mm:ss'))." -ForegroundColor Yellow
}

# ==============================
#  SUMMARY REPORT
# ==============================

Write-Step "SETUP COMPLETE"

Write-Host ""
Write-Host "  SERVER IP    : $serverIP" -ForegroundColor White
Write-Host "  RDP PORT     : $NewPort" -ForegroundColor White
Write-Host "  CONNECT TO   : ${serverIP}:${NewPort}" -ForegroundColor Green
Write-Host ""

Write-Host "  USERS CREATED (login / password):" -ForegroundColor White
if ($Users.Count -gt 0) {
    foreach ($user in $Users) {
        Write-Host ("    {0,-20} {1}" -f $user.Name, $user.Password) -ForegroundColor Green
    }
} else {
    Write-Host "    (none)" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "  FIREWALL:" -ForegroundColor White
Write-Host "    - All inbound BLOCKED" -ForegroundColor Red
Write-Host "    - ICMP Ping ALLOWED" -ForegroundColor Green
Write-Host "    - TCP/UDP $NewPort ALLOWED (RDP)" -ForegroundColor Green
if ($ChangePort -and $OldPort -ne $NewPort) {
    Write-Host "    - TCP $OldPort TEMPORARILY open (closes at $($triggerTime.ToString('HH:mm:ss')))" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "  LICENSING:" -ForegroundColor White
Write-Host "    - Mode: $licModeName" -ForegroundColor White
if ($DoActivate) {
    Write-Host "    - EA Number: $AgreementNumber" -ForegroundColor White
    Write-Host "    - If not auto-activated, run: licmgr.exe" -ForegroundColor Yellow
} else {
    Write-Host "    - NOT activated — run licmgr.exe and use Enterprise Agreement" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "  [!] Credentials + connection info saved to: $infoFile" -ForegroundColor Cyan
Write-Host "  [!] That file contains PASSWORDS — store it securely and delete afterwards." -ForegroundColor Red
Write-Host ""

if ($ChangePort -and $OldPort -ne $NewPort) {
    Write-Host "  [!] SAVE THIS PORT: $NewPort" -ForegroundColor Red
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  Restarting TermService in 10 seconds...        │" -ForegroundColor Yellow
    Write-Host "  │  Your RDP session WILL disconnect.              │" -ForegroundColor Yellow
    Write-Host "  │  Reconnect using the NEW port above.            │" -ForegroundColor Green
    Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 10
    Restart-Service -Name "TermService" -Force
}
else {
    Write-Host "  [OK] RDP port unchanged — no service restart needed." -ForegroundColor Green
    Write-Host "  [OK] Setup finished." -ForegroundColor Green
}
