#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 — Terminal Server (RDS) setup without Active Directory domain.
.DESCRIPTION
    1. Installs RDS roles (RD Session Host + RD Licensing)
    2. Activates RD Licensing via Enterprise Agreement
    3. Creates local users for RDP access
    4. Changes default RDP port to a random port
    5. Hardens Windows Firewall: blocks everything, allows only ICMP (ping) + custom RDP port
.NOTES
    Run as Administrator. Server will REBOOT after role installation.
    After reboot, run the script again — it will skip already-installed roles and continue setup.
    
    SAFE FOR RDP: the script keeps the current port open until you reconnect on the new port.
    A scheduled task will lock down the old port after a grace period.
#>

# ==============================
#  CONFIGURATION — EDIT HERE
# ==============================

# Local users to create (username = password pairs)
# !! CHANGE PASSWORDS BEFORE RUNNING !!
$Users = @(
    @{ Name = "u01";  Password = "***_CHANGE_ME_***" }
    @{ Name = "u02";  Password = "***_CHANGE_ME_***" }
    @{ Name = "u03";  Password = "***_CHANGE_ME_***" }
    # Add more users as needed:
    # @{ Name = "user4";  Password = "SecurePass!444" }
)

# Enterprise Agreement number for RDS CAL activation
# Replace with your real EA number
$AgreementNumber = "***_CHANGE_ME_***"

# RDP port range for random generation (high ports to avoid conflicts)
$PortRangeMin = 10000
$PortRangeMax = 59999

# Grace period (minutes) before old RDP port (3389) is closed in firewall.
# This gives you time to reconnect on the new port after TermService restarts.
$FirewallGraceMinutes = 5

# ==============================
#  FUNCTIONS
# ==============================

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
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
    Write-Host "[!] Rebooting in 15 seconds..." -ForegroundColor Red
    Start-Sleep -Seconds 15
    Restart-Computer -Force
    exit
}

# ==============================
#  STEP 2: Configure RD Licensing
# ==============================

Write-Step "STEP 2: Configuring RD Licensing"

# Set licensing mode to Per User (4) — change to 2 for Per Device
$LicensingMode = 4  # 4 = Per User, 2 = Per Device

# Configure RD Session Host to use local license server
$localhost = $env:COMPUTERNAME

# Set licensing mode via registry
$rdshPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $rdshPath)) {
    New-Item -Path $rdshPath -Force | Out-Null
}
Set-ItemProperty -Path $rdshPath -Name "LicensingMode" -Value $LicensingMode -Type DWord
Set-ItemProperty -Path $rdshPath -Name "LicenseServers" -Value $localhost -Type String

Write-Host "[OK] Licensing mode set to Per User (local server: $localhost)" -ForegroundColor Green

# Activate License Server via Enterprise Agreement using WMI
Write-Step "STEP 2b: Activating License Server (Enterprise Agreement)"

try {
    $wmiObj = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_TSLicenseServer" -ErrorAction Stop

    if ($wmiObj) {
        $activationStatus = $wmiObj.GetActivationStatus()
        # 0 = activated, 1 = not activated
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
                Write-Host "[INFO] You may need to activate manually via Remote Desktop Licensing Manager." -ForegroundColor Yellow
                Write-Host "[INFO] Open: licmgr.exe -> Right-click server -> Activate Server" -ForegroundColor Yellow
                Write-Host "[INFO] Select 'Enterprise Agreement' and enter: $AgreementNumber" -ForegroundColor Yellow
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
    Write-Host ""
    Write-Host "[INFO] === MANUAL ACTIVATION INSTRUCTIONS ===" -ForegroundColor Yellow
    Write-Host "[INFO] 1. Open: licmgr.exe (Remote Desktop Licensing Manager)" -ForegroundColor White
    Write-Host "[INFO] 2. Right-click your server -> 'Activate Server'" -ForegroundColor White
    Write-Host "[INFO] 3. Connection method: Automatic / Web Browser" -ForegroundColor White
    Write-Host "[INFO] 4. Select program: 'Enterprise Agreement'" -ForegroundColor White
    Write-Host "[INFO] 5. Enter Agreement Number: $AgreementNumber" -ForegroundColor White
    Write-Host "[INFO] 6. Then: Install Licenses -> Enterprise Agreement -> RDS Per User CALs" -ForegroundColor White
}

# Also set registry for EA info (useful reference)
Set-ItemProperty -Path $rdshPath -Name "EnterpriseAgreement" -Value $AgreementNumber -Type String

# ==============================
#  STEP 3: Create Local Users
# ==============================

Write-Step "STEP 3: Creating Local Users"

# Determine the localized name of "Remote Desktop Users" group
$rdpGroupSID = "S-1-5-32-555"  # Well-known SID for Remote Desktop Users
$rdpGroup = (New-Object System.Security.Principal.SecurityIdentifier($rdpGroupSID)).Translate(
    [System.Security.Principal.NTAccount]
).Value.Split('\')[-1]

Write-Host "[INFO] Remote Desktop Users group name: $rdpGroup" -ForegroundColor Gray

foreach ($user in $Users) {
    $userName = $user.Name
    $userPass = $user.Password

    $existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Host "[SKIP] User '$userName' already exists." -ForegroundColor Yellow
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

    # Add user to Remote Desktop Users group
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

# ==============================
#  STEP 4: Change RDP Port
# ==============================

Write-Step "STEP 4: Changing RDP Port"

# Detect current port BEFORE changing
$rdpPortPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$OldPort = (Get-ItemProperty -Path $rdpPortPath -Name "PortNumber").PortNumber
Write-Host "[INFO] Current RDP port: $OldPort" -ForegroundColor Gray

$NewPort = Get-RandomPort -Min $PortRangeMin -Max $PortRangeMax

# Update RDP port in registry (takes effect after TermService restart)
Set-ItemProperty -Path $rdpPortPath -Name "PortNumber" -Value $NewPort -Type DWord

Write-Host "[OK] RDP port will change to: $NewPort (after service restart)" -ForegroundColor Green

# ==============================
#  STEP 5: Configure Firewall
#  !! RDP-SAFE ORDER !!
#
#  1. Create rules for NEW port FIRST
#  2. Create temporary rule for OLD port (keep current session alive)
#  3. Set default policy to Block
#  4. Disable other inbound rules
#  5. Restart TermService (now listening on new port)
#  6. Schedule removal of old port rule after grace period
# ==============================

Write-Step "STEP 5: Configuring Windows Firewall (RDP-Safe Mode)"

Write-Host "[INFO] Using RDP-safe firewall sequence to prevent lockout." -ForegroundColor Cyan
Write-Host "[INFO] Old port $OldPort will stay open for $FirewallGraceMinutes minutes after setup." -ForegroundColor Cyan
Write-Host ""

# 5a. Clean up old custom rules from previous runs
$oldRules = Get-NetFirewallRule -DisplayName "RDP-Custom-*" -ErrorAction SilentlyContinue
if ($oldRules) {
    $oldRules | Remove-NetFirewallRule
    Write-Host "[CLEAN] Removed previous custom RDP firewall rules." -ForegroundColor Gray
}
$oldPing = Get-NetFirewallRule -DisplayName "Allow-ICMPv4-In" -ErrorAction SilentlyContinue
if ($oldPing) { $oldPing | Remove-NetFirewallRule }
$oldPing6 = Get-NetFirewallRule -DisplayName "Allow-ICMPv6-In" -ErrorAction SilentlyContinue
if ($oldPing6) { $oldPing6 | Remove-NetFirewallRule }
$oldGrace = Get-NetFirewallRule -DisplayName "RDP-Temp-OldPort-*" -ErrorAction SilentlyContinue
if ($oldGrace) { $oldGrace | Remove-NetFirewallRule }

# 5b. CREATE NEW PORT RULES FIRST (before any blocking!)
New-NetFirewallRule -DisplayName "RDP-Custom-TCP-$NewPort" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $NewPort `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null

New-NetFirewallRule -DisplayName "RDP-Custom-UDP-$NewPort" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort $NewPort `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null

Write-Host "[OK] Firewall rules for NEW port $NewPort created (TCP + UDP)." -ForegroundColor Green

# 5c. CREATE TEMPORARY RULE for OLD port (keeps your current RDP session alive)
New-NetFirewallRule -DisplayName "RDP-Temp-OldPort-TCP-$OldPort" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $OldPort `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null

Write-Host "[OK] Temporary rule for OLD port $OldPort created (grace period: ${FirewallGraceMinutes}min)." -ForegroundColor Yellow

# 5d. Allow ICMP (Ping) — ICMPv4 and ICMPv6
New-NetFirewallRule -DisplayName "Allow-ICMPv4-In" `
    -Direction Inbound `
    -Protocol ICMPv4 `
    -IcmpType 8 `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null

New-NetFirewallRule -DisplayName "Allow-ICMPv6-In" `
    -Direction Inbound `
    -Protocol ICMPv6 `
    -IcmpType 8 `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null

Write-Host "[OK] ICMP Ping (v4 + v6) allowed." -ForegroundColor Green

# 5e. NOW safe to block — our rules are already in place
Set-NetFirewallProfile -Profile Domain, Public, Private `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -Enabled True

Write-Host "[OK] Default policy: Block ALL inbound, Allow outbound." -ForegroundColor Green

# 5f. Disable all existing inbound rules EXCEPT our custom ones
Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue | Where-Object {
    $_.Enabled -eq 'True' -and
    $_.DisplayName -notlike "RDP-Custom-*" -and
    $_.DisplayName -notlike "RDP-Temp-*" -and
    $_.DisplayName -notlike "Allow-ICMP*"
} | Set-NetFirewallRule -Enabled False

Write-Host "[OK] All other inbound rules disabled." -ForegroundColor Green

# ==============================
#  STEP 6: Restart TermService
#  (automatically — no interactive prompt)
# ==============================

Write-Step "STEP 6: Restarting TermService"

Write-Host "[!] Restarting RDP service to apply new port $NewPort ..." -ForegroundColor Yellow
Write-Host "[!] Your current session will drop. Reconnect to: ${NewPort}" -ForegroundColor Red
Write-Host ""

# Save connection info BEFORE restarting (in case session drops)
$serverIP = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1).IPAddress

$infoFile = "$env:PUBLIC\Desktop\RDP-CONNECTION-INFO.txt"
@"
==========================================
  TERMINAL SERVER CONNECTION INFO
  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
==========================================

  Server IP  : $serverIP
  RDP Port   : $NewPort
  Connect to : ${serverIP}:${NewPort}

  Old port $OldPort will be closed automatically
  after $FirewallGraceMinutes minutes.

  Users:
$(($Users | ForEach-Object { "    - $($_.Name)" }) -join "`n")

  Firewall:
    - All inbound BLOCKED
    - ICMP Ping ALLOWED
    - TCP/UDP $NewPort ALLOWED

  Licensing:
    - Mode: Per User
    - EA: $AgreementNumber

==========================================
"@ | Set-Content -Path $infoFile -Encoding UTF8

# ==============================
#  STEP 7: Schedule old port cleanup
# ==============================

# Create a script that removes the temporary old-port rule
$cleanupScript = @"
# Auto-generated: remove temporary old RDP port rule
Start-Sleep -Seconds 10
Get-NetFirewallRule -DisplayName "RDP-Temp-OldPort-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# Log the action
Add-Content -Path "$env:PUBLIC\Desktop\RDP-CONNECTION-INFO.txt" -Value "`n  [$(Get-Date -Format 'HH:mm:ss')] Old port $OldPort firewall rule removed."
"@

$cleanupScriptPath = "$env:ProgramData\Scripts\Remove-OldRdpPort.ps1"
$scriptsDir = Split-Path $cleanupScriptPath
if (-not (Test-Path $scriptsDir)) { New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null }
$cleanupScript | Set-Content -Path $cleanupScriptPath -Encoding UTF8

# Schedule the cleanup task to run once after the grace period
$triggerTime = (Get-Date).AddMinutes($FirewallGraceMinutes)
$taskAction    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScriptPath`""
$taskTrigger   = New-ScheduledTaskTrigger -Once -At $triggerTime
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$taskSettings  = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter "00:10:00" -StartWhenAvailable

Unregister-ScheduledTask -TaskName "RDS-RemoveOldPort" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "RDS-RemoveOldPort" `
    -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings `
    -Description "Remove temporary old RDP port ($OldPort) firewall rule after grace period" | Out-Null

Write-Host "[OK] Old port $OldPort will be auto-closed at $($triggerTime.ToString('HH:mm:ss'))." -ForegroundColor Yellow

# ==============================
#  STEP 8: Additional RDS Settings
# ==============================

Write-Step "STEP 8: Additional Settings"

# Enable NLA (Network Level Authentication)
Set-ItemProperty -Path $rdpPortPath -Name "UserAuthentication" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0 -Type DWord

Write-Host "[OK] NLA (Network Level Authentication) enabled." -ForegroundColor Green
Write-Host "[OK] Remote Desktop connections enabled." -ForegroundColor Green

# Set session limits (optional — prevents abandoned sessions)
$sessionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
Set-ItemProperty -Path $sessionPath -Name "MaxIdleTime"          -Value 3600000  -Type DWord  # 60 min idle
Set-ItemProperty -Path $sessionPath -Name "MaxDisconnectionTime" -Value 28800000 -Type DWord  # 8 hours disconnected
Set-ItemProperty -Path $sessionPath -Name "fResetBroken"         -Value 1        -Type DWord  # end broken sessions

Write-Host "[OK] Session timeouts configured (idle: 60min, disconnected: 8h)." -ForegroundColor Green

# ==============================
#  SUMMARY
# ==============================

Write-Step "SETUP COMPLETE"

Write-Host ""
Write-Host "  SERVER IP    : $serverIP" -ForegroundColor White
Write-Host "  NEW RDP PORT : $NewPort" -ForegroundColor White
Write-Host "  CONNECT TO   : ${serverIP}:${NewPort}" -ForegroundColor Green
Write-Host ""
Write-Host "  USERS CREATED:" -ForegroundColor White
foreach ($user in $Users) {
    Write-Host "    - $($user.Name)" -ForegroundColor White
}
Write-Host ""
Write-Host "  FIREWALL:" -ForegroundColor White
Write-Host "    - All inbound BLOCKED" -ForegroundColor Red
Write-Host "    - ICMP Ping ALLOWED" -ForegroundColor Green
Write-Host "    - TCP/UDP $NewPort ALLOWED (RDP)" -ForegroundColor Green
Write-Host "    - TCP $OldPort TEMPORARILY open (closes at $($triggerTime.ToString('HH:mm:ss')))" -ForegroundColor Yellow
Write-Host ""
Write-Host "  LICENSING:" -ForegroundColor White
Write-Host "    - Mode: Per User" -ForegroundColor White
Write-Host "    - EA Number: $AgreementNumber" -ForegroundColor White
Write-Host "    - If not auto-activated, run: licmgr.exe" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [!] SAVE THIS PORT: $NewPort" -ForegroundColor Red
Write-Host "  [!] Connection info saved to: $infoFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  Restarting TermService in 10 seconds...        │" -ForegroundColor Yellow
Write-Host "  │  Your RDP session WILL disconnect.              │" -ForegroundColor Yellow
Write-Host "  │                                                 │" -ForegroundColor Yellow
Write-Host "  │  Reconnect using: ${serverIP}:${NewPort}  │" -ForegroundColor Green
Write-Host "  │                                                 │" -ForegroundColor Yellow
Write-Host "  │  Old port $OldPort stays open until $($triggerTime.ToString('HH:mm:ss'))     │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds 10

# Restart TermService — this will drop the current RDP session
Restart-Service -Name "TermService" -Force
