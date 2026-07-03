#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 - Terminal Server (RDS) setup without Active Directory domain.
    INTERACTIVE edition.
.DESCRIPTION
    1. Installs RDS roles (RD Session Host + RD Licensing)
    2. Configures RD Licensing (3 independent steps, all optional / re-runnable):
         A) Point the Session Host at the local license server + set the mode
            (registry policy - fixes the "licensing mode not configured" nag)
         B) Activate the license server over the Internet (needs contact
            name/company/country - NOT the EA number)
         C) Install CALs from a volume agreement, e.g. Enterprise Agreement
            (needs the 7-digit agreement number + the server already activated)
    3. Asks whether to change the RDP port to a random one
    4. Asks whether to create local users, how many, proposes default names
       (u.01, u.02, ...) and auto-generates strong passwords
    5. Hardens Windows Firewall: blocks everything, allows only ICMP (ping) + RDP port
    6. Prints a full report including generated user credentials
.NOTES
    Run as Administrator. Server will REBOOT after role installation.
    RE-RUNNABLE: on every run it prints a CURRENT STATE inventory (roles,
    license-server activation, Session Host mode + configured license server,
    RDP port, users, firewall) and asks what to (re)do.
    Licensing uses CIM (Invoke-CimMethod) for Win32_TSLicenseServer /
    Win32_TSLicenseKeyPack because their methods use [out] params that the
    Get-WmiObject adapter cannot call. Diagnose anytime with lsdiag.msc.

    SAFE FOR RDP: when the port is changed, the current port stays open until you
    reconnect on the new port; a scheduled task locks down the old port afterwards.
#>

# ==============================
#  CONFIGURATION - DEFAULTS
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

# --- Licensing helpers (CIM-based; methods with [out] params need Invoke-CimMethod) ---

function Get-TSLicenseServerCim {
    # The RD Licensing server WMI object (singleton). $null if role/service not ready.
    try { return Get-CimInstance -Namespace "root/cimv2" -ClassName "Win32_TSLicenseServer" -ErrorAction Stop }
    catch { return $null }
}

function Get-LicenseServerActivation {
    # ActivationStatus: 0 = activated, 1 = not activated, 2 = unknown.
    $ls = Get-TSLicenseServerCim
    if (-not $ls) { return @{ Found = $false; Activated = $false; Code = -1 } }
    try {
        $r = Invoke-CimMethod -InputObject $ls -MethodName "GetActivationStatus" -ErrorAction Stop
        $code = [int]$r.ActivationStatus
        return @{ Found = $true; Activated = ($code -eq 0); Code = $code }
    } catch {
        return @{ Found = $true; Activated = $false; Code = -1 }
    }
}

function Get-SessionHostLicensing {
    # Reads the RD Session Host licensing config.
    # LicensingType: 2 = Per Device, 4 = Per User, 5 = Not configured.
    try {
        $ts = Get-CimInstance -Namespace "root/cimv2/terminalservices" -ClassName "Win32_TerminalServiceSetting" -ErrorAction Stop
        $servers = @()
        try {
            $r = Invoke-CimMethod -InputObject $ts -MethodName "GetSpecifiedLicenseServerList" -ErrorAction Stop
            if ($r.SpecifiedLSList) { $servers = @($r.SpecifiedLSList) }
        } catch {}
        return @{ Found = $true; Mode = [int]$ts.LicensingType; Servers = $servers }
    } catch {
        return @{ Found = $false; Mode = -1; Servers = @() }
    }
}

function Set-SessionHostLicensing {
    # Primary fix for the 'licensing not configured' nag = GPO registry values
    # (documented + honored by RDSH and the RD Licensing Diagnoser). The WMI
    # ChangeMode/SetSpecifiedLicenseServerList methods are unreliable on
    # 2022/2025 ('Invalid operation'), so we try them best-effort and stay quiet.
    param([int]$Mode, [string]$Server)
    $rdsh = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $rdsh)) { New-Item -Path $rdsh -Force | Out-Null }
    Set-ItemProperty -Path $rdsh -Name "LicensingMode"  -Value $Mode   -Type DWord
    Set-ItemProperty -Path $rdsh -Name "LicenseServers" -Value $Server -Type String
    # Best-effort WMI (ignore failures - registry policy is authoritative)
    try {
        $ts = Get-CimInstance -Namespace "root/cimv2/terminalservices" -ClassName "Win32_TerminalServiceSetting" -ErrorAction Stop
        try { Invoke-CimMethod -InputObject $ts -MethodName "ChangeMode" -Arguments @{ LicensingType = [uint32]$Mode } -ErrorAction Stop | Out-Null } catch {}
        try { Invoke-CimMethod -InputObject $ts -MethodName "SetSpecifiedLicenseServerList" -Arguments @{ LSList = @($Server) } -ErrorAction Stop | Out-Null } catch {}
    } catch {}
    return $true
}

function Invoke-LicenseServerActivate {
    # Activates the license server over the Internet.
    # FirstName/LastName/Company/CountryRegion are REQUIRED; eMail is optional
    # (the licmgr GUI asks for it on the 2nd "Company Information" page).
    # Win32_TSLicenseServer is a SINGLETON: it must be fetched via the "=@" path
    # so that .Put() works. Plain Get-WmiObject/Get-CimInstance gives an instance
    # whose .Put() fails with "Invalid parameter" on Server 2022/2025.
    param(
        [string]$FirstName, [string]$LastName, [string]$Company,
        [string]$Country,   [string]$Email = ""
    )
    try {
        $ls = [wmi]"\\.\root\cimv2:Win32_TSLicenseServer=@"
    } catch {
        return @{ ok = $false; msg = "Win32_TSLicenseServer not available (is the 'Remote Desktop Licensing' service running?)" }
    }
    try {
        $ls.FirstName     = $FirstName
        $ls.LastName      = $LastName
        $ls.Company       = $Company
        $ls.CountryRegion = $Country
        if ($Email) { $ls.eMail = $Email }
        $ls.Put() | Out-Null
    } catch {
        return @{ ok = $false; msg = "Could not set contact properties (needed for activation): $($_.Exception.Message)" }
    }
    # Activate on the same singleton object.
    try {
        $r  = $ls.ActivateServerAutomatic()
        $rv = [int]$r.ReturnValue
        $st = [int]$r.ActivationStatus
        if ($rv -eq 0 -and $st -eq 0) { return @{ ok = $true; msg = "Activated." } }
        # Fallback: try via CIM in case the WMI adapter mis-handled the [out] param
        try {
            $lc = Get-TSLicenseServerCim
            $r2 = Invoke-CimMethod -InputObject $lc -MethodName "ActivateServerAutomatic" -ErrorAction Stop
            if ([int]$r2.ReturnValue -eq 0 -and [int]$r2.ActivationStatus -eq 0) { return @{ ok = $true; msg = "Activated." } }
            return @{ ok = $false; msg = "ReturnValue=$([int]$r2.ReturnValue), ActivationStatus=$([int]$r2.ActivationStatus)" }
        } catch {
            return @{ ok = $false; msg = "ReturnValue=$rv, ActivationStatus=$st (automatic clearinghouse may be unreachable)" }
        }
    } catch {
        return @{ ok = $false; msg = "ActivateServerAutomatic failed: $($_.Exception.Message)" }
    }
}

function Install-AgreementCals {
    # Installs CALs from a volume agreement. AgreementType: 0=Select, 1=Enterprise,
    # 2=Campus, 3=School, 4=Service Provider, 5=Other. ProductType: 0=PerDevice, 1=PerUser.
    param([int]$AgreementType, [string]$Number, [int]$ProductVersion, [int]$ProductType, [int]$Count)
    try {
        $r = Invoke-CimMethod -Namespace "root/cimv2" -ClassName "Win32_TSLicenseKeyPack" `
            -MethodName "InstallAgreementLicenseKeyPack" -Arguments @{
                AgreementType    = [uint32]$AgreementType
                sAgreementNumber = "$Number"
                ProductVersion   = [uint32]$ProductVersion
                ProductType      = [uint32]$ProductType
                LicenseCount     = [uint32]$Count
            } -ErrorAction Stop
        $rv = [int]$r.ReturnValue
        if ($rv -eq 0) { return @{ ok = $true;  msg = "Installed $Count CAL(s). KeyPackId=$($r.KeyPackId)" } }
        return @{ ok = $false; msg = "InstallAgreementLicenseKeyPack ReturnValue=$rv (check EA number / product version / Internet)" }
    } catch {
        return @{ ok = $false; msg = "InstallAgreementLicenseKeyPack failed: $($_.Exception.Message)" }
    }
}

function Get-CalProductVersion {
    # Best-effort ProductVersion for InstallAgreementLicenseKeyPack based on OS.
    # Documented: 5=2016, 6=2019. 2022=7, 2025=8 are by observation (undocumented).
    $cap = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    switch -Regex ($cap) {
        '2016' { 5 }
        '2019' { 6 }
        '2022' { 7 }
        '2025' { 8 }
        default { 6 }
    }
}

function Get-LicensingModeName {
    param([int]$Mode)
    switch ($Mode) {
        2 { "Per Device" }
        4 { "Per User" }
        5 { "Not configured" }
        default { "Unknown ($Mode)" }
    }
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
#  CURRENT STATE / INVENTORY
#  (re-run friendly: shows what is already configured)
# ==============================

Write-Step "CURRENT STATE (what is already configured)"

$localhost = $env:COMPUTERNAME

# Roles
foreach ($role in $rolesToInstall) {
    $inst = (Get-WindowsFeature -Name $role).Installed
    $tag  = if ($inst) { "[OK]  " } else { "[--]  " }
    $clr  = if ($inst) { "Green" } else { "Yellow" }
    Write-Host "$tag Role $role : $(if($inst){'installed'}else{'MISSING'})" -ForegroundColor $clr
}

# Licensing state
$actState = Get-LicenseServerActivation
$shState  = Get-SessionHostLicensing
Write-Host ""
if ($actState.Found) {
    if ($actState.Activated) {
        Write-Host "[OK]  License server : ACTIVATED" -ForegroundColor Green
    } else {
        Write-Host "[!!]  License server : NOT activated (code $($actState.Code))" -ForegroundColor Red
    }
} else {
    Write-Host "[!!]  License server : WMI object not found (role not ready?)" -ForegroundColor Red
}
if ($shState.Found) {
    $modeName = Get-LicensingModeName -Mode $shState.Mode
    $srvList  = if ($shState.Servers.Count) { $shState.Servers -join ", " } else { "(none)" }
    $modeClr  = if ($shState.Mode -eq 5 -or $shState.Mode -lt 0) { "Red" } else { "Green" }
    Write-Host "      Session Host mode : $modeName" -ForegroundColor $modeClr
    $srvClr = if ($shState.Servers.Count) { "Green" } else { "Red" }
    Write-Host "      License server(s) configured on host : $srvList" -ForegroundColor $srvClr
}

# Current RDP port + users + firewall
$rdpPortPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$curPort = (Get-ItemProperty -Path $rdpPortPath -Name "PortNumber" -ErrorAction SilentlyContinue).PortNumber
Write-Host ""
Write-Host "      Current RDP port : $curPort" -ForegroundColor White
try {
    $rdpGrpName = (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-555")).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    $rdpMembers = @(Get-LocalGroupMember -Group $rdpGrpName -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Split('\')[-1] })
    Write-Host "      RDP users ($rdpGrpName): $(if($rdpMembers.Count){$rdpMembers -join ', '}else{'(none)'})" -ForegroundColor White
} catch {}
$fwInbound = (Get-NetFirewallProfile -Profile Domain).DefaultInboundAction
Write-Host "      Firewall default inbound (Domain profile): $fwInbound" -ForegroundColor White

# ==============================
#  INTERACTIVE CONFIGURATION
#  (asked only once - after roles are installed, no reboot pending)
# ==============================

Write-Step "INTERACTIVE SETUP"

Write-Host "Answer the questions below. Press Enter to accept the [default]." -ForegroundColor Gray
Write-Host ""

# --- Q1: RD Licensing (re-run aware) ---
# Three independent things (kept separate on purpose):
#   A) Session Host config  -> which license server + mode (registry policy). Fixes the
#      "licensing mode not configured" nag. No Internet / no EA needed.
#   B) Activate license server -> registers the server with MS over the Internet.
#      Needs contact name/company/country. NOT related to the EA number.
#   C) Install CALs from a volume agreement (e.g. Enterprise Agreement). Needs the
#      7-digit agreement number, the server ALREADY activated, and Internet.
Write-Host "1) RD Licensing" -ForegroundColor Cyan

$licConfigOk = $shState.Found -and $shState.Mode -ne 5 -and $shState.Mode -ge 0 -and $shState.Servers.Count -gt 0

Write-Host "   Current: activation=$(if($actState.Activated){'ACTIVATED'}else{'NOT activated'}), Session-Host config=$(if($licConfigOk){'OK'}else{'incomplete'})." -ForegroundColor Gray

$ReLicense = Read-YesNo -Prompt "   Configure RD licensing now?" -Default (-not ($actState.Activated -and $licConfigOk))

# Sub-decisions
$DoActivate = $false
$DoInstallCals = $false
$AgreementNumber = ""
$CalCount = 0
$CalAgreementType = 1   # 1 = Enterprise Agreement
$CalProductType   = if ($LicensingMode -eq 2) { 0 } else { 1 }   # 0=Per Device, 1=Per User
$CalProductVersion = Get-CalProductVersion
$ActFirst = ""; $ActLast = ""; $ActCompany = ""; $ActCountry = ""; $ActEmail = ""

if ($ReLicense) {
    # B) Activation
    $DoActivate = Read-YesNo -Prompt "   (A) Activate the license server over the Internet now?" -Default (-not $actState.Activated)
    if ($DoActivate) {
        Write-Host "   Contact details are REQUIRED by Microsoft to activate (not the EA number):" -ForegroundColor Gray
        $ActFirst   = Read-Default -Prompt "     First name" -Default "Admin"
        $ActLast    = Read-Default -Prompt "     Last name"  -Default "Admin"
        $ActCompany = Read-Default -Prompt "     Company"    -Default "Company"
        $ActCountry = Read-Default -Prompt "     Country/Region (e.g. US, GB, UA, DE)" -Default "US"
        $ActEmail   = Read-Default -Prompt "     Email (optional, Enter to skip)" -Default ""
    }

    # C) CAL installation from an agreement
    $DoInstallCals = Read-YesNo -Prompt "   (B) Install RDS CALs from a volume agreement (EA) now?" -Default $false
    if ($DoInstallCals) {
        Write-Host "   Agreement type: 0=Select 1=Enterprise 2=Campus 3=School 4=ServiceProvider 5=Other" -ForegroundColor Gray
        $CalAgreementType  = Read-IntInRange -Prompt "     Agreement type" -Default 1 -Min 0 -Max 5
        $AgreementNumber   = Read-Default    -Prompt "     Agreement number (7 digits, no hyphens)" -Default ""
        $CalCount          = Read-IntInRange -Prompt "     Number of CALs to install" -Default 5 -Min 1 -Max 100000
        $CalProductVersion = Read-IntInRange -Prompt "     Product version (5=2016 6=2019 7=2022 8=2025)" -Default $CalProductVersion -Min 2 -Max 9
        if ([string]::IsNullOrWhiteSpace($AgreementNumber)) {
            Write-Host "     No agreement number -> CAL install skipped." -ForegroundColor Yellow
            $DoInstallCals = $false
        }
    }

    Write-Host "   -> Session Host will be pointed at local license server ($localhost, $(Get-LicensingModeName -Mode $LicensingMode))." -ForegroundColor Green
    if ($DoActivate)    { Write-Host "   -> Will activate the license server." -ForegroundColor Green }
    if ($DoInstallCals) { Write-Host "   -> Will install $CalCount CAL(s) from agreement $AgreementNumber." -ForegroundColor Green }
} else {
    Write-Host "   -> Leaving licensing as-is." -ForegroundColor Yellow
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

$rdshPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$licModeName = Get-LicensingModeName -Mode $LicensingMode
$calMsg = ""   # summary of CAL install for the report

if (-not $ReLicense) {
    Write-Host "[SKIP] Licensing left unchanged by choice." -ForegroundColor Yellow
}
else {
    # 2a. Session Host config: point at local license server + set mode.
    #     (registry policy is authoritative; WMI is best-effort inside the helper)
    Set-SessionHostLicensing -Mode $LicensingMode -Server $localhost | Out-Null
    Write-Host "[OK] Session Host configured: mode=$licModeName, license server='$localhost'." -ForegroundColor Green

    # 2b. Activate the license server (contact info required; needs Internet)
    if ($DoActivate) {
        Write-Step "STEP 2b: Activating License Server (over the Internet)"
        Write-Host "[ACTIVATING] Contact: $ActFirst $ActLast / $ActCompany / $ActCountry$(if($ActEmail){" / $ActEmail"}) ..." -ForegroundColor Yellow
        $act = Invoke-LicenseServerActivate -FirstName $ActFirst -LastName $ActLast -Company $ActCompany -Country $ActCountry -Email $ActEmail
        if ($act.ok) {
            Write-Host "[OK] License server activated." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Activation did not complete: $($act.msg)" -ForegroundColor Yellow
            Write-Host "[INFO] Finish in GUI: licmgr.exe -> right-click server -> Activate Server -> Automatic." -ForegroundColor White
        }
    }
    else {
        Write-Host "[INFO] License server activation skipped." -ForegroundColor Yellow
    }

    # 2c. Install CALs from an agreement (server must be activated first)
    if ($DoInstallCals) {
        Write-Step "STEP 2c: Installing CALs from agreement"
        $actNow = (Get-LicenseServerActivation).Activated
        if (-not $actNow) {
            $calMsg = "skipped (server not activated)"
            Write-Host "[WARN] Server is not activated yet - cannot install CALs. Activate first, then re-run." -ForegroundColor Yellow
        } else {
            $ptName = if ($CalProductType -eq 0) { "Per Device" } else { "Per User" }
            Write-Host "[INSTALLING] $CalCount $ptName CAL(s), agreement type=$CalAgreementType, number=$AgreementNumber, product ver=$CalProductVersion ..." -ForegroundColor Yellow
            $cal = Install-AgreementCals -AgreementType $CalAgreementType -Number $AgreementNumber -ProductVersion $CalProductVersion -ProductType $CalProductType -Count $CalCount
            if ($cal.ok) {
                $calMsg = "installed $CalCount CAL(s) (agreement $AgreementNumber)"
                Write-Host "[OK] $($cal.msg)" -ForegroundColor Green
            } else {
                $calMsg = "FAILED: $($cal.msg)"
                Write-Host "[WARN] CAL install failed: $($cal.msg)" -ForegroundColor Yellow
                Write-Host "[INFO] Finish in GUI: licmgr.exe -> right-click server -> Install Licenses -> pick your agreement program." -ForegroundColor White
                Write-Host "[INFO] If product version was wrong, re-run and try 7 (2022) or 8 (2025)." -ForegroundColor White
            }
        }
        Set-ItemProperty -Path $rdshPath -Name "EnterpriseAgreement" -Value $AgreementNumber -Type String
    }

    # 2d. Post-config diagnostic
    Write-Host ""
    Write-Host "[DIAG] Licensing after configuration:" -ForegroundColor Cyan
    $act2 = Get-LicenseServerActivation
    $sh2  = Get-SessionHostLicensing
    Write-Host ("       License server activated : {0}" -f $(if($act2.Activated){'YES'}else{'NO'})) -ForegroundColor $(if($act2.Activated){'Green'}else{'Yellow'})
    if ($sh2.Found) {
        Write-Host ("       Session Host mode        : {0}" -f (Get-LicensingModeName -Mode $sh2.Mode)) -ForegroundColor Green
        Write-Host ("       License server on host   : {0}" -f $(if($sh2.Servers.Count){$sh2.Servers -join ', '}else{'(none)'})) -ForegroundColor $(if($sh2.Servers.Count){'Green'}else{'Yellow'})
    }
    Write-Host "[INFO] Full diagnosis GUI: run  lsdiag.msc  (RD Licensing Diagnoser)." -ForegroundColor Gray
}

# Remember effective activation state for the final report
$licActivatedNow = (Get-LicenseServerActivation).Activated

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
            Write-Host "[SKIP] User '$userName' already exists - resetting password." -ForegroundColor Yellow
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

  !!! SENSITIVE - contains passwords. Store securely, then delete. !!!
  Users (login / password):
$userLines

  Firewall:
    - All inbound BLOCKED
    - ICMP Ping ALLOWED
    - TCP/UDP $NewPort ALLOWED

  Licensing:
    - Mode: $licModeName
    - License server: $(if ($licActivatedNow) { "ACTIVATED ($localhost)" } else { "NOT activated - run licmgr.exe / lsdiag.msc" })
    - Agreement: $(if ($AgreementNumber) { $AgreementNumber } else { "(none provided)" })
    - CALs: $(if ($calMsg) { $calMsg } else { "(not installed this run)" })

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
if ($licActivatedNow) {
    Write-Host "    - License server: ACTIVATED ($localhost)" -ForegroundColor Green
} else {
    Write-Host "    - License server: NOT activated -> activate: licmgr.exe ; diagnose: lsdiag.msc" -ForegroundColor Yellow
}
if ($AgreementNumber) { Write-Host "    - Agreement: $AgreementNumber" -ForegroundColor White }
if ($calMsg)          { Write-Host "    - CALs: $calMsg" -ForegroundColor $(if($calMsg -like 'installed*'){'Green'}else{'Yellow'}) }
Write-Host ""

Write-Host "  [!] Credentials + connection info saved to: $infoFile" -ForegroundColor Cyan
Write-Host "  [!] That file contains PASSWORDS - store it securely and delete afterwards." -ForegroundColor Red
Write-Host ""

if ($ChangePort -and $OldPort -ne $NewPort) {
    Write-Host "  [!] SAVE THIS PORT: $NewPort" -ForegroundColor Red
    Write-Host ""
    Write-Host "  +-------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  Restarting TermService in 10 seconds...        |" -ForegroundColor Yellow
    Write-Host "  |  Your RDP session WILL disconnect.              |" -ForegroundColor Yellow
    Write-Host "  |  Reconnect using the NEW port above.            |" -ForegroundColor Green
    Write-Host "  +-------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""
    Start-Sleep -Seconds 10
    Restart-Service -Name "TermService" -Force
}
else {
    Write-Host "  [OK] RDP port unchanged - no service restart needed." -ForegroundColor Green
    Write-Host "  [OK] Setup finished." -ForegroundColor Green
}
