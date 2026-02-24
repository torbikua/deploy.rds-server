#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 — Terminal Server Optimization & Hardening.
.DESCRIPTION
    Run AFTER the main Setup-TerminalServer.ps1 script.
    Applies performance tuning, security hardening, cleanup, and stability improvements.
    
    EXCLUDES: drive redirection blocking, printer redirection limiting (per user request).
.NOTES
    Some changes require a reboot to take full effect.
    All configurable parameters are in the CONFIGURATION section below.
#>

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         CONFIGURATION — EDIT HERE                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ── TEMP FOLDER ──────────────────────────────────────────────────────────────
# Redirect system TEMP/TMP to a separate drive for better I/O performance.
# Set to $null to keep default (C:\Windows\Temp), or specify path like "D:\Temp"
$TempDrive = $null

# ── RDP VISUAL QUALITY ───────────────────────────────────────────────────────
# Image quality for RDP codec: 1 = Low, 2 = Medium, 3 = High (lossless refinement)
# Higher = sharper picture, more bandwidth. Use 2 for slow connections, 3 for LAN/fast WAN.
$RdpImageQuality = 3

# Color depth: 3 = 16-bit, 4 = 24-bit, 5 = 32-bit
# 32-bit gives best colors but uses more bandwidth. 24-bit is a good compromise.
$RdpColorDepth = 5

# Progressive encoding: $true = show blurry frame first then sharpen (saves bandwidth),
# $false = always send sharp frames (no pixelation, but uses more bandwidth)
$RdpProgressiveEncoding = $false

# Font smoothing (ClearType): $true = smooth readable fonts, $false = saves bandwidth
$RdpFontSmoothing = $true

# Allow desktop wallpaper in RDP sessions: $true = yes, $false = solid color (saves bandwidth)
$RdpAllowWallpaper = $true

# Allow camera redirection from client to server: $true = yes, $false = disabled
$RdpAllowCamera = $true

# UDP transport: $true = enable (faster on unstable links), $false = TCP only
$RdpEnableUDP = $true

# ── SESSION TIMEOUTS (milliseconds) ─────────────────────────────────────────
# How long an IDLE session stays alive before warning/disconnect (ms). 0 = unlimited.
$SessionIdleTimeoutMs = 3600000       # 60 minutes (from main setup script)

# How long a DISCONNECTED session stays on server before terminating (ms). 0 = unlimited.
$SessionDisconnectTimeoutMs = 28800000 # 8 hours

# ── SECURITY: ACCOUNT LOCKOUT ───────────────────────────────────────────────
# Number of failed login attempts before account is locked
$LockoutBadCount = 5

# Time (seconds) after which the failed attempt counter resets
$LockoutResetTimeSec = 900            # 15 minutes

# How long (seconds) a locked account stays locked. 0 = until admin unlocks manually.
$LockoutDurationSec = 1800            # 30 minutes

# ── SECURITY: CREDSSP ───────────────────────────────────────────────────────
# CredSSP encryption oracle remediation:
#   0 = Force Updated Clients (most secure, old clients can't connect)
#   1 = Mitigated (secure default, warns on old clients)
#   2 = Vulnerable (allows all clients, NOT recommended)
$CredSSPPolicy = 0

# ── CLEANUP ──────────────────────────────────────────────────────────────────
# Delete temp files older than this many days (scheduled cleanup task)
$TempCleanupDays = 7

# Time of day to run temp cleanup (24h format)
$TempCleanupTime = "03:00"

# Recycle Bin max size in MB per drive (0 = Windows default)
$RecycleBinMaxMB = 512

# ── WINDOWS UPDATE ───────────────────────────────────────────────────────────
# Update behavior:
#   2 = Notify before download
#   3 = Auto download, notify to install (recommended for servers)
#   4 = Auto download and install on schedule
$WindowsUpdateMode = 3

# Active hours — Windows will NOT reboot for updates during this window
$ActiveHoursStart = 6                 # 06:00
$ActiveHoursEnd   = 23                # 23:00

# ── EVENT LOGS (sizes in MB) ────────────────────────────────────────────────
$LogSizeApplication   = 128
$LogSizeSecurity      = 256
$LogSizeSystem        = 128
$LogSizeRdsLocal      = 64            # TerminalServices-LocalSessionManager
$LogSizeRdsRemote     = 64            # TerminalServices-RemoteConnectionManager

# ── SERVICES TO DISABLE ─────────────────────────────────────────────────────
# Comment out (with #) any service you want to KEEP running.
$ServicesToDisable = @(
    @{ Name = "XblAuthManager";     Desc = "Xbox Live Auth Manager" }
    @{ Name = "XblGameSave";        Desc = "Xbox Live Game Save" }
    @{ Name = "XboxGipSvc";         Desc = "Xbox Accessory Management" }
    @{ Name = "XboxNetApiSvc";      Desc = "Xbox Live Networking" }
    @{ Name = "DiagTrack";          Desc = "Connected User Experiences (Telemetry)" }
    @{ Name = "dmwappushservice";   Desc = "WAP Push Message Routing" }
    @{ Name = "MapsBroker";         Desc = "Downloaded Maps Manager" }
    @{ Name = "lfsvc";              Desc = "Geolocation Service" }
    @{ Name = "RetailDemo";         Desc = "Retail Demo Service" }
    @{ Name = "wisvc";              Desc = "Windows Insider Service" }
    @{ Name = "WSearch";            Desc = "Windows Search (heavy I/O on terminal servers)" }
    @{ Name = "Fax";                Desc = "Fax Service" }
    @{ Name = "TabletInputService"; Desc = "Tablet PC Input Service" }
    @{ Name = "WerSvc";             Desc = "Windows Error Reporting" }
    @{ Name = "SysMain";            Desc = "Superfetch (not useful on servers)" }
)

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                     END OF CONFIGURATION — DO NOT EDIT BELOW               ║
# ║                     (unless you know what you're doing)                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ==============================
#  AUTO-DETECT & HELPERS
# ==============================

$RdpPort = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber").PortNumber
Write-Host "[INFO] Detected RDP port from registry: $RdpPort" -ForegroundColor Cyan

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

$tsPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

if (-not (Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }


# ##############################################################################
#  1. PERFORMANCE & RESPONSIVENESS
# ##############################################################################

Write-Step "1. PERFORMANCE TUNING"

# --- 1a. Power Plan: High Performance ---
Write-Host "[*] Setting power plan to High Performance..." -ForegroundColor Yellow
$highPerf = powercfg -list | Select-String "High performance"
if ($highPerf -match "([0-9a-f\-]{36})") {
    powercfg -setactive $Matches[1]
    Write-Host "[OK] Power plan set to High Performance." -ForegroundColor Green
} else {
    powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    $highPerf = powercfg -list | Select-String "High performance"
    if ($highPerf -match "([0-9a-f\-]{36})") {
        powercfg -setactive $Matches[1]
        Write-Host "[OK] High Performance plan created and activated." -ForegroundColor Green
    }
}

# Disable CPU idle (prevent C-states throttling)
powercfg -setacvalueindex scheme_current sub_processor IDLEDISABLE 1
powercfg -setactive scheme_current

# Disable USB selective suspend
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg -setactive scheme_current
Write-Host "[OK] CPU idle states and USB suspend disabled." -ForegroundColor Green

# --- 1b. Processor Scheduling: Background Services ---
Write-Host "[*] Setting processor scheduling to Background Services..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" `
    -Name "Win32PrioritySeparation" -Value 24 -Type DWord
Write-Host "[OK] Processor scheduling optimized for background services." -ForegroundColor Green

# --- 1c. Visual Effects — Quality + Performance Balance ---
Write-Host "[*] Configuring visual effects (quality mode, animations off)..." -ForegroundColor Yellow

# Wallpaper policy
$wallpaperValue = if ($RdpAllowWallpaper) { 0 } else { 1 }
Set-ItemProperty -Path $tsPath -Name "fNoRemoteDesktopWallpaper" -Value $wallpaperValue -Type DWord
Set-ItemProperty -Path $tsPath -Name "fDisableWallpaper" -Value ([int](-not $RdpAllowWallpaper)) -Type DWord

# Disable only window animations (not rendering quality)
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowAnimations" -Value 1 -Type DWord

# Visual effects: Custom — disable only animations, keep quality rendering
$visualFxPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
if (-not (Test-Path $visualFxPath)) { New-Item -Path $visualFxPath -Force | Out-Null }
Set-ItemProperty -Path $visualFxPath -Name "VisualFXSetting" -Value 3 -Type DWord  # 3 = Custom

# Fine-grained control: disable animations but keep smooth fonts and edges
$desktopPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $desktopPath -Name "TaskbarAnimations" -Value 0 -Type DWord

$dwPath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $dwPath -Name "UserPreferencesMask" `
    -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Type Binary

$dwmPath2 = "HKCU:\Software\Microsoft\Windows\DWM"
if (-not (Test-Path $dwmPath2)) { New-Item -Path $dwmPath2 -Force | Out-Null }
Set-ItemProperty -Path $dwmPath2 -Name "EnableAeroPeek"               -Value 0 -Type DWord
Set-ItemProperty -Path $dwmPath2 -Name "AlwaysHibernateThumbnails"     -Value 0 -Type DWord

# Camera redirect
$camValue = if ($RdpAllowCamera) { 0 } else { 1 }
Set-ItemProperty -Path $tsPath -Name "fDisableCam" -Value $camValue -Type DWord

# Enhanced RemoteFX UI
Set-ItemProperty -Path $tsPath -Name "bEnhancedRemoteFXUI" -Value 1 -Type DWord

# Font smoothing (ClearType)
$smoothValue = if ($RdpFontSmoothing) { 1 } else { 0 }
Set-ItemProperty -Path $tsPath -Name "fEnableSmoothing" -Value $smoothValue -Type DWord

Write-Host "[OK] Visual effects configured (wallpaper=$RdpAllowWallpaper, fonts=$RdpFontSmoothing, camera=$RdpAllowCamera)." -ForegroundColor Green

# --- 1d. UDP Transport for RDP ---
Write-Host "[*] Configuring RDP UDP transport..." -ForegroundColor Yellow

$udpDisableValue = if ($RdpEnableUDP) { 0 } else { 1 }
$selectTransport = if ($RdpEnableUDP) { 0 } else { 1 }  # 0 = auto (UDP preferred), 1 = TCP only
Set-ItemProperty -Path $tsPath -Name "fDisableUDPTransport" -Value $udpDisableValue -Type DWord
Set-ItemProperty -Path $tsPath -Name "SelectTransport"      -Value $selectTransport -Type DWord

if ($RdpEnableUDP) {
    $existingUDP = Get-NetFirewallRule -DisplayName "RDP-Custom-UDP-$RdpPort" -ErrorAction SilentlyContinue
    if (-not $existingUDP) {
        New-NetFirewallRule -DisplayName "RDP-Custom-UDP-$RdpPort" `
            -Direction Inbound -Protocol UDP -LocalPort $RdpPort `
            -Action Allow -Profile Any -Enabled True | Out-Null
        Write-Host "[OK] Firewall rule for UDP $RdpPort created." -ForegroundColor Green
    }
}
Write-Host "[OK] RDP UDP transport: $RdpEnableUDP" -ForegroundColor Green

# --- 1e. RDP Codec & Compression ---
Write-Host "[*] Optimizing RDP codecs and image quality..." -ForegroundColor Yellow

$rfxPath = $tsPath  # same registry path

# RemoteFX adaptive graphics
Set-ItemProperty -Path $rfxPath -Name "fEnableVirtualizedGraphics"      -Value 1 -Type DWord
Set-ItemProperty -Path $rfxPath -Name "fEnableRemoteFXAdvancedRemoteApp" -Value 1 -Type DWord

# AVC/H.264
Set-ItemProperty -Path $rfxPath -Name "AVCHardwareEncodePreferred" -Value 1 -Type DWord
Set-ItemProperty -Path $rfxPath -Name "AVC444ModePreferred"        -Value 1 -Type DWord

# Progressive encoding (the "pixelated then sharpens" toggle)
$progressiveValue = if ($RdpProgressiveEncoding) { 1 } else { 0 }
Set-ItemProperty -Path $rfxPath -Name "bProgressiveEncoding" -Value $progressiveValue -Type DWord

# Visual quality
Set-ItemProperty -Path $rfxPath -Name "VisualChannelPriority" -Value 1 -Type DWord
Set-ItemProperty -Path $rfxPath -Name "GraphicsProfile"       -Value 2 -Type DWord   # 2 = High quality
Set-ItemProperty -Path $rfxPath -Name "ImageQuality"          -Value $RdpImageQuality -Type DWord

# Color depth
Set-ItemProperty -Path $rdpTcpPath -Name "ColorDepth"       -Value $RdpColorDepth -Type DWord
Set-ItemProperty -Path $rdpTcpPath -Name "ColorDepthPolicy"  -Value 1 -Type DWord   # 1 = enforce

# Compression
Set-ItemProperty -Path $rdpTcpPath -Name "CompressRDP" -Value 1 -Type DWord

# Keep-alive
Set-ItemProperty -Path $rfxPath -Name "KeepAliveInterval" -Value 1 -Type DWord
Set-ItemProperty -Path $rfxPath -Name "KeepAliveEnable"   -Value 1 -Type DWord

Write-Host "[OK] RDP codecs: AVC444, ImageQuality=$RdpImageQuality, ColorDepth=$RdpColorDepth, Progressive=$RdpProgressiveEncoding." -ForegroundColor Green

# --- 1f. Memory ---
Write-Host "[*] Tuning memory settings..." -ForegroundColor Yellow

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
    -Name "LargeSystemCache" -Value 1 -Type DWord
Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue

Write-Host "[OK] Memory optimized (large cache, compression disabled)." -ForegroundColor Green


# ##############################################################################
#  2. SECURITY HARDENING
# ##############################################################################

Write-Step "2. SECURITY HARDENING"

# --- 2a. RDP TLS/Encryption ---
Write-Host "[*] Enforcing TLS 1.2 for RDP connections..." -ForegroundColor Yellow

Set-ItemProperty -Path $rdpTcpPath -Name "SecurityLayer"      -Value 2 -Type DWord  # 2 = SSL/TLS
Set-ItemProperty -Path $rdpTcpPath -Name "MinEncryptionLevel" -Value 3 -Type DWord  # 3 = High

Write-Host "[OK] RDP security: SSL/TLS layer, High encryption." -ForegroundColor Green

# --- 2b. Disable legacy protocols ---
Write-Host "[*] Disabling SSL 3.0, TLS 1.0, TLS 1.1..." -ForegroundColor Yellow

$protocols = @(
    @{ Name = "SSL 3.0";  Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" }
    @{ Name = "TLS 1.0";  Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" }
    @{ Name = "TLS 1.1";  Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" }
)

foreach ($proto in $protocols) {
    foreach ($side in @("Server", "Client")) {
        $regPath = "$($proto.Path)\$side"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "Enabled"           -Value 0 -Type DWord
        Set-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value 1 -Type DWord
    }
    Write-Host "[OK] $($proto.Name) disabled." -ForegroundColor Green
}

foreach ($side in @("Server", "Client")) {
    $tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$side"
    if (-not (Test-Path $tls12Path)) { New-Item -Path $tls12Path -Force | Out-Null }
    Set-ItemProperty -Path $tls12Path -Name "Enabled"           -Value 1 -Type DWord
    Set-ItemProperty -Path $tls12Path -Name "DisabledByDefault" -Value 0 -Type DWord
}
Write-Host "[OK] TLS 1.2 explicitly enabled." -ForegroundColor Green

# --- 2c. CredSSP ---
Write-Host "[*] Hardening CredSSP..." -ForegroundColor Yellow

$credSSPPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if (-not (Test-Path $credSSPPath)) { New-Item -Path $credSSPPath -Force | Out-Null }
Set-ItemProperty -Path $credSSPPath -Name "AllowEncryptionOracle" -Value $CredSSPPolicy -Type DWord

$credSSPDesc = switch ($CredSSPPolicy) { 0 {"Force Updated Clients"} 1 {"Mitigated"} 2 {"Vulnerable"} }
Write-Host "[OK] CredSSP set to '$credSSPDesc' (value=$CredSSPPolicy)." -ForegroundColor Green

# --- 2d. Weak ciphers ---
Write-Host "[*] Disabling weak ciphers (RC4, DES, NULL, 3DES)..." -ForegroundColor Yellow

$weakCiphers = @(
    "RC4 128/128", "RC4 56/128", "RC4 40/128", "RC4 64/128",
    "DES 56/56", "NULL", "Triple DES 168"
)

foreach ($cipher in $weakCiphers) {
    $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
    if (-not (Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
    Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord
}
Write-Host "[OK] Weak ciphers disabled." -ForegroundColor Green

# --- 2e. Account Lockout ---
Write-Host "[*] Configuring account lockout policy..." -ForegroundColor Yellow

$secpolFile = "$env:TEMP\secpol_export.cfg"
$secpolMod  = "$env:TEMP\secpol_modified.cfg"
secedit /export /cfg $secpolFile /quiet

$secContent = Get-Content $secpolFile
$secContent = $secContent -replace "LockoutBadCount\s*=\s*\d+",     "LockoutBadCount = $LockoutBadCount"
$secContent = $secContent -replace "ResetLockoutCount\s*=\s*\d+",   "ResetLockoutCount = $LockoutResetTimeSec"
$secContent = $secContent -replace "LockoutDuration\s*=\s*\d+",     "LockoutDuration = $LockoutDurationSec"

if ($secContent -notmatch "LockoutBadCount") {
    $secContent = $secContent -replace "(\[System Access\])", "`$1`r`nLockoutBadCount = $LockoutBadCount"
}
if ($secContent -notmatch "ResetLockoutCount") {
    $secContent = $secContent -replace "(\[System Access\])", "`$1`r`nResetLockoutCount = $LockoutResetTimeSec"
}
if ($secContent -notmatch "LockoutDuration") {
    $secContent = $secContent -replace "(\[System Access\])", "`$1`r`nLockoutDuration = $LockoutDurationSec"
}

$secContent | Set-Content $secpolMod -Encoding Unicode
secedit /configure /db secedit.sdb /cfg $secpolMod /quiet
Remove-Item $secpolFile, $secpolMod -Force -ErrorAction SilentlyContinue

$lockResetMin = [math]::Round($LockoutResetTimeSec / 60)
$lockDurMin   = [math]::Round($LockoutDurationSec / 60)
Write-Host "[OK] Lockout: $LockoutBadCount attempts, reset ${lockResetMin}min, lock ${lockDurMin}min." -ForegroundColor Green


# ##############################################################################
#  3. DISK & TEMP CLEANUP
# ##############################################################################

Write-Step "3. DISK & TEMP MANAGEMENT"

# --- 3a. TEMP redirection ---
if ($TempDrive) {
    Write-Host "[*] Redirecting system TEMP to $TempDrive ..." -ForegroundColor Yellow
    if (-not (Test-Path $TempDrive)) { New-Item -Path $TempDrive -ItemType Directory -Force | Out-Null }
    [Environment]::SetEnvironmentVariable("TEMP", $TempDrive, "Machine")
    [Environment]::SetEnvironmentVariable("TMP",  $TempDrive, "Machine")
    Write-Host "[OK] System TEMP/TMP redirected to $TempDrive." -ForegroundColor Green
} else {
    Write-Host "[SKIP] TEMP redirection not configured." -ForegroundColor Gray
}

# --- 3b. Scheduled Cleanup ---
Write-Host "[*] Creating scheduled task for temp cleanup (files > $TempCleanupDays days)..." -ForegroundColor Yellow

$cleanupScript = @"
# Auto-generated by Optimize-TerminalServer.ps1
# Cleanup temp files older than $TempCleanupDays days
`$maxAge = (Get-Date).AddDays(-$TempCleanupDays)
`$folders = @(
    "`$env:SystemRoot\Temp",
    "`$env:SystemRoot\Logs\CBS"
)
Get-ChildItem "C:\Users\*\AppData\Local\Temp" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    `$folders += `$_.FullName
}
foreach (`$folder in `$folders) {
    if (Test-Path `$folder) {
        Get-ChildItem -Path `$folder -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not `$_.PSIsContainer -and `$_.LastWriteTime -lt `$maxAge } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item "`$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue
"@

$cleanupPath = "$env:ProgramData\Scripts\Cleanup-TempFiles.ps1"
$scriptsDir = Split-Path $cleanupPath
if (-not (Test-Path $scriptsDir)) { New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null }
$cleanupScript | Set-Content -Path $cleanupPath -Encoding UTF8

$taskAction    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupPath`""
$taskTrigger   = New-ScheduledTaskTrigger -Daily -At $TempCleanupTime
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Unregister-ScheduledTask -TaskName "RDS-TempCleanup" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "RDS-TempCleanup" `
    -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal `
    -Description "Clean temp files older than $TempCleanupDays days (RDS optimization)" | Out-Null

Write-Host "[OK] Scheduled task 'RDS-TempCleanup' created (daily at $TempCleanupTime)." -ForegroundColor Green

# --- 3c. Recycle Bin ---
Write-Host "[*] Limiting Recycle Bin to $RecycleBinMaxMB MB..." -ForegroundColor Yellow

$globalRecycle = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket"
if (-not (Test-Path $globalRecycle)) { New-Item -Path $globalRecycle -Force | Out-Null }
Set-ItemProperty -Path $globalRecycle -Name "MaxCapacity" -Value $RecycleBinMaxMB -Type DWord
Set-ItemProperty -Path $globalRecycle -Name "NukeOnDelete" -Value 0 -Type DWord

Write-Host "[OK] Recycle Bin limited to $RecycleBinMaxMB MB." -ForegroundColor Green


# ##############################################################################
#  4. DISABLE UNNECESSARY SERVICES
# ##############################################################################

Write-Step "4. DISABLING UNNECESSARY SERVICES"

foreach ($svc in $ServicesToDisable) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.StartType -ne 'Disabled') {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "[OK] Disabled: $($svc.Desc) ($($svc.Name))" -ForegroundColor Green
        } else {
            Write-Host "[SKIP] Already disabled: $($svc.Desc)" -ForegroundColor Gray
        }
    } else {
        Write-Host "[SKIP] Not found: $($svc.Desc) ($($svc.Name))" -ForegroundColor Gray
    }
}

# Consumer Experience, OneDrive, Cortana
$consumerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $consumerPath)) { New-Item -Path $consumerPath -Force | Out-Null }
Set-ItemProperty -Path $consumerPath -Name "DisableWindowsConsumerFeatures"  -Value 1 -Type DWord
Set-ItemProperty -Path $consumerPath -Name "DisableSoftLanding"              -Value 1 -Type DWord
Set-ItemProperty -Path $consumerPath -Name "DisableCloudOptimizedContent"    -Value 1 -Type DWord

$onedrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $onedrivePath)) { New-Item -Path $onedrivePath -Force | Out-Null }
Set-ItemProperty -Path $onedrivePath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord

$cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (-not (Test-Path $cortanaPath)) { New-Item -Path $cortanaPath -Force | Out-Null }
Set-ItemProperty -Path $cortanaPath -Name "AllowCortana" -Value 0 -Type DWord

Write-Host "[OK] Consumer Experience, OneDrive, Cortana disabled." -ForegroundColor Green


# ##############################################################################
#  5. WINDOWS UPDATE
# ##############################################################################

Write-Step "5. WINDOWS UPDATE — CONTROLLED SCHEDULE"

$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }

Set-ItemProperty -Path $wuPath -Name "AUOptions"                      -Value $WindowsUpdateMode -Type DWord
Set-ItemProperty -Path $wuPath -Name "NoAutoRebootWithLoggedOnUsers"  -Value 1 -Type DWord

$wuMainPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (-not (Test-Path $wuMainPath)) { New-Item -Path $wuMainPath -Force | Out-Null }
Set-ItemProperty -Path $wuMainPath -Name "SetActiveHours"   -Value 1                -Type DWord
Set-ItemProperty -Path $wuMainPath -Name "ActiveHoursStart" -Value $ActiveHoursStart -Type DWord
Set-ItemProperty -Path $wuMainPath -Name "ActiveHoursEnd"   -Value $ActiveHoursEnd   -Type DWord

$wuModeDesc = switch ($WindowsUpdateMode) { 2 {"notify before download"} 3 {"download, notify to install"} 4 {"auto install"} }
Write-Host "[OK] Windows Update: $wuModeDesc, no auto-reboot, active hours ${ActiveHoursStart}:00-${ActiveHoursEnd}:00." -ForegroundColor Green


# ##############################################################################
#  6. EVENT LOGS
# ##############################################################################

Write-Step "6. EVENT LOG — INCREASE SIZES"

$logs = @(
    @{ Name = "Application";  MaxSizeMB = $LogSizeApplication }
    @{ Name = "Security";     MaxSizeMB = $LogSizeSecurity }
    @{ Name = "System";       MaxSizeMB = $LogSizeSystem }
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";      MaxSizeMB = $LogSizeRdsLocal }
    @{ Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";  MaxSizeMB = $LogSizeRdsRemote }
)

foreach ($log in $logs) {
    try {
        $maxBytes = $log.MaxSizeMB * 1MB
        wevtutil sl $log.Name /ms:$maxBytes 2>$null
        Write-Host "[OK] $($log.Name): $($log.MaxSizeMB) MB" -ForegroundColor Green
    }
    catch {
        Write-Host "[SKIP] Could not resize: $($log.Name)" -ForegroundColor Gray
    }
}

auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
auditpol /set /subcategory:"Logoff" /success:enable 2>$null
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>$null

Write-Host "[OK] Audit logging enabled (Logon/Logoff/Lockout)." -ForegroundColor Green


# ##############################################################################
#  7. NETWORK OPTIMIZATION
# ##############################################################################

Write-Step "7. NETWORK OPTIMIZATION"

netsh int tcp set global autotuninglevel=normal | Out-Null
netsh int tcp set global rss=enabled | Out-Null
netsh int tcp set global dca=enabled 2>$null

$tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Set-ItemProperty -Path $tcpParams -Name "TcpAckFrequency" -Value 1 -Type DWord
Set-ItemProperty -Path $tcpParams -Name "TCPNoDelay"      -Value 1 -Type DWord

netsh int tcp set global timestamps=disabled | Out-Null

Write-Host "[OK] Network stack optimized (RSS, no Nagle, auto-tuning)." -ForegroundColor Green


# ##############################################################################
#  8. SUMMARY
# ##############################################################################

Write-Step "OPTIMIZATION COMPLETE"

Write-Host ""
Write-Host "  PERFORMANCE:" -ForegroundColor White
Write-Host "    - High Performance power plan, CPU idle disabled" -ForegroundColor Green
Write-Host "    - CPU scheduling for Background Services" -ForegroundColor Green
Write-Host "    - Wallpaper=$RdpAllowWallpaper, FontSmoothing=$RdpFontSmoothing, Camera=$RdpAllowCamera" -ForegroundColor Green
Write-Host "    - RDP UDP transport: $RdpEnableUDP" -ForegroundColor Green
Write-Host "    - AVC444, ImageQuality=$RdpImageQuality, ColorDepth=$RdpColorDepth, Progressive=$RdpProgressiveEncoding" -ForegroundColor Green
Write-Host "    - Memory compression off, large cache on" -ForegroundColor Green
Write-Host "    - Nagle disabled (lower RDP latency)" -ForegroundColor Green
Write-Host ""
Write-Host "  SECURITY:" -ForegroundColor White
Write-Host "    - TLS 1.2 only (SSL3/TLS1.0/1.1 disabled)" -ForegroundColor Green
Write-Host "    - RDP: SSL layer, High encryption" -ForegroundColor Green
Write-Host "    - CredSSP: $credSSPDesc" -ForegroundColor Green
Write-Host "    - Weak ciphers disabled (RC4/DES/NULL/3DES)" -ForegroundColor Green
Write-Host "    - Lockout: $LockoutBadCount attempts / ${lockDurMin}min lock" -ForegroundColor Green
Write-Host ""
Write-Host "  CLEANUP:" -ForegroundColor White
Write-Host "    - Temp cleanup: files > ${TempCleanupDays}d, daily at $TempCleanupTime" -ForegroundColor Green
Write-Host "    - Recycle Bin: max $RecycleBinMaxMB MB" -ForegroundColor Green
Write-Host ""
Write-Host "  WINDOWS UPDATE:" -ForegroundColor White
Write-Host "    - Mode: $wuModeDesc, no auto-reboot" -ForegroundColor Green
Write-Host "    - Active hours: ${ActiveHoursStart}:00 - ${ActiveHoursEnd}:00" -ForegroundColor Green
Write-Host ""
Write-Host "  [!] REBOOT RECOMMENDED to apply all changes." -ForegroundColor Red
Write-Host ""

$reboot = Read-Host "  Reboot now? (Y/N)"
if ($reboot -match '^[Yy]') {
    Write-Host "[*] Rebooting in 10 seconds..." -ForegroundColor Yellow
    shutdown /r /t 10 /c "RDS Optimization applied — rebooting"
} else {
    Write-Host "[INFO] Remember to reboot when convenient." -ForegroundColor Yellow
}
