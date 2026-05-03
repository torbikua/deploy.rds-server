# ═══════════════════════════════════════════════════════════════════════
# Optimize-TerminalServer.ps1   v3.3
# ═══════════════════════════════════════════════════════════════════════
# Optimize Windows Server 2019 for RDS (Remote Desktop Services) role.
# Hybrid: own work + best from torbikua/rds-farm-setup, TL infrastructure.
#
# v3.3 - REMOVED <#...#> comment-help block completely.
#        PowerShell ISE has a bug where UTF-8 BOM files with cyrillic
#        in <#...#> block fail to parse (comment-block not recognized).
#        Single-line # comments work in any encoding without issues.
# v3.2 - UTF-16 LE BOM -> UTF-8 BOM (universal Windows compatibility).
# v3.1 - VM-aware Power Plan (HLT bug fix for virtualized Windows).
# v3.0 - Added -DisableTelemetry (Sophia Script + HushWin best-of).
# v2.1 - 3rd-party AV detection, WSearch COM ProgID fallbacks.
# v2.0 - Hybrid w/ torbik: RDP UDP/codec, Power Plan, Memory tuning,
#        Network TcpNoDelay, Event Log size, Temp Cleanup, Recycle Bin,
#        optional TLS hardening + Account Lockout.
# v1.x - Initial.
#
# USAGE:
#   PowerShell -ExecutionPolicy Bypass -File 2_TerminalServer-Optimize.ps1
#   PowerShell -ExecutionPolicy Bypass -File 2_TerminalServer-Optimize.ps1 -WhatIf
#   PowerShell -ExecutionPolicy Bypass -File 2_TerminalServer-Optimize.ps1 -DisableTelemetry
#
# PARAMETERS:
#   -WhatIf            Dry-run preview without changes
#   -RemoveBloat       Remove Lightshot / Yandex / Mail.ru / Amigo
#   -HardenTLS         Disable TLS 1.0/1.1, RC4/DES/3DES (may break legacy)
#   -EnableLockout     Account lockout policy (5 attempts / 30 min)
#   -EnableAVC         RDP AVC444/H.264 (only with NVIDIA GPU passthrough)
#   -TuneSearch        Tune WSearch indexer (default: ON)
#   -DisableTelemetry  Deep telemetry off (Sophia/HushWin best-of)
#
# REQUIREMENT: run as Administrator.
# ═══════════════════════════════════════════════════════════════════════


[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$RemoveBloat,
    [switch]$HardenTLS,
    [switch]$EnableLockout,
    [switch]$EnableAVC,
    [switch]$TuneSearch = $true,
    [switch]$DisableTelemetry
)

#region init
$ErrorActionPreference = 'Continue'
$TS         = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile    = "C:\OptimizeRDS-$TS.log"
$BackupDir  = "C:\OptimizeRDS-Backup-$TS"
$null = New-Item -ItemType Directory -Path $BackupDir -Force

function Write-Log {
    param([string]$Msg, [ValidateSet('INFO','OK','WARN','ERR','SKIP','STEP')] [string]$Level='INFO')
    $color = @{INFO='White';OK='Green';WARN='Yellow';ERR='Red';SKIP='DarkGray';STEP='Cyan'}[$Level]
    $line  = "[{0}] [{1}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Step {
    param([string]$Title)
    Write-Log "" 'INFO'
    Write-Log "═══ $Title ═══" 'STEP'
}

# Verify admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Запусти PowerShell как Administrator!" -ForegroundColor Red
    exit 1
}

Write-Log "═════════════════════════════════════════════════" 'INFO'
Write-Log "Optimize-TerminalServer v3.1 starting" 'INFO'
Write-Log "Hostname:       $env:COMPUTERNAME" 'INFO'
Write-Log "User:           $env:USERNAME" 'INFO'
Write-Log "WhatIf:         $WhatIfPreference" 'INFO'
Write-Log "RemoveBloat:    $RemoveBloat" 'INFO'
Write-Log "HardenTLS:      $HardenTLS" 'INFO'
Write-Log "EnableLockout:  $EnableLockout" 'INFO'
Write-Log "EnableAVC:      $EnableAVC" 'INFO'
Write-Log "TuneSearch:     $TuneSearch" 'INFO'
Write-Log "DisableTelem.:  $DisableTelemetry" 'INFO'
Write-Log "Log:            $LogFile" 'INFO'
Write-Log "Backup:         $BackupDir" 'INFO'
Write-Log "═════════════════════════════════════════════════" 'INFO'

# Common registry paths
$tsPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
if (-not (Test-Path $tsPath)) { New-Item -Path $tsPath -Force | Out-Null }

# Detect Windows Defender state - if 3rd-party AV (Kaspersky/ESET) is installed,
# WinDefend is stopped/manual, MpPreference cmdlets fail with 0x800106ba.
function Test-DefenderActive {
    $svc = Get-Service WinDefend -EA SilentlyContinue
    if (-not $svc -or $svc.Status -ne 'Running') { return $false }
    try {
        $null = Get-MpPreference -EA Stop
        return $true
    } catch { return $false }
}
$DefenderActive = Test-DefenderActive
if ($DefenderActive) {
    Write-Log "Windows Defender is ACTIVE - exclusions/scan sections will run" 'OK'
} else {
    Write-Log "Windows Defender is NOT active (likely 3rd-party AV installed) - skipping Defender sections" 'WARN'
    $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -EA SilentlyContinue |
          Select -Expand displayName -EA SilentlyContinue
    if ($av) { Write-Log "Detected AV: $($av -join ', ')" 'INFO' }
}
#endregion

#region 1. Reset accumulated WmiPrvSE
Step "[1/20] Reset WmiPrvSE accumulated CPU"
$wmi = Get-Process WmiPrvSE -EA SilentlyContinue
if ($wmi) {
    $totalCpuMin = [math]::Round((($wmi | Measure-Object CPU -Sum).Sum)/60, 1)
    Write-Log "Current WmiPrvSE: $($wmi.Count) instances, accumulated $totalCpuMin min CPU" 'INFO'
    if ($PSCmdlet.ShouldProcess("WmiPrvSE", "Stop-Process")) {
        $wmi | Stop-Process -Force -EA SilentlyContinue
        Start-Sleep 2
        Write-Log "WmiPrvSE killed (auto-restart on next WMI request)" 'OK'
    }
} else {
    Write-Log "No WmiPrvSE running" 'SKIP'
}
#endregion

#region 2. Restart Zabbix Agent
Step "[2/20] Restart Zabbix Agent (apply new intervals)"
$zbx = Get-Service "Zabbix Agent*" -EA SilentlyContinue
if ($zbx) {
    foreach ($svc in $zbx) {
        if ($PSCmdlet.ShouldProcess($svc.Name, "Restart")) {
            try {
                Restart-Service -Name $svc.Name -Force -EA Stop
                Write-Log "Restarted: $($svc.Name) -> $((Get-Service $svc.Name).Status)" 'OK'
            } catch {
                Write-Log "Failed to restart $($svc.Name): $_" 'ERR'
            }
        }
    }
} else {
    Write-Log "No Zabbix Agent service found" 'SKIP'
}
#endregion

#region 3. Power Plan + CPU idle + USB suspend
Step "[3/20] Power Plan (VM-aware: Balanced for VM, High Performance for bare-metal)"
# CRITICAL: на virtualized Windows госте 'High Performance' + 'CPU idle disabled' приводит к 100% CPU
# на хосте — vCPU thread не выполняет HLT, qemu бесконечно крутится.
# Microsoft рекомендует Balanced для всех VM. High Performance ТОЛЬКО bare-metal.
$isVM = $false
try {
    $sys  = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue
    if ($sys.Manufacturer -match 'QEMU|VMware|innotek|Microsoft Corporation|Xen|Bochs|Red Hat' -or
        $sys.Model        -match 'Virtual|VMware|HVM|KVM' -or
        $bios.SerialNumber -match 'VMware|0$') {
        $isVM = $true
    }
} catch {}
Write-Log ("Virtualized: $isVM ({0})" -f $(if($isVM){'Balanced + idle ON'} else {'High Performance + idle OFF'})) 'INFO'

if ($PSCmdlet.ShouldProcess("Power", "Set scheme")) {
    try {
        if ($isVM) {
            # VM: Balanced + явно IDLEDISABLE=0 (allow HLT -> qemu освобождает host CPU)
            powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e | Out-Null
            powercfg -setacvalueindex scheme_current sub_processor IDLEDISABLE 0 2>$null
            powercfg -setactive scheme_current | Out-Null
            Write-Log "Balanced power plan + CPU idle ENABLED (HLT works -> host CPU correct)" 'OK'
        } else {
            $highPerf = powercfg -list | Select-String "High performance|Высокая производительность"
            if ($highPerf -match "([0-9a-f\-]{36})") {
                powercfg -setactive $Matches[1] | Out-Null
                Write-Log "Activated High Performance plan: $($Matches[1])" 'OK'
            } else {
                powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
                $highPerf = powercfg -list | Select-String "High performance|Высокая производительность"
                if ($highPerf -match "([0-9a-f\-]{36})") {
                    powercfg -setactive $Matches[1] | Out-Null
                    Write-Log "Created and activated High Performance plan" 'OK'
                }
            }
            powercfg -setacvalueindex scheme_current sub_processor IDLEDISABLE 1 2>$null
            powercfg -setactive scheme_current | Out-Null
            Write-Log "Bare-metal: CPU idle states disabled (no C-state throttling)" 'OK'
        }
        # USB selective suspend OFF в обоих случаях
        powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        powercfg -setactive scheme_current | Out-Null
    } catch {
        Write-Log "Power tuning error: $_" 'WARN'
    }
}
#endregion

#region 4. Win32PrioritySeparation = 38 (foreground apps)
Step "[4/20] Win32PrioritySeparation = 38 (foreground priority)"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
$current = (Get-ItemProperty -Path $regPath -Name "Win32PrioritySeparation" -EA SilentlyContinue).Win32PrioritySeparation
try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "$BackupDir\PriorityControl-before.reg" /y 2>&1 | Out-Null
} catch {}
if ($current -eq 38) {
    Write-Log "Already set to 38, skipping" 'SKIP'
} else {
    if ($PSCmdlet.ShouldProcess("Win32PrioritySeparation", "Set 38")) {
        try {
            Set-ItemProperty -Path $regPath -Name "Win32PrioritySeparation" -Value 38 -Type DWORD -Force
            Write-Log "Win32PrioritySeparation: $current -> 38 (effective after reboot)" 'OK'
        } catch {
            Write-Log "Failed: $_" 'ERR'
        }
    }
}
#endregion

#region 5. Memory tuning
Step "[5/20] Memory: LargeSystemCache + Disable Memory Compression"
if ($PSCmdlet.ShouldProcess("Memory", "Tuning")) {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
            -Name "LargeSystemCache" -Value 1 -Type DWord -Force
        Write-Log "LargeSystemCache=1 (favor file system cache)" 'OK'
    } catch {
        Write-Log "LargeSystemCache failed: $_" 'WARN'
    }
    try {
        $mmagent = Get-MMAgent -EA SilentlyContinue
        if ($mmagent.MemoryCompression) {
            Disable-MMAgent -mc -EA Stop
            Write-Log "Memory Compression disabled (effective after reboot)" 'OK'
        } else {
            Write-Log "Memory Compression already disabled" 'SKIP'
        }
    } catch {
        Write-Log "Cannot manage MMAgent: $_" 'WARN'
    }
}
#endregion

#region 6. SysMain disable
Step "[6/20] Disable SysMain (Superfetch)"
$sysmain = Get-Service SysMain -EA SilentlyContinue
if ($sysmain -and $sysmain.StartType -ne 'Disabled') {
    if ($PSCmdlet.ShouldProcess("SysMain", "Stop and Disable")) {
        try {
            Stop-Service SysMain -Force -EA SilentlyContinue
            Set-Service SysMain -StartupType Disabled -EA Stop
            Write-Log "SysMain stopped and disabled" 'OK'
        } catch {
            Write-Log "SysMain disable failed: $_" 'ERR'
        }
    }
} else {
    Write-Log "SysMain already disabled or not present" 'SKIP'
}
#endregion

#region 7. Disable unnecessary services (NOT WSearch!)
Step "[7/20] Disable unnecessary services"
# WSearch INTENTIONALLY NOT IN LIST - users actively use Explorer/Outlook search
$ServicesToDisable = @(
    @{ Name = "XblAuthManager";     Desc = "Xbox Live Auth Manager" },
    @{ Name = "XblGameSave";        Desc = "Xbox Live Game Save" },
    @{ Name = "XboxGipSvc";         Desc = "Xbox Accessory Management" },
    @{ Name = "XboxNetApiSvc";      Desc = "Xbox Live Networking" },
    @{ Name = "DiagTrack";          Desc = "Connected User Experiences (Telemetry)" },
    @{ Name = "dmwappushservice";   Desc = "WAP Push Message Routing" },
    @{ Name = "MapsBroker";         Desc = "Downloaded Maps Manager" },
    @{ Name = "lfsvc";              Desc = "Geolocation Service" },
    @{ Name = "RetailDemo";         Desc = "Retail Demo Service" },
    @{ Name = "wisvc";              Desc = "Windows Insider Service" },
    @{ Name = "Fax";                Desc = "Fax Service" },
    @{ Name = "TabletInputService"; Desc = "Tablet PC Input Service" },
    @{ Name = "WerSvc";             Desc = "Windows Error Reporting" }
)
foreach ($svc in $ServicesToDisable) {
    $service = Get-Service -Name $svc.Name -EA SilentlyContinue
    if (-not $service) {
        Write-Log "Not present: $($svc.Name)" 'SKIP'
        continue
    }
    if ($service.StartType -eq 'Disabled') {
        Write-Log "Already disabled: $($svc.Name)" 'SKIP'
        continue
    }
    if ($PSCmdlet.ShouldProcess($svc.Name, "Stop and Disable")) {
        try {
            Stop-Service -Name $svc.Name -Force -EA SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -EA Stop
            Write-Log "Disabled: $($svc.Desc) ($($svc.Name))" 'OK'
        } catch {
            Write-Log "Failed $($svc.Name): $_" 'WARN'
        }
    }
}
#endregion

#region 8. Disable Telemetry / CEIP scheduled tasks
Step "[8/20] Disable Telemetry / CEIP scheduled tasks"
$tasksToDisable = @(
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="Consolidator"},
    @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="UsbCeip"},
    @{Path="\Microsoft\Windows\Application Experience\"; Name="Microsoft Compatibility Appraiser"},
    @{Path="\Microsoft\Windows\Application Experience\"; Name="ProgramDataUpdater"},
    @{Path="\Microsoft\Windows\Autochk\"; Name="Proxy"},
    @{Path="\Microsoft\Windows\DiskDiagnostic\"; Name="Microsoft-Windows-DiskDiagnosticDataCollector"}
)
foreach ($t in $tasksToDisable) {
    $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA SilentlyContinue
    if (-not $task) {
        Write-Log "Not present: $($t.Name)" 'SKIP'
        continue
    }
    if ($task.State -eq 'Disabled') {
        Write-Log "Already disabled: $($t.Name)" 'SKIP'
        continue
    }
    if ($PSCmdlet.ShouldProcess($t.Name, "Disable")) {
        try {
            Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA Stop | Out-Null
            Write-Log "Disabled task: $($t.Name)" 'OK'
        } catch {
            Write-Log "Cannot disable $($t.Name): $_" 'WARN'
        }
    }
}
#endregion

#region 9. Defender exclusions
Step "[9/20] Defender exclusions for 1C / Adobe / Excel / TEMP"
if (-not $DefenderActive) {
    Write-Log "Defender not active - skipping exclusions (configure them in your 3rd-party AV instead)" 'SKIP'
} else {
try {
    Get-MpPreference | Select ExclusionPath, ExclusionProcess, ExclusionExtension |
        Export-Clixml -Path "$BackupDir\MpPreference-before.xml"
    Write-Log "Defender backup: $BackupDir\MpPreference-before.xml" 'OK'
} catch {
    Write-Log "Cannot backup MpPreference: $_" 'WARN'
}
$exclExt = @(
    "1cd","dt","cdx","cf","cfu","cfl","epf","mxl","ert","grs","st","md","mft",
    "psd","psb","psp","ai","tmp",
    "xlsb","xlsx","xlsm","xls"
)
$exclProc = @(
    "1cv8.exe","1cv8c.exe","ragent.exe","rmngr.exe","rphost.exe",
    "Photoshop.exe","Illustrator.exe","AcroRd32.exe","Acrobat.exe",
    "EXCEL.EXE","WINWORD.EXE","OUTLOOK.EXE","POWERPNT.EXE"
)
$exclPath = @(
    "C:\Users\*\AppData\Local\1C",
    "C:\Users\*\AppData\Roaming\1C",
    "C:\Users\*\AppData\Local\Adobe",
    "C:\Users\*\AppData\Roaming\Adobe",
    "C:\Users\*\AppData\Local\Microsoft\Office",
    "C:\Users\*\AppData\Local\Temp",
    "C:\Users\*\AppData\Roaming\Microsoft\Excel",
    "C:\Windows\Temp",
    "C:\ProgramData\Temp"
)
if ($PSCmdlet.ShouldProcess("Defender", "Add exclusions")) {
    try {
        Add-MpPreference -ExclusionExtension $exclExt -EA Stop
        Add-MpPreference -ExclusionProcess  $exclProc -EA Stop
        Add-MpPreference -ExclusionPath     $exclPath -EA Stop
        $cur = Get-MpPreference
        Write-Log "Defender exclusions: $($cur.ExclusionExtension.Count) ext / $($cur.ExclusionProcess.Count) proc / $($cur.ExclusionPath.Count) paths" 'OK'
    } catch {
        Write-Log "Add-MpPreference failed: $_" 'ERR'
    }
}
}  # end if $DefenderActive
#endregion

#region 10. Defender QuickScan + Schedule weekly FullScan
Step "[10/20] Defender: QuickScan now + weekly FullScan task"
if (-not $DefenderActive) {
    Write-Log "Defender not active - skipping QuickScan + FullScan task" 'SKIP'
} elseif ($PSCmdlet.ShouldProcess("Defender", "QuickScan + FullScan task")) {
    try {
        Start-MpScan -ScanType QuickScan -AsJob | Out-Null
        Write-Log "QuickScan started (background)" 'OK'
    } catch {
        Write-Log "QuickScan failed: $_" 'WARN'
    }
    $taskName = "Defender Weekly FullScan"
    $existing = Get-ScheduledTask -TaskName $taskName -EA SilentlyContinue
    if ($existing) {
        Write-Log "Task '$taskName' already exists" 'SKIP'
    } else {
        try {
            $action  = New-ScheduledTaskAction -Execute "PowerShell" -Argument '-NoProfile -WindowStyle Hidden -Command "Start-MpScan -ScanType FullScan"'
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 02:00
            $set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $set -User "SYSTEM" -RunLevel Highest -Force | Out-Null
            Write-Log "Created: '$taskName' (Sunday 02:00)" 'OK'
        } catch {
            Write-Log "Cannot create task: $_" 'ERR'
        }
    }
}
#endregion

#region 11. WSearch tune (NOT disable)
Step "[11/20] Windows Search tune (exclude trash folders, KEEP enabled)"
Write-Log "Users actively use Explorer + Outlook search - WSearch stays ENABLED" 'INFO'
Write-Log "Thunderbird uses Gloda (its own indexer) - not affected" 'INFO'

$wsearch = Get-Service WSearch -EA SilentlyContinue
if ($wsearch) {
    if ($wsearch.StartType -eq 'Disabled') {
        Write-Log "WSearch was Disabled - re-enabling Automatic Delayed Start" 'WARN'
        if ($PSCmdlet.ShouldProcess("WSearch", "Enable")) {
            Set-Service WSearch -StartupType AutomaticDelayedStart
            Start-Service WSearch -EA SilentlyContinue
        }
    } elseif ($wsearch.Status -ne 'Running') {
        Write-Log "WSearch not running - starting" 'WARN'
        if ($PSCmdlet.ShouldProcess("WSearch", "Start")) {
            Start-Service WSearch -EA SilentlyContinue
        }
    } else {
        Write-Log "WSearch running ($($wsearch.StartType))" 'OK'
    }
}
if ($TuneSearch) {
    try {
        reg export "HKLM\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager" "$BackupDir\WSearch-CrawlScope-before.reg" /y 2>&1 | Out-Null
    } catch {}
    # Try multiple ProgIDs - SearchManager may be exposed under different names
    # depending on Windows Search version installed.
    $sm = $null
    foreach ($progId in @("Microsoft.SearchManager","Microsoft.Search.Administration.SearchManager","Search.SearchManager","Microsoft.Search.SearchManager")) {
        try {
            $sm = New-Object -ComObject $progId -EA Stop
            Write-Log "WSearch COM connected via ProgID: $progId" 'OK'
            break
        } catch { continue }
    }
    if (-not $sm) {
        Write-Log "WSearch COM not available - SearchManager not registered (often case on WS2019 core/minimal)" 'WARN'
        Write-Log "FALLBACK: Control Panel -> Indexing Options -> Modify -> uncheck folders manually" 'INFO'
        Write-Log "Or run: control srchadmin.dll" 'INFO'
    } else {
    try {
        $cat = $sm.GetCatalog("SystemIndex")
        $csm = $cat.GetCrawlScopeManager()
        # AddDefaultScopeRule(URL, IncludeSubdirs=$false, FollowFlags=0=exclude)
        $excludeUrls = @(
            "file:///C:\Windows\Temp\",
            "file:///C:\ProgramData\Temp\",
            "file:///C:\Users\*\AppData\Local\Temp\",
            "file:///C:\Users\*\AppData\Local\Adobe\",
            "file:///C:\Users\*\AppData\Roaming\Adobe\Photoshop*\",
            "file:///C:\Users\*\AppData\Local\1C\",
            "file:///C:\Users\*\AppData\Roaming\1C\",
            "file:///C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\",
            "file:///C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\",
            "file:///C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cache\",
            "file:///C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cache\"
        )
        $added = 0
        foreach ($u in $excludeUrls) {
            if ($PSCmdlet.ShouldProcess($u, "Exclude from index")) {
                try {
                    $csm.AddDefaultScopeRule($u, $false, 0) | Out-Null
                    $added++
                } catch {
                    Write-Log "Cannot exclude $u : $($_.Exception.Message)" 'WARN'
                }
            }
        }
        if ($added -gt 0) {
            $csm.SaveAll() | Out-Null
            Write-Log "Excluded $added folders from WSearch index" 'OK'
        }
    } catch {
        Write-Log "WSearch COM tune failed: $_" 'ERR'
        Write-Log "FALLBACK: control srchadmin.dll -> Modify -> uncheck folders manually" 'WARN'
    }
    }  # end else (sm available)
}
#endregion

#region 12. RDP UDP transport
Step "[12/20] RDP UDP transport ON"
if ($PSCmdlet.ShouldProcess("RDP", "Enable UDP transport")) {
    try {
        Set-ItemProperty -Path $tsPath -Name "fDisableUDPTransport" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "SelectTransport"      -Value 0 -Type DWord -Force
        # Firewall rule for UDP on RDP port
        $rdpPort = (Get-ItemProperty -Path $rdpTcpPath -Name "PortNumber" -EA SilentlyContinue).PortNumber
        if (-not $rdpPort) { $rdpPort = 3389 }
        $existingUDP = Get-NetFirewallRule -DisplayName "RDP-Custom-UDP-$rdpPort" -EA SilentlyContinue
        if (-not $existingUDP) {
            New-NetFirewallRule -DisplayName "RDP-Custom-UDP-$rdpPort" `
                -Direction Inbound -Protocol UDP -LocalPort $rdpPort `
                -Action Allow -Profile Any -Enabled True | Out-Null
            Write-Log "Firewall rule for UDP $rdpPort created" 'OK'
        } else {
            Write-Log "UDP firewall rule already present" 'SKIP'
        }
        Write-Log "RDP UDP transport enabled (port $rdpPort)" 'OK'
    } catch {
        Write-Log "RDP UDP setup failed: $_" 'ERR'
    }
}
#endregion

#region 13. RDP visual / codec settings (NO AVC by default!)
Step "[13/20] RDP visual + classic codec (NO AVC = no software CPU encoding)"
if ($PSCmdlet.ShouldProcess("RDP", "Visual settings")) {
    try {
        # Wallpaper OFF (saves bandwidth + encoding CPU)
        Set-ItemProperty -Path $tsPath -Name "fNoRemoteDesktopWallpaper" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "fDisableWallpaper"          -Value 1 -Type DWord -Force
        # Font smoothing ON (ClearType - tiny CPU, big readability)
        Set-ItemProperty -Path $tsPath -Name "fEnableSmoothing"           -Value 1 -Type DWord -Force
        # Camera redirect ON (default - users can use)
        Set-ItemProperty -Path $tsPath -Name "fDisableCam"                -Value 0 -Type DWord -Force
        # RemoteFX adaptive UI (lightweight, helps)
        Set-ItemProperty -Path $tsPath -Name "bEnhancedRemoteFXUI"        -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "fEnableVirtualizedGraphics" -Value 1 -Type DWord -Force
        # CRITICAL: AVC OFF (no GPU on host = software encoding = CPU killer)
        if (-not $EnableAVC) {
            Set-ItemProperty -Path $tsPath -Name "AVCHardwareEncodePreferred" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $tsPath -Name "AVC444ModePreferred"        -Value 0 -Type DWord -Force
            Write-Log "AVC444/H.264 DISABLED (use -EnableAVC only with NVIDIA/Intel GPU)" 'OK'
        }
        # Color depth 24-bit (4 = 24bit, 5 = 32bit). 24 enough for office, less bandwidth
        Set-ItemProperty -Path $rdpTcpPath -Name "ColorDepth"       -Value 4 -Type DWord -Force
        Set-ItemProperty -Path $rdpTcpPath -Name "ColorDepthPolicy" -Value 1 -Type DWord -Force
        # Compression on
        Set-ItemProperty -Path $rdpTcpPath -Name "CompressRDP" -Value 1 -Type DWord -Force
        # Keep-alive (faster dead-session detection)
        Set-ItemProperty -Path $tsPath -Name "KeepAliveInterval" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "KeepAliveEnable"   -Value 1 -Type DWord -Force
        # Visual quality (1 = low, 2 = medium, 3 = high). 2 = balance
        Set-ItemProperty -Path $tsPath -Name "ImageQuality"          -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "GraphicsProfile"       -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $tsPath -Name "VisualChannelPriority" -Value 1 -Type DWord -Force
        # Progressive encoding OFF (no pixelation - sharp from first frame, more bandwidth)
        Set-ItemProperty -Path $tsPath -Name "bProgressiveEncoding" -Value 0 -Type DWord -Force
        # Disable window animations only (keep render quality)
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DWM" -Name "DisallowAnimations" -Value 1 -Type DWord -Force
        Write-Log "RDP visual: wallpaper OFF, ClearType ON, ColorDepth 24-bit, animations OFF, AVC=$EnableAVC" 'OK'
    } catch {
        Write-Log "RDP visual setup failed: $_" 'ERR'
    }
}
#endregion

#region 14. RDP AVC enable (only with -EnableAVC and GPU detected)
Step "[14/20] RDP AVC enable (only if GPU available)"
if ($EnableAVC) {
    # Detect GPU
    $gpus = Get-WmiObject Win32_VideoController -EA SilentlyContinue | Where {$_.AdapterRAM -gt 100MB}
    $hasRealGPU = $gpus | Where {$_.Name -notmatch 'Basic|Microsoft Basic|VGA'}
    if ($hasRealGPU) {
        Write-Log "GPU detected: $($hasRealGPU.Name -join ', ')" 'OK'
        if ($PSCmdlet.ShouldProcess("RDP", "Enable AVC444/H.264")) {
            Set-ItemProperty -Path $tsPath -Name "AVCHardwareEncodePreferred" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $tsPath -Name "AVC444ModePreferred"        -Value 1 -Type DWord -Force
            Write-Log "AVC444/H.264 ENABLED with hardware encoding" 'OK'
        }
    } else {
        Write-Log "WARN: -EnableAVC specified but NO real GPU detected (only Basic Display Adapter)!" 'ERR'
        Write-Log "WARN: AVC software encoding on CPU = catastrophic for 30+ RDP sessions. SKIPPING." 'ERR'
        Write-Log "WARN: Add NVIDIA GPU passthrough to enable AVC properly." 'WARN'
    }
} else {
    Write-Log "AVC remains OFF (use -EnableAVC only with hardware GPU)" 'SKIP'
}
#endregion

#region 15. Network: TcpNoDelay, RSS, autotuning
Step "[15/20] Network: TcpNoDelay (no Nagle), RSS, autotuning normal"
if ($PSCmdlet.ShouldProcess("Network", "TCP tuning")) {
    try {
        netsh int tcp set global autotuninglevel=normal | Out-Null
        Write-Log "TCP autotuning: normal" 'OK'
    } catch { Write-Log "autotuning failed: $_" 'WARN' }
    try {
        netsh int tcp set global rss=enabled | Out-Null
        Write-Log "RSS: enabled (parallel network processing)" 'OK'
    } catch {}
    try {
        netsh int tcp set global dca=enabled 2>$null | Out-Null
        Write-Log "DCA: enabled (cache-friendly NIC processing)" 'OK'
    } catch {}
    # Disable Nagle for interactive RDP responsiveness
    try {
        $tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Set-ItemProperty -Path $tcpParams -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $tcpParams -Name "TCPNoDelay"      -Value 1 -Type DWord -Force
        Write-Log "TcpNoDelay + TcpAckFrequency=1 (Nagle off, RDP latency lower)" 'OK'
    } catch { Write-Log "Nagle off failed: $_" 'WARN' }
    # Note: NOT disabling timestamps (keeping RFC 1323 for proper RTT measurement)
}
#endregion

#region 16. Event log size increase
Step "[16/20] Event Log size increase"
$logs = @(
    @{ Name = "Application"; SizeMB = 128 },
    @{ Name = "Security"; SizeMB = 256 },
    @{ Name = "System"; SizeMB = 128 },
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; SizeMB = 64 },
    @{ Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; SizeMB = 64 }
)
foreach ($log in $logs) {
    if ($PSCmdlet.ShouldProcess($log.Name, "Resize to $($log.SizeMB)MB")) {
        try {
            $bytes = $log.SizeMB * 1MB
            wevtutil sl $log.Name /ms:$bytes 2>$null
            Write-Log "$($log.Name): $($log.SizeMB) MB" 'OK'
        } catch {
            Write-Log "Cannot resize $($log.Name)" 'SKIP'
        }
    }
}
#endregion

#region 17. Temp cleanup scheduled task
Step "[17/20] Temp cleanup scheduled task (daily 03:00, files > 7 days)"
$cleanupPath = "$env:ProgramData\Scripts\Cleanup-TempFiles.ps1"
$cleanupScript = @'
# Auto-generated by Optimize-TerminalServer.ps1
# Cleanup temp files older than 7 days
$maxAge = (Get-Date).AddDays(-7)
$folders = @(
    "$env:SystemRoot\Temp",
    "$env:SystemRoot\Logs\CBS"
)
Get-ChildItem "C:\Users\*\AppData\Local\Temp" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $folders += $_.FullName
}
foreach ($folder in $folders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -lt $maxAge } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}
# Windows Update cache
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue
'@
if ($PSCmdlet.ShouldProcess("TempCleanup", "Create scheduled task")) {
    $scriptsDir = Split-Path $cleanupPath
    if (-not (Test-Path $scriptsDir)) { New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null }
    $cleanupScript | Set-Content -Path $cleanupPath -Encoding UTF8
    Write-Log "Cleanup script: $cleanupPath" 'OK'
    try {
        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupPath`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Unregister-ScheduledTask -TaskName "RDS-TempCleanup" -Confirm:$false -EA SilentlyContinue
        Register-ScheduledTask -TaskName "RDS-TempCleanup" -Action $action -Trigger $trigger -Principal $principal `
            -Description "Clean temp files older than 7 days (RDS optimization)" | Out-Null
        Write-Log "Scheduled 'RDS-TempCleanup' daily at 03:00" 'OK'
    } catch {
        Write-Log "Schedule task failed: $_" 'ERR'
    }
}
#endregion

#region 18. Recycle Bin limit
Step "[18/20] Recycle Bin limit 512 MB"
$globalRecycle = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket"
if ($PSCmdlet.ShouldProcess("RecycleBin", "Limit 512MB")) {
    try {
        if (-not (Test-Path $globalRecycle)) { New-Item -Path $globalRecycle -Force | Out-Null }
        Set-ItemProperty -Path $globalRecycle -Name "MaxCapacity"  -Value 512 -Type DWord -Force
        Set-ItemProperty -Path $globalRecycle -Name "NukeOnDelete" -Value 0   -Type DWord -Force
        Write-Log "Recycle Bin limited to 512 MB per drive" 'OK'
    } catch {
        Write-Log "RecycleBin failed: $_" 'WARN'
    }
}
#endregion

#region 19. (Optional) TLS hardening
Step "[19/20] TLS hardening (disable TLS 1.0/1.1 + weak ciphers)"
if ($HardenTLS) {
    Write-Log "WARN: This may break legacy clients (old printers, old 1C, old apps)" 'WARN'
    if ($PSCmdlet.ShouldProcess("TLS", "Harden")) {
        # Backup
        try {
            reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" "$BackupDir\SCHANNEL-before.reg" /y 2>&1 | Out-Null
        } catch {}
        $protocols = @("SSL 3.0","TLS 1.0","TLS 1.1")
        foreach ($p in $protocols) {
            foreach ($side in @("Server","Client")) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\$side"
                try {
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name "Enabled"           -Value 0 -Type DWord -Force
                    Set-ItemProperty -Path $regPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force
                } catch {}
            }
            Write-Log "Disabled: $p" 'OK'
        }
        # Force enable TLS 1.2
        foreach ($side in @("Server","Client")) {
            $tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$side"
            if (-not (Test-Path $tls12Path)) { New-Item -Path $tls12Path -Force | Out-Null }
            Set-ItemProperty -Path $tls12Path -Name "Enabled"           -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $tls12Path -Name "DisabledByDefault" -Value 0 -Type DWord -Force
        }
        Write-Log "TLS 1.2 explicitly enabled" 'OK'
        # Disable weak ciphers
        $weakCiphers = @("RC4 128/128","RC4 56/128","RC4 40/128","RC4 64/128","DES 56/56","NULL","Triple DES 168")
        foreach ($cipher in $weakCiphers) {
            $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
            try {
                if (-not (Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
                Set-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -Type DWord -Force
            } catch {}
        }
        Write-Log "Weak ciphers disabled (RC4/DES/NULL/3DES)" 'OK'
        # RDP encryption layer
        Set-ItemProperty -Path $rdpTcpPath -Name "SecurityLayer"      -Value 2 -Type DWord -Force
        Set-ItemProperty -Path $rdpTcpPath -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force
        Write-Log "RDP: SSL/TLS layer + High encryption" 'OK'
    }
} else {
    Write-Log "TLS hardening skipped (use -HardenTLS to enable)" 'SKIP'
}
#endregion

#region 20. (Optional) Account Lockout Policy
Step "[20/20] Account Lockout policy"
if ($EnableLockout) {
    Write-Log "WARN: lockout may affect users who mistype passwords - monitor Event 4740" 'WARN'
    if ($PSCmdlet.ShouldProcess("Account Lockout", "5 attempts / 30min lock / 15min reset")) {
        $secpolFile = "$env:TEMP\secpol_export.cfg"
        $secpolMod  = "$env:TEMP\secpol_modified.cfg"
        try {
            Copy-Item $secpolFile "$BackupDir\secpol-before.cfg" -EA SilentlyContinue
            secedit /export /cfg $secpolFile /quiet
            $sec = Get-Content $secpolFile
            $sec = $sec -replace "LockoutBadCount\s*=\s*\d+",   "LockoutBadCount = 5"
            $sec = $sec -replace "ResetLockoutCount\s*=\s*\d+", "ResetLockoutCount = 900"
            $sec = $sec -replace "LockoutDuration\s*=\s*\d+",   "LockoutDuration = 1800"
            if ($sec -notmatch "LockoutBadCount") {
                $sec = $sec -replace "(\[System Access\])", "`$1`r`nLockoutBadCount = 5"
            }
            if ($sec -notmatch "ResetLockoutCount") {
                $sec = $sec -replace "(\[System Access\])", "`$1`r`nResetLockoutCount = 900"
            }
            if ($sec -notmatch "LockoutDuration") {
                $sec = $sec -replace "(\[System Access\])", "`$1`r`nLockoutDuration = 1800"
            }
            $sec | Set-Content $secpolMod -Encoding Unicode
            secedit /configure /db secedit.sdb /cfg $secpolMod /quiet
            Remove-Item $secpolFile, $secpolMod -Force -EA SilentlyContinue
            Write-Log "Lockout: 5 attempts / 30min lock / 15min counter reset" 'OK'
            Write-Log "Audit Logon/Logoff/Lockout events:" 'INFO'
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null | Out-Null
            auditpol /set /subcategory:"Logoff" /success:enable 2>$null | Out-Null
            auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>$null | Out-Null
            Write-Log "Audit policies enabled" 'OK'
        } catch {
            Write-Log "Lockout policy failed: $_" 'ERR'
        }
    }
} else {
    Write-Log "Account Lockout skipped (use -EnableLockout to enable)" 'SKIP'
}
#endregion

#region 21. (Optional) Bloat removal
if ($RemoveBloat) {
    Step "[+] Bloat removal"
    $patterns = @("*Lightshot*","*Yandex*","*Mail.ru*","*Amigo*","*Browser_assistant*","*Speedupmypc*","*WinZip Driver*")
    foreach ($pat in $patterns) {
        $pkg = Get-Package -Name $pat -EA SilentlyContinue
        if ($pkg) {
            foreach ($p in $pkg) {
                if ($PSCmdlet.ShouldProcess($p.Name, "Uninstall")) {
                    try {
                        $p | Uninstall-Package -Force -EA Stop | Out-Null
                        Write-Log "Removed: $($p.Name)" 'OK'
                    } catch {
                        Write-Log "Cannot remove $($p.Name): $_" 'WARN'
                    }
                }
            }
        }
    }
    $procs = Get-Process browser_assistant -EA SilentlyContinue
    if ($procs) {
        Write-Log "browser_assistant still running ($($procs.Count) instances)" 'WARN'
        $procs | Select Id, Path, Company | Format-Table | Out-String | ForEach-Object { Write-Log $_ 'INFO' }
    }
}
#endregion

#region 22. (Optional) Deep Telemetry Disable
if ($DisableTelemetry) {
    Step "[+] Deep Telemetry Disable (Sophia/HushWin best-of, RDS-safe)"

    # 22a. Extra services beyond region 7 (DiagTrack already there)
    Write-Log "--- 22a: telemetry services" 'INFO'
    $tlmServices = @(
        @{ Name='dmwappushservice';                       Desc='WAP Push Routing' },
        @{ Name='diagnosticshub.standardcollector.service'; Desc='Diagnostics Hub Standard Collector' }
    )
    foreach ($s in $tlmServices) {
        $svc = Get-Service -Name $s.Name -EA SilentlyContinue
        if (-not $svc) { Write-Log "Not present: $($s.Name)" 'SKIP'; continue }
        if ($svc.StartType -eq 'Disabled') { Write-Log "Already disabled: $($s.Name)" 'SKIP'; continue }
        if ($PSCmdlet.ShouldProcess($s.Name, "Stop+Disable")) {
            try {
                Stop-Service -Name $s.Name -Force -EA SilentlyContinue
                Set-Service -Name $s.Name -StartupType Disabled -EA Stop
                Write-Log "Disabled: $($s.Desc) ($($s.Name))" 'OK'
            } catch { Write-Log "Cannot disable $($s.Name): $_" 'WARN' }
        }
    }

    # 22b. ETW AutoLoggers (kill at boot)
    Write-Log "--- 22b: ETW AutoLoggers" 'INFO'
    $autoLoggers = @('DiagLog','AutoLogger-Diagtrack-Listener','SQMLogger')
    foreach ($al in $autoLoggers) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$al"
        if (-not (Test-Path $regPath)) { Write-Log "AutoLogger not present: $al" 'SKIP'; continue }
        if ($PSCmdlet.ShouldProcess($al, "Set Start=0 in registry")) {
            try {
                Set-ItemProperty -Path $regPath -Name "Start" -Value 0 -Type DWord -Force
                Write-Log "AutoLogger '$al' Start=0 (will not start at boot)" 'OK'
            } catch { Write-Log "Cannot set Start=0 for $al: $_" 'WARN' }
        }
    }
    foreach ($al in @('DiagLog','AutoLogger-Diagtrack-Listener')) {
        try {
            Update-AutologgerConfig -Name $al -Start 0 -EA Stop | Out-Null
            Write-Log "Update-AutologgerConfig $al -Start 0 OK" 'OK'
        } catch { Write-Log "Update-AutologgerConfig $al failed: $_" 'SKIP' }
    }

    # 22c. Extra scheduled tasks beyond region 8
    Write-Log "--- 22c: extra scheduled telemetry tasks" 'INFO'
    $tlmTasks = @(
        @{Path="\Microsoft\Windows\Application Experience\";          Name="AITAgent"},
        @{Path="\Microsoft\Windows\Customer Experience Improvement Program\"; Name="KernelCeipTask"},
        @{Path="\Microsoft\Windows\Maps\";                            Name="MapsToastTask"},
        @{Path="\Microsoft\Windows\Maps\";                            Name="MapsUpdateTask"},
        @{Path="\Microsoft\Windows\Maintenance\";                     Name="WinSAT"},
        @{Path="\Microsoft\Windows\Windows Error Reporting\";         Name="QueueReporting"},
        @{Path="\Microsoft\Windows\Shell\";                           Name="FamilySafetyMonitor"},
        @{Path="\Microsoft\Windows\Shell\";                           Name="FamilySafetyRefreshTask"},
        @{Path="\Microsoft\XblGameSave\";                             Name="XblGameSaveTask"},
        @{Path="\Microsoft\Windows\Setup\";                           Name="FODCleanupTask"},
        @{Path="\Microsoft\Windows\Feedback\Siuf\";                   Name="DmClient"},
        @{Path="\Microsoft\Windows\Feedback\Siuf\";                   Name="DmClientOnScenarioDownload"}
    )
    foreach ($t in $tlmTasks) {
        $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA SilentlyContinue
        if (-not $task) { Write-Log "Task not present: $($t.Name)" 'SKIP'; continue }
        if ($task.State -eq 'Disabled') { Write-Log "Already disabled: $($t.Name)" 'SKIP'; continue }
        if ($PSCmdlet.ShouldProcess($t.Name, "Disable scheduled task")) {
            try {
                Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA Stop | Out-Null
                Write-Log "Disabled task: $($t.Name)" 'OK'
            } catch { Write-Log "Cannot disable $($t.Name): $_" 'WARN' }
        }
    }

    # 22d. HKLM Policies (Group-Policy style)
    Write-Log "--- 22d: HKLM Policies registry" 'INFO'
    $regChanges = @(
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection";              Name="AllowTelemetry";    Value=0},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry";  Value=0},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo";       Name="Enabled";           Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat";                   Name="AITEnable";         Value=0},
        @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat";                   Name="DisableUAR";        Value=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry"; Name="IsCensusDisabled"; Value=1},
        @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry"; Name="DontRetryOnError"; Value=1}
    )
    foreach ($r in $regChanges) {
        if ($PSCmdlet.ShouldProcess("$($r.Path)\$($r.Name)", "Set DWORD = $($r.Value)")) {
            try {
                if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
                Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -Type DWord -Force
                Write-Log "$($r.Path)\$($r.Name) = $($r.Value)" 'OK'
            } catch { Write-Log "Cannot set $($r.Path)\$($r.Name): $_" 'WARN' }
        }
    }

    # 22e. Default User hive (HKCU defaults for new RDP-users)
    Write-Log "--- 22e: Default User hive (применяется ко всем НОВЫМ пользователям)" 'INFO'
    $defaultHive = "C:\Users\Default\NTUSER.DAT"
    if (-not (Test-Path $defaultHive)) {
        Write-Log "Default User hive not found at $defaultHive" 'WARN'
    } else {
        # Backup
        try { Copy-Item $defaultHive "$BackupDir\NTUSER.DAT.before" -Force; Write-Log "Default hive backup: $BackupDir\NTUSER.DAT.before" 'OK' } catch {}
        if ($PSCmdlet.ShouldProcess($defaultHive, "Apply HKCU defaults via reg load")) {
            $loaded = $false
            try {
                & reg load "HKU\OptDefault" "$defaultHive" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { $loaded = $true; Write-Log "Loaded hive at HKU\OptDefault" 'OK' }
                else { Write-Log "reg load failed (exit $LASTEXITCODE) - hive likely in use" 'ERR' }
            } catch { Write-Log "reg load exception: $_" 'ERR' }

            if ($loaded) {
                $hkcuChanges = @(
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"; Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"; Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"; Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353696Enabled"; Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled";   Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\Search";                Name="BingSearchEnabled";              Value=0},
                    @{Sub="Software\Microsoft\Windows\CurrentVersion\Privacy";               Name="TailoredExperiencesWithDiagnosticDataEnabled"; Value=0},
                    @{Sub="Software\Microsoft\Siuf\Rules";                                   Name="NumberOfSIUFInPeriod";           Value=0}
                )
                foreach ($c in $hkcuChanges) {
                    & reg add "HKU\OptDefault\$($c.Sub)" /v "$($c.Name)" /t REG_DWORD /d $($c.Value) /f 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "DefaultUser: $($c.Sub)\$($c.Name) = $($c.Value)" 'OK'
                    } else {
                        Write-Log "DefaultUser: failed $($c.Sub)\$($c.Name)" 'WARN'
                    }
                }
                # Force unload (handles + GC)
                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep 1
                & reg unload "HKU\OptDefault" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "Default User hive unloaded cleanly" 'OK'
                } else {
                    Write-Log "Hive unload failed - may need reboot before re-running" 'WARN'
                }
            }
        }
    }

    # 22f. Office telemetry — only if Office detected
    Write-Log "--- 22f: Office telemetry (only if Office installed)" 'INFO'
    $hasOffice = (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\16.0") -or (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\15.0")
    if (-not $hasOffice) {
        Write-Log "MS Office not installed - skipping" 'SKIP'
    } else {
        Write-Log "Office detected - disabling Office telemetry tasks + reg" 'INFO'
        $officeTasks = @(
            @{Path="\Microsoft\Office\"; Name="OfficeTelemetryAgentFallBack"},
            @{Path="\Microsoft\Office\"; Name="OfficeTelemetryAgentLogOn"},
            @{Path="\Microsoft\Office\"; Name="OfficeTelemetryAgentFallBack2016"},
            @{Path="\Microsoft\Office\"; Name="OfficeTelemetryAgentLogOn2016"},
            @{Path="\Microsoft\Office\"; Name="Office 15 Subscription Heartbeat"},
            @{Path="\Microsoft\Office\"; Name="Office 16 Subscription Heartbeat"}
        )
        foreach ($t in $officeTasks) {
            $task = Get-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA SilentlyContinue
            if (-not $task) { continue }
            if ($task.State -eq 'Disabled') { continue }
            if ($PSCmdlet.ShouldProcess($t.Name, "Disable Office telemetry task")) {
                try {
                    Disable-ScheduledTask -TaskPath $t.Path -TaskName $t.Name -EA Stop | Out-Null
                    Write-Log "Disabled Office task: $($t.Name)" 'OK'
                } catch { Write-Log "Cannot disable $($t.Name): $_" 'WARN' }
            }
        }
        foreach ($ver in @('15.0','16.0')) {
            $p = "HKLM:\SOFTWARE\Microsoft\Office\$ver\Common\ClientTelemetry"
            if ($PSCmdlet.ShouldProcess($p, "Disable Office $ver telemetry")) {
                try {
                    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
                    Set-ItemProperty -Path $p -Name "DisableTelemetry" -Value 1 -Type DWord -Force
                    Set-ItemProperty -Path $p -Name "VerboseLogging"   -Value 0 -Type DWord -Force
                    Write-Log "Office $ver telemetry disabled (HKLM)" 'OK'
                } catch {}
            }
        }
    }

    Write-Log "Deep telemetry disable complete" 'OK'
} else {
    Step "[skip] Deep Telemetry Disable"
    Write-Log "Telemetry deep-disable skipped (use -DisableTelemetry to enable)" 'SKIP'
}
#endregion

#region Summary
Write-Log "" 'INFO'
Write-Log "═════════════════════════════════════════════════" 'INFO'
Write-Log "ВЫПОЛНЕНО — Summary" 'INFO'
Write-Log "═════════════════════════════════════════════════" 'INFO'
Write-Log "Log:    $LogFile" 'INFO'
Write-Log "Backup: $BackupDir" 'INFO'
Write-Log "" 'INFO'

# Post-state services
Write-Log "Services post-state:" 'INFO'
foreach ($n in @('SysMain','WSearch','DiagTrack','WinDefend','Zabbix Agent','MapsBroker','Fax','TabletInputService','WerSvc')) {
    $s = Get-Service $n -EA SilentlyContinue
    if ($s) { Write-Log ("  {0,-22} status={1,-8} startup={2}" -f $s.Name, $s.Status, $s.StartType) 'INFO' }
}
$wmi = Get-Process WmiPrvSE -EA SilentlyContinue
if ($wmi) {
    $cpu = [math]::Round((($wmi | Measure CPU -Sum).Sum)/60, 1)
    Write-Log ("  WmiPrvSE              count={0} accumulated_CPU={1}min" -f $wmi.Count, $cpu) 'INFO'
}
if ($DefenderActive) {
    try {
        $mp = Get-MpPreference -EA Stop
        Write-Log ("  Defender              ext={0} proc={1} path={2}" -f $mp.ExclusionExtension.Count, $mp.ExclusionProcess.Count, $mp.ExclusionPath.Count) 'INFO'
    } catch {
        Write-Log "  Defender              query failed: $_" 'WARN'
    }
} else {
    Write-Log "  Defender              not active (3rd-party AV present)" 'INFO'
}
$gpu = Get-WmiObject Win32_VideoController | Where {$_.AdapterRAM -gt 100MB -and $_.Name -notmatch 'Basic|VGA'} | Select -First 1
if ($gpu) {
    Write-Log ("  GPU                   {0} ({1} MB VRAM)" -f $gpu.Name, [math]::Round($gpu.AdapterRAM/1MB)) 'INFO'
} else {
    Write-Log "  GPU                   none (Basic Display Adapter only) - AVC OFF correct" 'INFO'
}

Write-Log "" 'INFO'
Write-Log "REMINDERS:" 'INFO'
Write-Log "  * REBOOT нужен для:  Memory Compression, Win32PrioritySeparation, LargeSystemCache" 'WARN'
Write-Log "  * Schedule reboot for off-hours (нерабочее время)" 'WARN'
Write-Log "  * Откат Defender exclusions:" 'INFO'
Write-Log "    `$bk = Import-Clixml '$BackupDir\MpPreference-before.xml'" 'INFO'
Write-Log "    `$now = Get-MpPreference" 'INFO'
Write-Log "    `$now.ExclusionExtension | Where {`$_ -notin `$bk.ExclusionExtension} | %% { Remove-MpPreference -ExclusionExtension `$_ }" 'INFO'
Write-Log "═════════════════════════════════════════════════" 'INFO'
#endregion
