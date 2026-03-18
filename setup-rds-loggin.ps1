#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Настройка мониторинга сессий на терминальном сервере (RDS)

.DESCRIPTION
    Скрипт выполняет:
    1. Выставление нормальных размеров логов
    2. Перезапуск службы логирования
    3. Проверку применённых настроек
    4. Настройку ежедневного бэкапа логов
    5. Настройку ротации бэкапов (глубина хранения — $BackupRetentionDays)
    6. Создание задач в планировщике Windows

.NOTES
    Запускать от имени Администратора
    Протестировано на Windows Server 2016/2019/2022
#>

# ============================================================
#  НАСТРОЙКИ — меняй только здесь
# ============================================================

# Папка для хранения бэкапов логов и лога ротации
$BackupDir        = "C:\Logs"

# Глубина хранения бэкапов (дней)
$BackupRetentionDays = 90   # 3 месяца

# Жёсткий лимит на папку с бэкапами (MB) — защита от переполнения диска
$MaxBackupFolderMB   = 3072  # 3 GB

# Размеры логов
$RDSLogMaxSizeMB     = 200   # RDS LocalSessionManager
$SecurityLogMaxSizeMB = 500  # Security

# Время запуска задач планировщика
$BackupTaskTime   = "23:50"  # ежедневный бэкап
$RotationTaskTime = "02:00"  # еженедельная ротация (воскресенье)

# Папка для хранения вспомогательных скриптов
$ScriptsDir = "C:\Scripts\RDSLogging"

# ============================================================
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

function Write-Header {
    param([string]$Text)
    $Line = "=" * 60
    Write-Host "`n$Line" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "$Line" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n  >> $Text" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Text)
    Write-Host "     [OK] $Text" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Text)
    Write-Host "     [!!] $Text" -ForegroundColor Red
}

function Write-Info {
    param([string]$Text)
    Write-Host "          $Text" -ForegroundColor Gray
}

# ============================================================
#  НАЧАЛО РАБОТЫ
# ============================================================

$StartTime = Get-Date
Write-Host ""
Write-Host "  ██████╗ ██████╗ ███████╗    ██╗      ██████╗  ██████╗ " -ForegroundColor Cyan
Write-Host "  ██╔══██╗██╔══██╗██╔════╝    ██║     ██╔═══██╗██╔════╝ " -ForegroundColor Cyan
Write-Host "  ██████╔╝██║  ██║███████╗    ██║     ██║   ██║██║  ███╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██║  ██║╚════██║    ██║     ██║   ██║██║   ██║" -ForegroundColor Cyan
Write-Host "  ██║  ██║██████╔╝███████║    ███████╗╚██████╔╝╚██████╔╝" -ForegroundColor Cyan
Write-Host "  ╚═╝  ╚═╝╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝ " -ForegroundColor Cyan
Write-Host ""
Write-Host "  Сервер  : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  Время   : $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor White
Write-Host "  Глубина : $BackupRetentionDays дней" -ForegroundColor White
Write-Host ""

# ============================================================
#  ШАГ 1 — ВЫСТАВЛЕНИЕ РАЗМЕРОВ ЛОГОВ
# ============================================================

Write-Header "ШАГ 1 — Настройка размеров логов"

$LogSettings = @(
    @{
        Name    = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
        SizeMB  = $RDSLogMaxSizeMB
        Label   = "RDS LocalSessionManager"
    },
    @{
        Name    = "Security"
        SizeMB  = $SecurityLogMaxSizeMB
        Label   = "Security Log"
    }
)

foreach ($Log in $LogSettings) {
    Write-Step "$($Log.Label) → $($Log.SizeMB) MB"
    try {
        $SizeBytes = $Log.SizeMB * 1MB
        # wevtutil: sl = set-log, /ms = max size, /rt:false = circular (перезаписывает старое)
        $Result = wevtutil sl "$($Log.Name)" /ms:$SizeBytes /rt:false 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Размер установлен: $($Log.SizeMB) MB"
        } else {
            Write-Fail "Ошибка: $Result"
        }
    } catch {
        Write-Fail $_.Exception.Message
    }
}

# ============================================================
#  ШАГ 2 — ПЕРЕЗАПУСК СЛУЖБЫ ЛОГИРОВАНИЯ
# ============================================================

Write-Header "ШАГ 2 — Перезапуск службы Windows Event Log"

Write-Step "Останавливаем EventLog..."
Write-Info "(кратковременная пауза 3-5 секунд — это нормально)"

try {
    Stop-Service -Name EventLog -Force -ErrorAction Stop
    Start-Sleep -Seconds 3
    Start-Service -Name EventLog -ErrorAction Stop
    Start-Sleep -Seconds 2

    $Svc = Get-Service -Name EventLog
    if ($Svc.Status -eq 'Running') {
        Write-OK "Служба EventLog запущена (статус: $($Svc.Status))"
    } else {
        Write-Fail "Служба не запустилась! Статус: $($Svc.Status)"
    }
} catch {
    Write-Fail "Не удалось перезапустить службу: $($_.Exception.Message)"
    Write-Info "Попробуй вручную: Restart-Service EventLog -Force"
}

# ============================================================
#  ШАГ 3 — ПРОВЕРКА ПРИМЕНЁННЫХ НАСТРОЕК
# ============================================================

Write-Header "ШАГ 3 — Проверка настроек"

$AllOK = $true

foreach ($Log in $LogSettings) {
    Write-Step "Проверяем: $($Log.Label)"
    try {
        $Info = Get-WinEvent -ListLog $Log.Name -ErrorAction Stop

        $ActualMB  = [math]::Round($Info.MaximumSizeInBytes / 1MB, 0)
        $FilledMB  = [math]::Round($Info.FileSize / 1MB, 1)
        $FilledPct = [math]::Round(($Info.FileSize / $Info.MaximumSizeInBytes) * 100, 1)
        $Mode      = $Info.LogMode

        Write-Info "Максимум   : $ActualMB MB (ожидается $($Log.SizeMB) MB)"
        Write-Info "Занято     : $FilledMB MB ($FilledPct %)"
        Write-Info "Режим      : $Mode"
        Write-Info "Записей    : $($Info.RecordCount)"
        Write-Info "Включён    : $($Info.IsEnabled)"

        if ($ActualMB -ge $Log.SizeMB) {
            Write-OK "Размер соответствует заданному"
        } else {
            Write-Fail "Размер НЕ применился! Попробуй перезагрузить сервер."
            $AllOK = $false
        }

        # Самое старое событие в логе
        $OldestEvent = Get-WinEvent -FilterHashtable @{ LogName = $Log.Name } `
            -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($OldestEvent) {
            $AgeDays = [math]::Round(((Get-Date) - $OldestEvent.TimeCreated).TotalDays, 1)
            Write-Info "История    : с $($OldestEvent.TimeCreated.ToString('dd.MM.yyyy')) ($AgeDays дн.)"
        }

    } catch {
        Write-Fail "Не удалось прочитать лог: $($_.Exception.Message)"
        $AllOK = $false
    }
}

if ($AllOK) {
    Write-Host "`n  Все проверки пройдены успешно!" -ForegroundColor Green
} else {
    Write-Host "`n  Есть проблемы — см. [!!] выше" -ForegroundColor Red
}

# ============================================================
#  ШАГ 4 — СОЗДАНИЕ ВСПОМОГАТЕЛЬНЫХ СКРИПТОВ
# ============================================================

Write-Header "ШАГ 4 — Создание скриптов бэкапа и ротации"

# Создаём папки
foreach ($Dir in @($BackupDir, $ScriptsDir)) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Write-OK "Создана папка: $Dir"
    } else {
        Write-Info "Папка уже существует: $Dir"
    }
}

# --- Скрипт ежедневного бэкапа ---
$BackupScript = @"
#Requires -RunAsAdministrator
# Ежедневный бэкап RDS и Security логов
# Создан автоматически Setup-RDSLogging.ps1

`$BackupDir  = "$BackupDir"
`$LogFile    = "$BackupDir\backup.log"
`$Date       = Get-Date -Format 'yyyy-MM-dd'
`$TimeStamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Write-Log {
    param(`$Msg)
    `$Line = "`$TimeStamp | `$Msg"
    Add-Content -Path `$LogFile -Value `$Line
    Write-Host `$Line
}

Write-Log "=== Запуск бэкапа на `$(`$env:COMPUTERNAME) ==="

`$Logs = @(
    @{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Short = "RDS" },
    @{ Name = "Security"; Short = "Security" }
)

foreach (`$Log in `$Logs) {
    `$FileName = "`$BackupDir\`$(`$Log.Short)_`$Date.evtx"
    try {
        wevtutil epl "`$(`$Log.Name)" "`$FileName" /ow:true 2>&1 | Out-Null
        if (Test-Path `$FileName) {
            `$SizeMB = [math]::Round((Get-Item `$FileName).Length / 1MB, 1)
            Write-Log "OK | `$(`$Log.Short) -> `$FileName [`$SizeMB MB]"
        } else {
            Write-Log "WARN | `$(`$Log.Short) -> файл не создан (лог пуст?)"
        }
    } catch {
        Write-Log "ERR | `$(`$Log.Short) -> `$(`$_.Exception.Message)"
    }
}

Write-Log "=== Бэкап завершён ==="
"@

# --- Скрипт ротации бэкапов ---
$RotationScript = @"
#Requires -RunAsAdministrator
# Еженедельная ротация бэкапов RDS логов
# Создан автоматически Setup-RDSLogging.ps1

`$BackupDir          = "$BackupDir"
`$RetentionDays      = $BackupRetentionDays
`$MaxFolderMB        = $MaxBackupFolderMB
`$LogFile            = "$BackupDir\rotation.log"
`$TimeStamp          = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Write-Log {
    param(`$Msg)
    `$Line = "`$TimeStamp | `$Msg"
    Add-Content -Path `$LogFile -Value `$Line
    Write-Host `$Line
}

Write-Log "=== Запуск ротации на `$(`$env:COMPUTERNAME) ==="

# Шаг 1: удаляем файлы старше RetentionDays
`$OldFiles = Get-ChildItem `$BackupDir -Filter "*.evtx" -ErrorAction SilentlyContinue |
    Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-`$RetentionDays) }

if (`$OldFiles.Count -eq 0) {
    Write-Log "INFO | Файлов старше `$RetentionDays дней не найдено"
} else {
    foreach (`$File in `$OldFiles) {
        `$SizeMB = [math]::Round(`$File.Length / 1MB, 1)
        Remove-Item `$File.FullName -Force
        Write-Log "DEL  | `$(`$File.Name) [`$SizeMB MB] (старше `$RetentionDays дней)"
    }
}

# Шаг 2: проверяем общий размер папки — удаляем самые старые если превышен лимит
`$GetFolderSizeMB = {
    `$Files = Get-ChildItem `$BackupDir -Filter "*.evtx" -ErrorAction SilentlyContinue
    if (`$Files) { [math]::Round((`$Files | Measure-Object -Property Length -Sum).Sum / 1MB, 1) }
    else { 0 }
}

`$FolderSizeMB = & `$GetFolderSizeMB
Write-Log "INFO | Размер папки: `$FolderSizeMB MB / лимит `$MaxFolderMB MB"

if (`$FolderSizeMB -gt `$MaxFolderMB) {
    Write-Log "WARN | Превышен лимит! Удаляем самые старые файлы..."
    `$AllFiles = Get-ChildItem `$BackupDir -Filter "*.evtx" | Sort-Object LastWriteTime

    foreach (`$File in `$AllFiles) {
        if ((& `$GetFolderSizeMB) -le `$MaxFolderMB) { break }
        `$SizeMB = [math]::Round(`$File.Length / 1MB, 1)
        Remove-Item `$File.FullName -Force
        Write-Log "DEL  | `$(`$File.Name) [`$SizeMB MB] (лимит папки)"
    }
}

# Шаг 3: финальная статистика
`$Remaining = Get-ChildItem `$BackupDir -Filter "*.evtx" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
`$FinalMB   = & `$GetFolderSizeMB

Write-Log "STAT | Файлов: `$(`$Remaining.Count) | Итого: `$FinalMB MB"

if (`$Remaining.Count -gt 0) {
    `$From = `$Remaining[0].LastWriteTime.ToString('dd.MM.yyyy')
    `$To   = `$Remaining[-1].LastWriteTime.ToString('dd.MM.yyyy')
    Write-Log "STAT | Период: `$From — `$To"
}

Write-Log "=== Ротация завершена ==="
"@

# Сохраняем скрипты
$BackupScriptPath   = "$ScriptsDir\Backup-RDSLogs.ps1"
$RotationScriptPath = "$ScriptsDir\Rotate-RDSLogs.ps1"

$BackupScript   | Out-File $BackupScriptPath   -Encoding UTF8 -Force
$RotationScript | Out-File $RotationScriptPath -Encoding UTF8 -Force

Write-OK "Создан скрипт бэкапа   : $BackupScriptPath"
Write-OK "Создан скрипт ротации  : $RotationScriptPath"

# ============================================================
#  ШАГ 5 — СОЗДАНИЕ ЗАДАЧ В ПЛАНИРОВЩИКЕ
# ============================================================

Write-Header "ШАГ 5 — Создание задач в планировщике"

$Tasks = @(
    @{
        Name        = "RDS_DailyBackup"
        Description = "Ежедневный бэкап RDS и Security логов"
        Script      = $BackupScriptPath
        Trigger     = New-ScheduledTaskTrigger -Daily -At $BackupTaskTime
        TriggerDesc = "Ежедневно в $BackupTaskTime"
    },
    @{
        Name        = "RDS_WeeklyRotation"
        Description = "Еженедельная ротация бэкапов (глубина $BackupRetentionDays дней)"
        Script      = $RotationScriptPath
        Trigger     = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $RotationTaskTime
        TriggerDesc = "Еженедельно, воскресенье в $RotationTaskTime"
    }
)

foreach ($Task in $Tasks) {
    Write-Step "$($Task.Name) — $($Task.TriggerDesc)"
    try {
        # Удаляем старую задачу если есть
        Unregister-ScheduledTask -TaskName $Task.Name -Confirm:$false -ErrorAction SilentlyContinue

        $Action   = New-ScheduledTaskAction `
            -Execute "PowerShell.exe" `
            -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$($Task.Script)`""

        $Settings = New-ScheduledTaskSettingsSet `
            -RunOnlyIfNetworkAvailable:$false `
            -StartWhenAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1)

        $Principal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest

        Register-ScheduledTask `
            -TaskName    $Task.Name `
            -Description $Task.Description `
            -Action      $Action `
            -Trigger     $Task.Trigger `
            -Settings    $Settings `
            -Principal   $Principal `
            -Force | Out-Null

        Write-OK "Задача создана: $($Task.Name)"
        Write-Info "Расписание: $($Task.TriggerDesc)"
        Write-Info "Скрипт    : $($Task.Script)"

    } catch {
        Write-Fail "Не удалось создать задачу $($Task.Name): $($_.Exception.Message)"
    }
}

# ============================================================
#  ИТОГОВЫЙ ОТЧЁТ
# ============================================================

Write-Header "ИТОГОВЫЙ ОТЧЁТ"

$Duration = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)

Write-Host ""
Write-Host "  Сервер         : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  Выполнено за   : $Duration сек." -ForegroundColor White
Write-Host ""
Write-Host "  Логи:" -ForegroundColor Cyan
Write-Host "    RDS лог         : $RDSLogMaxSizeMB MB" -ForegroundColor White
Write-Host "    Security лог    : $SecurityLogMaxSizeMB MB" -ForegroundColor White
Write-Host ""
Write-Host "  Бэкапы:" -ForegroundColor Cyan
Write-Host "    Папка           : $BackupDir" -ForegroundColor White
Write-Host "    Хранение        : $BackupRetentionDays дней" -ForegroundColor White
Write-Host "    Лимит папки     : $MaxBackupFolderMB MB" -ForegroundColor White
Write-Host ""
Write-Host "  Задачи планировщика:" -ForegroundColor Cyan
Write-Host "    RDS_DailyBackup     — ежедневно в $BackupTaskTime" -ForegroundColor White
Write-Host "    RDS_WeeklyRotation  — воскресенье в $RotationTaskTime" -ForegroundColor White
Write-Host ""
Write-Host "  Скрипты:" -ForegroundColor Cyan
Write-Host "    $BackupScriptPath" -ForegroundColor White
Write-Host "    $RotationScriptPath" -ForegroundColor White
Write-Host ""

# Проверяем задачи в планировщике ещё раз
Write-Host "  Статус задач в планировщике:" -ForegroundColor Cyan
foreach ($TaskName in @("RDS_DailyBackup", "RDS_WeeklyRotation")) {
    $T = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($T) {
        Write-Host "    [OK] $TaskName — $($T.State)" -ForegroundColor Green
    } else {
        Write-Host "    [!!] $TaskName — НЕ НАЙДЕНА" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "  Готово! Скрипт можно запустить на втором сервере." -ForegroundColor Green
Write-Host ""
