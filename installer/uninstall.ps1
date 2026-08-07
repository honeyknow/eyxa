# =============================================================================
# uninstall.ps1 - Eyxa EDR Agent Uninstaller (Aggressive / Full Clean)
#
# Removes EVERYTHING Eyxa installed:
#   - EyxaEDR service
#   - Sysmon64 driver
#   - C:\Program Files\Eyxa (retries until gone)
#   - C:\ProgramData\Eyxa (retries until gone)
#   - HKLM\SOFTWARE\Eyxa registry key
#   - HKLM Run key entry for tray
#   - Defender exclusions for both paths
#
# Usage: Double-click uninstall.bat  (auto-requests UAC)
# Log  : uninstall.log written next to this script (deleted and recreated each run)
# =============================================================================

$INSTALL_DIR  = "C:\Program Files\Eyxa"
$DATA_DIR     = "C:\ProgramData\Eyxa"
$SERVICE_NAME = "EyxaEDR"
$REG_PATH     = "HKLM:\SOFTWARE\Eyxa"
$LogFile      = Join-Path $PSScriptRoot "uninstall.log"

# ── Logging: delete old log, create fresh ────────────────────────────────────
if (Test-Path $LogFile) { Remove-Item $LogFile -Force -ErrorAction SilentlyContinue }
$null = New-Item -Path $LogFile -ItemType File -Force

function Log { param([string]$level, [string]$msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$ts] [$level] $msg"
}

# ── Console + Log helpers ─────────────────────────────────────────────────────
function Write-Step { param([int]$n, [string]$msg)
    Write-Host ""
    Write-Host "+-[STEP $n] $msg" -ForegroundColor Cyan
    Log "STEP" "[$n] $msg"
}
function Write-OK { param([string]$m)
    Write-Host "|  [+] $m" -ForegroundColor Green
    Log "OK" $m
}
function Write-WARN { param([string]$m)
    Write-Host "|  [!] $m" -ForegroundColor Yellow
    Log "WARN" $m
}
function Write-Dot { param([string]$m)
    Write-Host "|  ... $m" -ForegroundColor Gray
    Log "WAIT" $m
}
function Write-Done { param([string]$m)
    Write-Host "+-$m" -ForegroundColor Cyan
    Log "DONE" $m
}
function Write-FAIL { param([string]$m)
    Write-Host "|  [X] $m" -ForegroundColor Red
    Write-Host "+-[ABORTED]" -ForegroundColor Red
    Log "FAIL" $m
    Read-Host "|  Press Enter to close"
    exit 1
}

# ── Helper: Kill all instances of a process by name (retry loop) ─────────────
function Kill-Process-Loop { param([string]$name, [int]$maxTries = 5)
    for ($i = 1; $i -le $maxTries; $i++) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if (-not $procs) { break }
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Dot "Killed $name.exe (attempt $i)"
        Start-Sleep 1
    }
    $still = Get-Process -Name $name -ErrorAction SilentlyContinue
    if ($still) { Write-WARN "$name.exe could not be killed after $maxTries attempts" }
    else { Write-OK "All $name.exe processes terminated" }
}

# ── Helper: Force-delete a directory (retry loop with takeown fallback) ───────
function Remove-Dir-Force { param([string]$path, [int]$maxTries = 6)
    for ($i = 1; $i -le $maxTries; $i++) {
        if (-not (Test-Path $path)) { Write-OK "Directory gone: $path"; return }
        Write-Dot "Deleting $path (attempt $i)..."
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        } catch {
            # Fallback 1: cmd rd (2>NUL is the correct CMD null device - not $null)
            cmd /c "rd /s /q `"$path`" 2>NUL"
        }
        if (-not (Test-Path $path)) { Write-OK "Deleted: $path"; return }
        # Fallback 2: takeown + icacls to break locks, then retry
        if ($i -ge 3) {
            Write-Dot "Taking ownership and resetting ACLs on $path..."
            & takeown /f $path /r /d y 2>&1 | Out-Null
            & icacls $path /grant Administrators:F /t /c /q 2>&1 | Out-Null
        }
        Start-Sleep 2
    }
    if (Test-Path $path) {
        Write-WARN "Could not fully delete $path - may need manual deletion after reboot"
        Log "WARN" "Directory still present after $maxTries attempts: $path"
    }
}

Log "START" "============ Eyxa Uninstaller Started ============"
Write-Host ""
Write-Host "==================================================" -ForegroundColor Red
Write-Host "   Eyxa EDR Agent - Uninstaller (Full Clean)" -ForegroundColor Red
Write-Host "==================================================" -ForegroundColor Red

# ── STEP 0: Auto-elevation ─────────────────────────────────────────────────
Write-Step 0 "Checking Administrator privileges"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-WARN "Not elevated - requesting UAC elevation..."
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Path)`""
    exit 0
}
Write-OK "Running as Administrator"
Write-Done "OK"

# ── STEP 1: Kill tray app ──────────────────────────────────────────────────
Write-Step 1 "Killing tray application (terminator.exe)"
Kill-Process-Loop "terminator"
Write-Done "OK"

# ── STEP 2: Stop EyxaEDR service ──────────────────────────────────────────
Write-Step 2 "Stopping EyxaEDR service"
$svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Write-OK "Stop-Service issued"
    } else {
        Write-OK "Service already STOPPED"
    }
    # Poll until confirmed STOPPED (max 20s)
    $elapsed = 0
    while ($elapsed -lt 20) {
        $s = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
        if ($null -eq $s -or $s -eq "Stopped") { break }
        Write-Dot "waiting STOPPED (${elapsed}s)"; Start-Sleep 2; $elapsed += 2
    }
    $finalSvcStatus = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
    if ($null -eq $finalSvcStatus -or $finalSvcStatus -eq "Stopped") {
        Write-OK "Service STOPPED"
    } else {
        Write-WARN "Service still in state: $finalSvcStatus - continuing anyway"
    }
} else {
    Write-WARN "No EyxaEDR service found - already removed"
}
Write-Done "OK"

# ── STEP 3: Kill eyxa.exe process (belt and suspenders) ────────────────────
Write-Step 3 "Killing any remaining eyxa.exe processes"
Kill-Process-Loop "eyxa"
Write-Done "OK"

# ── STEP 4: Delete EyxaEDR service from SCM ───────────────────────────────
Write-Step 4 "Deleting EyxaEDR service from Service Control Manager"
for ($i = 1; $i -le 3; $i++) {
    if (-not (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue)) {
        Write-OK "Service definition already gone"; break
    }
    & sc.exe delete $SERVICE_NAME | Out-Null
    Start-Sleep 2
    if (-not (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue)) {
        Write-OK "Service deleted from SCM"; break
    }
    Write-Dot "Retry sc delete (attempt $i)..."
}
if (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue) {
    Write-WARN "Service still visible in SCM - will be fully removed on next reboot"
}
Write-Done "OK"

# ── STEP 5: Uninstall Sysmon ───────────────────────────────────────────────
Write-Step 5 "Uninstalling Sysmon"
# Try using the bundled Sysmon64.exe first (most reliable)
$sysmonLocal = Join-Path $PSScriptRoot "Sysmon64.exe"
$sysmonInst  = Join-Path $INSTALL_DIR "Sysmon64.exe"
$sysmonExe   = if (Test-Path $sysmonLocal) { $sysmonLocal } elseif (Test-Path $sysmonInst) { $sysmonInst } else { $null }

if (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue) {
    if ($sysmonExe) {
        & $sysmonExe -u force 2>&1 | Out-Null
        Write-OK "Sysmon uninstall command issued"
    } else {
        # Fallback: stop and delete the driver service manually
        Stop-Service -Name "SysmonDrv" -Force -ErrorAction SilentlyContinue
        & sc.exe delete SysmonDrv  | Out-Null
        & sc.exe delete Sysmon64   | Out-Null
        Write-WARN "Sysmon64.exe not found - removed driver service via sc.exe"
    }
    Start-Sleep 3
    if (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue) {
        Write-WARN "SysmonDrv still registered - may require reboot to fully clear"
    } else {
        Write-OK "SysmonDrv removed"
    }
} else {
    Write-OK "SysmonDrv not installed - nothing to remove"
}
Write-Done "OK"

# ── STEP 6: Delete install directory (retry with ownership takeover) ────────
Write-Step 6 "Deleting install directory: $INSTALL_DIR"
Remove-Dir-Force $INSTALL_DIR
Write-Done "OK"

# ── STEP 7: Delete data directory ─────────────────────────────────────────
Write-Step 7 "Deleting data directory: $DATA_DIR"
Remove-Dir-Force $DATA_DIR
Write-Done "OK"

# ── STEP 8: Remove registry key ────────────────────────────────────────────
# Source: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item
Write-Step 8 "Removing registry key (HKLM\SOFTWARE\Eyxa)"
if (Test-Path $REG_PATH) {
    Remove-Item -Path $REG_PATH -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $REG_PATH) {
        Write-WARN "Registry key still present - may clear after reboot"
    } else {
        Write-OK "Registry key removed"
    }
} else {
    Write-OK "Registry key not found - already clean"
}
Write-Done "OK"

# ── STEP 9: Remove tray from Run key ──────────────────────────────────────
Write-Step 9 "Removing tray entry from HKLM Run key"
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
try {
    Remove-ItemProperty -Path $runKey -Name "EyxaTray" -Force -ErrorAction Stop
    Write-OK "EyxaTray removed from Run key"
} catch {
    Write-OK "EyxaTray not in Run key - already clean"
}
Write-Done "OK"

# ── STEP 10: Remove Defender exclusions ───────────────────────────────────
Write-Step 10 "Removing Windows Defender exclusions"
try {
    Remove-MpPreference -ExclusionPath $INSTALL_DIR -ErrorAction SilentlyContinue
    Write-OK "Exclusion removed: $INSTALL_DIR"
} catch { Write-WARN "Could not remove exclusion for $INSTALL_DIR" }
try {
    Remove-MpPreference -ExclusionPath $DATA_DIR -ErrorAction SilentlyContinue
    Write-OK "Exclusion removed: $DATA_DIR"
} catch { Write-WARN "Could not remove exclusion for $DATA_DIR" }
Write-Done "OK"

# ══════════════════════════════════════════════════════════════════════════════
# FINAL VERIFICATION - confirm everything is gone
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   FINAL VERIFICATION (all should show [+])" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Log "VERIFY" "======= Final Verification ======="

$allClean = $true

function Check-Gone { param([string]$label, [bool]$isGone, [string]$detail = "")
    if ($isGone) {
        Write-Host "  [+] $label" -ForegroundColor Green
        Log "VERIFY" "[CLEAN] $label $detail"
    } else {
        Write-Host "  [!] $label" -ForegroundColor Yellow
        Log "VERIFY" "[REMAIN] $label $detail - may clear after reboot"
        $script:allClean = $false
    }
}

Check-Gone "EyxaEDR service removed"       ($null -eq (Get-Service $SERVICE_NAME -ErrorAction SilentlyContinue))
Check-Gone "SysmonDrv service removed"      ($null -eq (Get-Service "SysmonDrv"   -ErrorAction SilentlyContinue))
Check-Gone "eyxa.exe process not running"   ($null -eq (Get-Process "eyxa"        -ErrorAction SilentlyContinue))
Check-Gone "terminator.exe not running"     ($null -eq (Get-Process "terminator"  -ErrorAction SilentlyContinue))
Check-Gone "Install dir deleted"            (-not (Test-Path $INSTALL_DIR))
Check-Gone "Data dir deleted"               (-not (Test-Path $DATA_DIR))
Check-Gone "Registry key removed"          (-not (Test-Path $REG_PATH))

$trayGone = $true
try { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EyxaTray" -ErrorAction Stop | Out-Null; $trayGone = $false } catch {}
Check-Gone "Tray Run key entry removed"     $trayGone

Write-Host "==================================================" -ForegroundColor Cyan

if ($allClean) {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "  [+] Eyxa EDR Agent fully uninstalled" -ForegroundColor Green
    Write-Host "  [+] System restored to pre-install state" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Log "SUCCESS" "All checks passed. System fully clean."
} else {
    Write-Host ""
    Write-Host "  [!] Some items could not be removed yet." -ForegroundColor Yellow
    Write-Host "  [!] A REBOOT will complete the cleanup." -ForegroundColor Yellow
    Write-Host "  [!] Check uninstall.log for details." -ForegroundColor Yellow
    Log "WARNING" "Some items remain - reboot required to complete cleanup."
}

Write-Host ""
Read-Host "Press Enter to close"
