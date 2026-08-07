# =============================================================================
# install.ps1 - Eyxa EDR Agent Installer
#
# Prerequisites (run ONCE as Admin BEFORE downloading installer zip):
#   Add-MpPreference -ExclusionPath "C:\Program Files\Eyxa"
#   Add-MpPreference -ExclusionPath "C:\ProgramData\Eyxa"
#
# Usage: Double-click install.bat  (auto-requests UAC)
# Log  : install.log written next to this script (deleted and recreated each run)
# =============================================================================

$INSTALL_DIR  = "C:\Program Files\Eyxa"
$DATA_DIR     = "C:\ProgramData\Eyxa"
$SERVICE_NAME = "EyxaEDR"
$SERVICE_EXE  = "$INSTALL_DIR\eyxa.exe"
$TRAY_EXE     = "$INSTALL_DIR\terminator.exe"
$REG_PATH     = "HKLM:\SOFTWARE\Eyxa"
$REQUIRED     = @("Sysmon64.exe","sysmon_config.xml","eyxa.exe","eyxa.xml","terminator.exe")
$LogFile      = Join-Path $PSScriptRoot "install.log"

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
    Log "ABORTED" "Installation failed at this step"
    Read-Host "|  Press Enter to close"
    exit 1
}

Log "START" "============ Eyxa Installer Started ============"
Write-Host ""
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "   Eyxa EDR Agent - Installer" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta

# ── STEP 0: Auto-elevation ─────────────────────────────────────────────────
Write-Step 0 "Checking Administrator privileges"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-WARN "Not elevated - requesting UAC elevation now..."
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$($MyInvocation.MyCommand.Path)`""
    exit 0
}
Write-OK "Running as Administrator"
Write-Done "OK"

# ── STEP 1: Verify all 5 required files ────────────────────────────────────
Write-Step 1 "Verifying required files"
foreach ($f in $REQUIRED) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $f))) {
        Write-FAIL "Missing: $f -- all 5 installer files must be in the same folder as install.ps1"
    }
    Write-OK "Found: $f"
}
Write-Done "All 5 files present"

# ── STEP 2: Prompt Server URL + Enroll Token ───────────────────────────────
Write-Step 2 "Configuration input"
Write-Host "|" -ForegroundColor Cyan
Write-Host "|  Enter server address (IP or hostname - no https:// prefix):" -ForegroundColor White
$serverInput = Read-Host "|  Server"
if ([string]::IsNullOrWhiteSpace($serverInput)) { Write-FAIL "Server address cannot be empty." }

if ($serverInput -notmatch "^https?://") {
    $backendUrl = if ($serverInput -match ":\d+$") { "https://$serverInput" } else { "https://${serverInput}:8443" }
} else { $backendUrl = $serverInput }
Write-OK "Backend URL: $backendUrl"

Write-Host "|" -ForegroundColor Cyan
Write-Host "|  Enter Enroll Token:" -ForegroundColor White
$enrollToken = Read-Host "|  Token"
if ([string]::IsNullOrWhiteSpace($enrollToken)) { Write-FAIL "Enroll Token cannot be empty." }
Write-OK "Token received ($($enrollToken.Length) chars)"
Write-Done "Config set"

# ── STEP 3: Sysmon install or update config ────────────────────────────────
Write-Step 3 "Sysmon - install or update configuration"
$sysmonExe    = Join-Path $PSScriptRoot "Sysmon64.exe"
$sysmonConfig = Join-Path $PSScriptRoot "sysmon_config.xml"

if (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue) {
    Write-OK "SysmonDrv found - updating config"
    & $sysmonExe -c $sysmonConfig -accepteula 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-FAIL "Sysmon config update failed (exit $LASTEXITCODE)" }
    Write-OK "Config updated"
} else {
    Write-OK "SysmonDrv not found - fresh install"
    & $sysmonExe -i $sysmonConfig -accepteula 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-FAIL "Sysmon install failed (exit $LASTEXITCODE)" }
    Write-OK "Sysmon installed"
}
Write-Done "Sysmon configured"

# ── STEP 4: Wait for SysmonDrv RUNNING ────────────────────────────────────
Write-Step 4 "Waiting for SysmonDrv RUNNING (timeout 30s)"
$elapsed = 0
do {
    Start-Sleep 2; $elapsed += 2
    $state = (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue).Status
    Write-Dot "$state (${elapsed}s)"
} until ($state -eq "Running" -or $elapsed -ge 30)
if ($state -ne "Running") { Write-FAIL "SysmonDrv did not reach RUNNING in 30s" }
Write-OK "SysmonDrv is RUNNING"
Write-Done "OK"

# ── STEP 5: Stop EyxaEDR + kill locked processes ───────────────────────────
Write-Step 5 "Stopping EyxaEDR and releasing file locks"
$svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") {
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Write-OK "Stop-Service issued"
    } else { Write-OK "Service already STOPPED" }
} else { Write-WARN "No existing $SERVICE_NAME service" }

foreach ($procName in @("eyxa","terminator")) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($procs) { $procs | Stop-Process -Force -ErrorAction SilentlyContinue; Write-OK "Killed: $procName.exe" }
}

$elapsed = 0
while ($elapsed -lt 15) {
    $s = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
    if ($null -eq $s -or $s -eq "Stopped") { break }
    Write-Dot "waiting STOPPED (${elapsed}s)"; Start-Sleep 2; $elapsed += 2
}
Write-OK "Locks released"
Write-Done "OK"

# ── STEP 6: Delete old service (immediately after STOPPED) ─────────────────
Write-Step 6 "Removing old EyxaEDR from SCM"
if (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue) {
    & sc.exe delete $SERVICE_NAME | Out-Null
    Start-Sleep 2
    Write-OK "Old service removed"
} else { Write-OK "No old service - clean state" }
Write-Done "OK"

# ── STEP 7: Create directories ─────────────────────────────────────────────
Write-Step 7 "Creating installation directories"
New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
New-Item -ItemType Directory -Path $DATA_DIR    -Force | Out-Null
Write-OK "Install : $INSTALL_DIR"
Write-OK "Data    : $DATA_DIR"
Write-Done "OK"

# ── STEP 8: Copy files ─────────────────────────────────────────────────────
Write-Step 8 "Copying files to $INSTALL_DIR"
foreach ($f in $REQUIRED) {
    try {
        Copy-Item -Path (Join-Path $PSScriptRoot $f) -Destination (Join-Path $INSTALL_DIR $f) -Force -ErrorAction Stop
        Write-OK "Copied: $f"
    } catch {
        Write-FAIL "Failed to copy $f : $_"
    }
}
Write-Done "All files copied"

# ── STEP 9: Write registry ─────────────────────────────────────────────────
# Source: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-itemproperty
Write-Step 9 "Writing registry (HKLM\SOFTWARE\Eyxa)"
if (-not (Test-Path $REG_PATH)) { New-Item -Path $REG_PATH -Force | Out-Null }
try {
    Set-ItemProperty -Path $REG_PATH -Name "BackendUrl"    -Value $backendUrl  -Type String -ErrorAction Stop
    Set-ItemProperty -Path $REG_PATH -Name "EnrollToken"   -Value $enrollToken -Type String -ErrorAction Stop
    Set-ItemProperty -Path $REG_PATH -Name "SkipTlsVerify" -Value 1            -Type DWord  -ErrorAction Stop
} catch {
    Write-FAIL "Registry write failed: $_"
}
Write-OK "BackendUrl    = $backendUrl"
Write-OK "EnrollToken   = [set, $($enrollToken.Length) chars]"
Write-OK "SkipTlsVerify = 1"
Write-Done "Registry written"

# ── STEP 10: Create EyxaEDR service ───────────────────────────────────────
# Source: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create
Write-Step 10 "Creating EyxaEDR service (LocalSystem, AutoStart)"
& sc.exe create $SERVICE_NAME binPath= "`"$SERVICE_EXE`"" start= auto obj= LocalSystem DisplayName= "Eyxa EDR Agent" | Out-Null
if ($LASTEXITCODE -ne 0) { Write-FAIL "sc.exe create failed (exit $LASTEXITCODE)" }
& sc.exe description $SERVICE_NAME "Eyxa Endpoint Detection and Response Agent" | Out-Null
# Source: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-failure
& sc.exe failure $SERVICE_NAME reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Write-OK "Account    : LocalSystem"
Write-OK "Start type : Automatic"
Write-OK "Recovery   : restart on crash x3 (5s delay)"
Write-Done "Service created"

# ── STEP 11: Start service ─────────────────────────────────────────────────
Write-Step 11 "Starting EyxaEDR"
& sc.exe start $SERVICE_NAME | Out-Null
if ($LASTEXITCODE -ne 0) { Write-FAIL "sc.exe start failed (exit $LASTEXITCODE)" }
Write-OK "Start issued"
Write-Done "OK"

# ── STEP 12: Wait for RUNNING ──────────────────────────────────────────────
Write-Step 12 "Waiting for EyxaEDR RUNNING (timeout 30s)"
$elapsed = 0
do {
    Start-Sleep 2; $elapsed += 2
    $state = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
    Write-Dot "$state (${elapsed}s)"
} until ($state -eq "Running" -or $elapsed -ge 30)
if ($state -ne "Running") { Write-FAIL "EyxaEDR did not reach RUNNING in 30s - check Event Viewer > Windows Logs > Application" }
Write-OK "EyxaEDR is RUNNING"
Write-Done "OK"

# ── STEP 13: Register tray + launch ────────────────────────────────────────
# Source: https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
Write-Step 13 "Registering and launching tray application"
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
        -Name "EyxaTray" -Value "`"$TRAY_EXE`"" -Type String -ErrorAction Stop
} catch {
    Write-FAIL "Failed to register tray in Run key: $_"
}
Write-OK "Registered in HKLM Run key"
Start-Process -FilePath $TRAY_EXE -ErrorAction SilentlyContinue
Write-OK "Tray launched"
Write-Done "OK"

# ══════════════════════════════════════════════════════════════════════════════
# FINAL VERIFICATION - check every component and show tick/cross
# ══════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   FINAL VERIFICATION" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Log "VERIFY" "======= Final Verification ======="

$allOK = $true

function Check { param([string]$label, [bool]$ok, [string]$detail = "")
    if ($ok) {
        Write-Host "  [+] $label" -ForegroundColor Green
        Log "VERIFY" "[PASS] $label $detail"
    } else {
        Write-Host "  [X] $label" -ForegroundColor Red
        Log "VERIFY" "[FAIL] $label $detail"
        $script:allOK = $false
    }
}

# 1. EyxaEDR service RUNNING
$svcState = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
Check "EyxaEDR service is RUNNING" ($svcState -eq "Running") "($svcState)"

# 2. SysmonDrv service RUNNING
$sysState = (Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue).Status
Check "SysmonDrv service is RUNNING" ($sysState -eq "Running") "($sysState)"

# 3. All binaries present in install dir
foreach ($f in $REQUIRED) {
    $exists = Test-Path (Join-Path $INSTALL_DIR $f)
    Check "File present: $f" $exists
}

# 4. Data directory exists
Check "Data directory exists: $DATA_DIR" (Test-Path $DATA_DIR)

# 5. Registry keys set
$regOk = $false
try {
    $bu = (Get-ItemProperty -Path $REG_PATH -Name "BackendUrl" -ErrorAction Stop).BackendUrl
    $regOk = (-not [string]::IsNullOrWhiteSpace($bu))
} catch {}
Check "Registry BackendUrl is set" $regOk

$regTok = $false
try {
    $tok = (Get-ItemProperty -Path $REG_PATH -Name "EnrollToken" -ErrorAction Stop).EnrollToken
    $regTok = (-not [string]::IsNullOrWhiteSpace($tok))
} catch {}
Check "Registry EnrollToken is set" $regTok

# 6. Tray app registered in Run key
$trayReg = $false
try {
    $tv = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EyxaTray" -ErrorAction Stop).EyxaTray
    $trayReg = (-not [string]::IsNullOrWhiteSpace($tv))
} catch {}
Check "Tray registered in HKLM Run key" $trayReg

# 7. Tray process running
$trayRunning = ($null -ne (Get-Process -Name "terminator" -ErrorAction SilentlyContinue))
Check "Tray process (terminator.exe) running" $trayRunning

Write-Host "==================================================" -ForegroundColor Cyan

# ── Final summary ──────────────────────────────────────────────────────────
if ($allOK) {
    $finalState = (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue).Status
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "  [+] Eyxa EDR Agent - Installation Complete" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "  Service  : $finalState"                          -ForegroundColor Green
    Write-Host "  Account  : LocalSystem"                          -ForegroundColor Green
    Write-Host "  Binary   : $SERVICE_EXE"                         -ForegroundColor Green
    Write-Host "  Backend  : $backendUrl"                          -ForegroundColor Green
    Write-Host "  Data dir : $DATA_DIR"                            -ForegroundColor Green
    Write-Host "  Log file : $LogFile"                             -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Log "SUCCESS" "All verification checks passed. Installation complete."
} else {
    Write-Host ""
    Write-Host "  [!] Installation completed but some checks FAILED." -ForegroundColor Yellow
    Write-Host "  [!] Review install.log for details." -ForegroundColor Yellow
    Log "WARNING" "Installation finished but one or more verification checks failed."
}

Write-Host ""
Read-Host "Press Enter to close"
