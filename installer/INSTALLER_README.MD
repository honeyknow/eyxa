# Eyxa EDR - Installer Directory Documentation

This file documents the installation and uninstallation scripts for the Eyxa EDR Agent, located in the `installer/` directory.

---

## 1. `install.bat`
- **File Name:** `install.bat`
- **Location:** `./install.bat`
- **Purpose:** Launcher for the installation process.
- **Simple Explanation:** A double-clickable batch file that automatically asks Windows for Administrator permissions (UAC) before launching the real PowerShell installer.
- **Code Explanation:** Uses `fltmc` to check for elevation. If not elevated, it spawns a PowerShell process with `-Verb RunAs` to restart itself as Admin. Once elevated, it calls `install.ps1`.
- **Known Issues:** None.

## 2. `install.ps1`
- **File Name:** `install.ps1`
- **Location:** `./install.ps1`
- **Purpose:** Main installation script for the Windows Agent.
- **Simple Explanation:** This script does the heavy lifting: it creates the `C:\Program Files\Eyxa` and `C:\ProgramData\Eyxa` folders, copies the agent files there, sets up the Windows Service so the agent runs automatically in the background, configures the registry, and installs Sysmon.
- **Code Explanation:** 
  - Validates all required files are present.
  - Prompts the user for the `BackendUrl` and `EnrollToken`.
  - Installs or updates Microsoft Sysmon using `sysmon_config.xml`.
  - Cleans up any old versions of the `EyxaEDR` service.
  - Copies `eyxa.exe`, `terminator.exe`, `Sysmon64.exe`, and configs to the install directory.
  - Writes the configuration to `HKLM\SOFTWARE\Eyxa`. **Critically, it hardcodes `SkipTlsVerify = 1`.**
  - Creates the `EyxaEDR` service running as `LocalSystem`.
  - Adds `terminator.exe` (the tray app) to the `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` key so it starts on user login.
- **Known Vulnerabilities / Security Notes:** 
  - **Insecure Configuration (`SkipTlsVerify`):** The script permanently sets `SkipTlsVerify=1`. In a production environment, this is a critical vulnerability that allows Man-in-the-Middle (MitM) attacks against all agent telemetry and C2 commands. However, project documentation indicates this was explicitly waived for the college project demo environment.

## 3. `uninstall.bat`
- **File Name:** `uninstall.bat`
- **Location:** `./uninstall.bat`
- **Purpose:** Launcher for the uninstallation process.
- **Simple Explanation:** Like `install.bat`, this double-clickable file simply asks for Administrator permissions before launching the real PowerShell uninstaller.
- **Code Explanation:** Identical UAC-bypass pattern to `install.bat`.
- **Known Issues:** None.

## 4. `uninstall.ps1`
- **File Name:** `uninstall.ps1`
- **Location:** `./uninstall.ps1`
- **Purpose:** Aggressive, full-system uninstallation script.
- **Simple Explanation:** Completely scrubs Eyxa and Sysmon from the machine. It stops the background services, deletes the folders, removes the registry keys, and undoes the Windows Defender exclusions.
- **Code Explanation:**
  - Employs resilient `Kill-Process-Loop` and `Remove-Dir-Force` functions. EDR directories often get locked by the OS or antivirus; the script uses `cmd rd`, `takeown`, and `icacls` as fallbacks to ensure the folders are deleted.
  - Removes the `EyxaEDR` and `SysmonDrv` services via `sc.exe`.
  - Scrubs `HKLM\SOFTWARE\Eyxa` and the `EyxaTray` Run key.
  - Removes `Add-MpPreference` exclusions.
- **Known Issues:** None.

## 5. `eyxa.xml`
- **File Name:** `eyxa.xml`
- **Location:** `./eyxa.xml`
- **Purpose:** Configures dynamic ETW channel subscriptions for the agent.
- **Simple Explanation:** Tells the Eyxa agent which non-Sysmon Windows Event Logs it should listen to (e.g. Security logs for cleared logs, PowerShell logs for script blocks).
- **Code Explanation:** Parsed natively by `channel_reader.c`. Instructs the agent to call `EvtSubscribe` for `Security` (EID 1102, 4698), `PowerShell/Operational` (EID 4104), and `Windows Defender/Operational` (EID 5001).

## 6. `sysmon_config.xml`
- **File Name:** `sysmon_config.xml`
- **Location:** `./sysmon_config.xml`
- **Purpose:** Sysmon-specific driver configuration.
- **Simple Explanation:** The ruleset given to Microsoft Sysmon telling it what to record (Process creations, Network DNS queries, Registry edits).
- **Code Explanation:** Extremely minimal configuration that simply enables all telemetry for `ProcessCreate`, `CreateRemoteThread`, `RegistryEvent`, `ProcessTampering`, and `DnsQuery` by using `onmatch="exclude"` with no sub-rules. This results in maximum logging volume.
