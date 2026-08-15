# Official Atomic Red Team Testing Guide

This guide outlines the standard operating procedure for executing automated technique simulations using the `Invoke-AtomicRedTeam` PowerShell framework, monitoring the resulting telemetry, and reviewing the Eyxa database for successful detection.

## 0. The Testing Loop Workflow
For each technique in the table below, we are following this exact, isolated testing loop to ensure clean telemetry capture:

1. **Clear the Database (Optional but recommended):** Ensure `backend/db/eyxa.db` is empty or fresh so alerts from previous tests don't mix.
2. **Execute the Simulation:** Run the test in the VM using: `Invoke-AtomicTest TXXXX`
3. **Wait for Telemetry:** Wait ~45 seconds for the Eyxa agent to batch, send, and process the events.
4. **Isolate the DB:** Copy the populated `eyxa.db` into the `garbage/test dbs/` folder and rename it (e.g., `TXXXX_eyxa.db`).
5. **Log the Results:** Paste the PowerShell output in the chat so the table below can be updated with the exact pass/fail counts and impact analysis.

## 0.1 Useful Commands Cheat Sheet

**Import the Framework (If opening a new PowerShell window):**
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Bypass Execution Policy (Required before running tests):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

**Blind Windows Defender (Run once per VM session if not snapshotted):**
```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionPath $env:TEMP
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

**Download Prerequisites for a specific test with high timeout:**
```powershell
Invoke-AtomicTest TXXXX -GetPrereqs -TimeoutSeconds 600
```



## 1. Running Tests the Official Way

Instead of manually crafting command lines, the official framework automates the execution, dependency resolution, and cleanup. 

> [!NOTE]
> This requires you to have the `Invoke-AtomicTest` PowerShell module installed in your VM environment.

### Step-by-Step Execution
Open a PowerShell session (as Administrator) in your VM and execute the following commands in sequence for any given technique (e.g., `T1003.001`):

1. **Check Prerequisites**: Validates if you have the required tools (e.g., `procdump.exe`, sysinternals, specific registry keys).
   ```powershell
   Invoke-AtomicTest T1003.001 -CheckPrereqs
   ```
2. **Resolve Prerequisites**: Automatically reaches out to the internet to download missing files and payloads to the correct paths.
   ```powershell
   Invoke-AtomicTest T1003.001 -GetPrereqs
   ```
3. **Execute the Simulation**: Runs a specific test (e.g., Test #1). You can omit `-TestNumbers` to run ALL tests under that technique.
   ```powershell
   Invoke-AtomicTest T1003.001 -TestNumbers 1
   ```
4. **Cleanup**: Reverts changes made by the test (e.g., deletes dropped payloads or restores modified registry keys).
   ```powershell
   Invoke-AtomicTest T1003.001 -Cleanup
   ```

## 2. Checking the Eyxa Database

After executing a test, you need to verify that the Eyxa agent successfully captured the telemetry and the detection engine fired an alert.

1. **Wait for Polling**: The agent batches and flushes events every ~30 seconds. Wait approximately 45 seconds after running an Atomic test.
2. **Acquire the DB**: Download or copy `eyxa.db` from the backend server (`backend/db/eyxa.db`).
3. **Run Validation Queries**: Use a SQLite browser (or `sqlite3` CLI) to verify the results:

   **Verify Telemetry (Did the agent see it?):**
   ```sql
   SELECT * FROM events ORDER BY received_at DESC LIMIT 10;
   ```
   **Verify Detection (Did the rule fire?):**
   ```sql
   SELECT a.id, r.title, a.detected_at 
   FROM alerts a 
   JOIN rules r ON a.rule_id = r.id 
   ORDER BY a.detected_at DESC LIMIT 5;
   ```

## 3. Supported Techniques & Test Counts

The following table lists the 15 specific techniques downloaded from the official repository that correspond to Eyxa's Sigma rules, along with the total number of distinct Atomic Tests available for each:

| Technique ID | Technique Name | Official Tests | Status | Failed Tests & Reason | Impact on EDR Validation |
|---|---|---|---|---|---|
| **T1003.001** | LSASS Process Dump | 14 tests total (13 executed) | ✅ **DONE** | **Failed (10 tests)**: Tests 1, 3, 4, 9, 10, 11, 14 (LSA Protection blocked handle). Tests 6, 7, 8 (Missing tools/timeout).<br>**Succeeded (3 tests)**: Tests 2, 12, 13 | **NONE** (Success). EDR rule triggers on the process creation command (which succeeded), not the memory dump itself. Alert fired successfully. |
| **T1027** | Certutil Decode / Obfuscated Files | 11 tests | ⏳ Pending | | |
| **T1036** | System File Execution Location Anomaly | 2 tests total (2 executed) | ✅ **DONE** | **Failed (0 tests)**.<br>**Succeeded (2 tests)**: Tests 1, 2 | **NONE** (Success). Both tests executed cleanly. |
| **T1053.005** | Scheduled Task Creation | 12 tests | ⏳ Pending | | |
| **T1055** | Process Injection / Remote Thread | 13 tests | ⏳ Pending | | |
| **T1055.012** | Process Hollowing | 4 tests total (4 executed) | ✅ **DONE** | **Failed (2 tests)**: Test 1 (PowerShell internal failure), Test 2 (Missing MS Word dependency).<br>**Succeeded (2 tests)**: Tests 3, 4 | **NONE** (Success). The Go implementations successfully hollowed werfault.exe. |
| **T1059.001** | PowerShell Base64 / Encoding | 22 tests | ⏳ Pending | | |
| **T1071.004** | DNS Query Anomaly | 4 tests | ⏳ Pending | | |
| **T1218.005** | MSHTA | 10 tests | ⏳ Pending | | |
| **T1218.010** | Regsvr32 | 5 tests | ⏳ Pending | | |
| **T1218.011** | Rundll32 | 16 tests | ⏳ Pending | | |
| **T1543.003** | Suspicious New Service | 6 tests total (6 executed) | ✅ **DONE** | **Failed (3 tests)**: Test 1 (Target service missing), Test 5 (Conflict with Test 2), Test 6 (Missing cmdlet).<br>**Succeeded (3 tests)**: Tests 2, 3, 4 | **NONE** (Success). The malicious service creations executed successfully via sc.exe and PowerShell. |
| **T1547.001** | Autorun Keys Modification | 20 tests | ⏳ Pending | | |
| **T1685** | Defender / Security Tool Disablement | 77 tests | ⏳ Pending | | |

> [!TIP]
> Technique **T1070.001** (Clear Windows Event Logs) is also supported by Eyxa, but it does not have a dedicated Atomic Red Team script package in the core repository. You can test it natively by running: `wevtutil cl Setup`
