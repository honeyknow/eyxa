# Eyxa EDR - Telemetry & Collection Strategy

This document provides a deep dive into **what** telemetry the Eyxa Agent collects from the Windows endpoints, and exactly **why** it is collected, mapped directly to MITRE ATT&CK techniques and our Sigma detection rules.

## Telemetry Collection Summary

| Source | Event Type | Event ID | What We Collect / Filter | Why We Collect It | Mapped Technique |
|---|---|---|---|---|---|
| **Sysmon** | Process Creation | 1 | Newly created processes, focusing on administrative, system, and scripting tools (e.g., `powershell.exe`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`). | To detect execution of malicious scripts (like Base64 encoded PowerShell) and LOLBin abuse (moving legitimate exes to unusual paths). | **T1059.001** (Suspicious Execution of Powershell), **T1036** (System Executable Anomaly) |
| **Sysmon** | Create Remote Thread | 8 | Remote thread creation in other processes, filtering for known injection sources (e.g., `bash.exe`, `msbuild.exe`, `powershell.exe`). | To detect process injection techniques where attackers inject malicious code into legitimate, running processes (like `explorer.exe`) to hide their execution. | **T1055** (Process Injection) |
| **Sysmon** | Registry Event | 12, 13, 14 | Keys/values added, modified, or deleted. Strictly filtered to Autostart Extensibility Points (ASEPs) like `\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `Active Setup`. | To instantly catch persistence mechanisms when malware writes its payload paths to the Registry to survive system reboots. | **T1547.001** (Common Autorun Keys Modification) |
| **AMSI** | Script Content Capture | 1101 | Raw, de-obfuscated script content blocks submitted by script engines (PowerShell, VBScript, Macros) before execution. | To bypass obfuscation/encoding. While Sysmon sees `powershell -enc...`, AMSI captures the decrypted payload. It heavily enriches the Host Timeline for analysts. | Supports **T1059** and general script analysis |
| **Defender** | Operational Logs | 5001 | Alerts from the Defender operational channel indicating that Real-Time Protection (RTP) has been disabled. | Disabling AV is a massive, high-fidelity indicator of a targeted attack or ransomware deployment. | **T1685** (Defender Real-Time Protection Disabled) |

---

## Detailed Philosophy ("Signal vs. Noise")

By tightly coupling our telemetry collection to our specific detection rules (Sigma), we achieve a **high signal-to-noise ratio**. The agent does not collect gigabytes of useless background data. Every row in the table above exists for a specific, actionable reason and is actively evaluated by the backend detection engine every 30 seconds.
