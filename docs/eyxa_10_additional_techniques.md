# Eyxa - Additional 10-Technique Coverage Plan

Ordered by priority: detection value + telemetry feasibility within Eyxa's extendable architecture (Sysmon / AMSI / Defender Operational Log / native Windows Event Log channels, all via the same EvtSubscribe pattern already built). Fileless/LOLBin-heavy techniques prioritized per stated preference; a few high-value non-fileless techniques included where coverage quality justified it.

**Note on confidence**: rule IDs/status below are compiled from established, well-documented SigmaHQ rules and one direct search verification (T1003.001). Per your instruction, this was not re-verified file-by-file this pass - spot-check the specific rule ID/status/falsepositives fields at implementation time the same way Phase 2's original 5 were verified, before enabling any rule in production.

---

## 1. T1003.001 - OS Credential Dumping: LSASS Memory
**Why top priority:** single most common real-world credential-theft technique (Mimikatz, ProcDump, NanoDump all target this); extremely high detection value.
**Sigma rule (verified this session):** *Potential LSASS Process Dump Via ProcDump* - id `5afee48e-67dd-4e03-a783-f74259dcf998`, status `stable`, process-creation based (command-line pattern: dump flags `-ma/-mm/-mp` + lsass marker). No new telemetry source needed.
**Stronger but higher-cost option:** *LSASS Memory Access* pattern rules (process_access category) - catch tool-agnostic LSASS memory access via `GrantedAccess` bitmask (e.g. `0x1010`, `0x1410`, `0x1438`), not just ProcDump specifically. Higher coverage, but requires enabling Sysmon Event ID 10 (ProcessAccess) - a new telemetry source (not currently enabled; explicitly excluded earlier for T1055 scope).
**Telemetry:**
- Baseline (no new source): Sysmon Event ID 1 - fields: `Image`, `CommandLine`
- Stronger (new source): Sysmon Event ID 10 - fields: `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`

---

## 2. T1218.011 / T1218.010 / T1218.005 - System Binary Proxy Execution (Rundll32 / Regsvr32 / Mshta)
**Why high priority:** classic fileless/LOLBin execution - attacker runs malicious code through a signed Microsoft binary, no dropped executable. Very mature detection area, multiple stable rules exist for each.
**Sigma rules:** SigmaHQ has long-standing stable/high rules such as *Suspicious Rundll32 Activity*, *Regsvr32 Anomaly* (the "Squiblydoo" pattern - network-sourced scriptlet via `regsvr32 /i:http...`), and *Mshta Spawning Suspicious Processes* / *HTA Execution via Mshta*.
**Telemetry:** Sysmon Event ID 1 only - fields: `Image`, `CommandLine`, `ParentImage`. No new source needed - same telemetry already powering T1059.001/T1036.

---

## 3. T1053.005 - Scheduled Task
**Why included:** common persistence + fileless execution trigger (`schtasks.exe /create`); pairs naturally with your existing T1547.001 (autorun keys) as the other major persistence vector.
**Sigma rule:** *Scheduled Task Creation* (process-creation based, command-line pattern on `schtasks.exe`) - multiple stable/high variants exist.
**Telemetry:**
- Baseline: Sysmon Event ID 1 - fields: `Image`, `CommandLine`, `ParentImage`
- Richer (new source): native Task Scheduler Operational log, Event ID 4698 (task created) - more structured but requires enabling a new Windows Event Log channel via EvtSubscribe (same pattern as Defender log addition).

---

## 4. T1070.001 - Indicator Removal: Clear Windows Event Logs
**Why included:** extremely high precision - legitimate admins almost never clear logs; near-zero false-positive surface, and a strong "attacker covering tracks" signal.
**Sigma rule:** *Suspicious Eventlog Clearing or Configuration Change Activity* - this exact rule was already surfaced and rejected earlier only because it was competing against a Defender-specific pick for T1562; it stands on its own merit here for T1070.001.
**Telemetry:**
- Baseline (no new source): Sysmon Event ID 1 - command-line detection of `wevtutil cl` / `Clear-EventLog` / `Remove-EventLog`.
- Stronger (new source): Windows Security Event Log, Event ID 1102 ("The audit log was cleared") - direct, unambiguous signal, but requires enabling Security Event Log collection (new source, same EvtSubscribe pattern).

---

## 5. T1055.012 - Process Injection: Process Hollowing
**Why included:** a specific, higher-precision sub-technique of your existing T1055 coverage - hollowing has a more distinctive telemetry signature than generic remote-thread injection.
**Sigma rule:** rules targeting Sysmon Event ID 25 (ProcessTampering - added specifically for hollowing/herpaderping detection in newer Sysmon versions) give the cleanest signal; older rules approximate hollowing via EID 8 CreateRemoteThread + suspicious `StartAddress`.
**Telemetry:**
- Preferred (new source, same channel as existing Sysmon reader): Event ID 25 - fields: `Image`, `TargetImage`, `TamperType`
- Fallback (already-scoped): Event ID 8 - fields already in your `logs` VIEW (`SourceImage`, `TargetImage`)

---

## 6. T1027 - Obfuscated Files or Information
**Why included:** directly complements your existing T1059.001 coverage and AMSI watcher - this technique captures obfuscation patterns broader than just PowerShell (e.g. Base64/certutil-based decode-and-execute chains).
**Sigma rule:** *Suspicious Base64 Encoded PowerShell Command* family and *Certutil Decode* rules - several stable/high options exist depending on exact obfuscation vector chosen.
**Telemetry:** Sysmon Event ID 1 - fields: `Image`, `CommandLine`. Also benefits directly from the AMSI watcher's deobfuscated content (already-approved source, no new work).

---

## 7. T1543.003 - Create or Modify System Process: Windows Service
**Why included:** fileless-adjacent persistence - malicious services created via `sc.exe create` or direct registry write, no dropped installer needed.
**Sigma rule:** *Suspicious Service Creation* family (command-line pattern on `sc.exe create` with unusual binPath, e.g. pointing to `cmd.exe`/`powershell.exe`).
**Telemetry:**
- Baseline: Sysmon Event ID 1 - fields: `Image`, `CommandLine`
- Corroborating: Sysmon Event ID 13 (Registry) on `HKLM\SYSTEM\CurrentControlSet\Services\*` - already-scoped Event ID, just a new key-path filter.

---

## 8. T1071.004 - Application Layer Protocol: DNS
**Why included:** the clearest fileless-malware C2 signal achievable at the endpoint layer - beaconing/tunneling over DNS is a common technique for memory-resident malware with no dropped payload.
**Sigma rule:** DNS-query-based anomaly rules (e.g. high-entropy subdomain patterns, known DNS-tunneling tool query patterns).
**Telemetry:** Sysmon Event ID 22 (DnsQuery) - a new Event ID on the already-existing Sysmon channel (no new source, just enable this ID) - fields: `QueryName`, `QueryResults`, `Image`.
**Caveat:** DNS-anomaly detection is inherently noisier than the others on this list (legitimate software also generates unusual DNS traffic) - expect this one to need the most false-positive tuning of the ten.

---

## 9. T1053 (parent) vs T1053.005 note
Not a separate entry - flagged so the sub-technique tagging in your rules table matches the specific `.005` (Scheduled Task/Job: Scheduled Task) sub-technique, not the broader parent, for MITRE navigator accuracy.

---

## 10. T1218 (parent) sub-technique tagging note
Similarly: tag each of Rundll32/Regsvr32/Mshta with its specific sub-technique ID (`.011`/`.010`/`.005`) rather than the generic `T1218`, for the same navigator-accuracy reason.

---

## Summary: New telemetry sources required beyond current scope

| New source | Needed for | Addition method |
|---|---|---|
| Sysmon Event ID 10 (ProcessAccess) | T1003.001 (stronger option) | New Event ID on existing Sysmon channel |
| Sysmon Event ID 25 (ProcessTampering) | T1055.012 | New Event ID on existing Sysmon channel |
| Sysmon Event ID 22 (DnsQuery) | T1071.004 | New Event ID on existing Sysmon channel |
| Windows Security Event Log (EventID 1102, optionally 4698) | T1070.001 / T1053.005 (stronger options) | New EvtSubscribe channel, same pattern as Defender log |

None of these require new architecture - all fit the existing EvtSubscribe-based reader pattern (`sysmon_reader.c` already handles multiple Event IDs on one channel; a `security_reader.c` would follow the exact same pattern as `defender_reader.c`).

## Recommended build order (highest signal-to-effort first)
1. T1218.011/.010/.005 (LOLBins) - zero new telemetry, mature rules, immediate
2. T1027 (Obfuscation) - zero new telemetry, reuses AMSI
3. T1543.003 (Service creation) - zero new telemetry
4. T1003.001 baseline - zero new telemetry (ProcDump command-line variant)
5. T1070.001 baseline - zero new telemetry (wevtutil command-line variant)
6. T1053.005 baseline - zero new telemetry
7. T1003.001 / T1070.001 / T1053.005 stronger variants - requires new EID10 / Security-log sources
8. T1055.012 - requires Sysmon EID 25
9. T1071.004 - requires Sysmon EID 22, expect highest FP-tuning effort
