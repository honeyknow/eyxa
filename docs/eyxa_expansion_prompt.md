# Eyxa - Expansion Build Directive (builds on the completed Phase 1–9 foundation)

This directive covers: migrating the agent to a fully config-driven, zero-hardcoded-technique architecture; adding telemetry for all 10 new techniques (from `eyxa_10_additional_techniques.md`) alongside the original 5; full system stats collection; and arbitrary remote command execution. Same Ground Rules as the original directive apply (no assumptions, official sources only, execute-and-show-real-output before claiming done, garbage/ folder for throwaway files, ask before any unspecified decision). This document adds the following, specific to this expansion:

## Locked decisions for this expansion

- **Agent does zero filtering/dropping/normalizing/business-logic**, for every source, old and new. It only: reads raw events exactly as the OS/ETW delivers them, buffers them locally, batches them, sends them. All normalization/mapping/field-extraction happens server-side (`backend/normalizer.py`).
- **Two config files, two different natures:**
  - `sysmon.xml` - Sysmon's own official config schema (authored directly by the user; the agent does not generate or modify this file). Controls only which Sysmon Event IDs are enabled - no process/path-based include/exclude conditions.
  - `eyxa.xml` - a new, custom (Eyxa-defined, not an external standard) config file that tells the agent which non-Sysmon Windows Event Log channels and Event IDs to subscribe to. This is what makes adding a future technique's telemetry a config-only change.
- **Generic, config-driven reader (replaces per-source hardcoded reader files):** the agent must have one reusable subscription mechanism that takes a channel name + list of Event IDs (read from `eyxa.xml` at startup, or from Sysmon's own file for the Sysmon channel) and subscribes to it via `EvtSubscribe` - not a separate hardcoded `.c` file/function per source. Adding a new channel/Event ID in the future must require zero agent code changes and zero recompilation - only an `eyxa.xml` edit followed by an agent restart.
- **System stats:** two distinct pieces, not to be conflated -
  - One-time (re-sent only if hardware changes / on reconnect) full hardware inventory: CPU model, GPU model(s), storage devices + serials, network adapters + MAC addresses, total RAM, OS version/build.
  - Continuous live usage stats over the persistent WebSocket connection: CPU load %, RAM used/free, disk I/O/usage %, network throughput.
- **Response actions - expanded scope:** in addition to the existing kill-process/quarantine-file actions, the agent must support arbitrary command execution: server sends a command string over the WebSocket connection, the agent executes it (via `CreateProcess`, capturing stdout/stderr), and returns the raw output exactly as produced - no truncation, no timeout, no output-size cap, per explicit instruction. This significantly expands the security-risk surface of the agent (equivalent to a full remote-command-execution capability) - this must be stated plainly and prominently in `docs/README.md`, not buried, including the specific risk (a compromised agent token/backend becomes a full-control backdoor on every enrolled endpoint) and the accepted reliability caveat (a hung command occupies the command-execution path indefinitely with no automatic recovery, since no timeout was chosen).

---

## Phase A - Design `eyxa.xml` schema

Propose a minimal schema before writing any code. Suggested starting shape (adjust/confirm during implementation, do not treat as final without explicit approval):

```xml
<EyxaConfig>
  <Channel name="Microsoft-Windows-Windows Defender/Operational">
    <EventID>5001</EventID>
  </Channel>
  <Channel name="Security">
    <EventID>1102</EventID>
    <EventID>4698</EventID>
  </Channel>
  <Channel name="Microsoft-Windows-PowerShell/Operational">
    <EventID>4104</EventID>
  </Channel>
</EyxaConfig>
```
Present the finalized schema for approval before Phase B.

## Phase B - Generic multi-channel reader

1. Build the single generic reader module (`agent/src/channel_reader.c` or similar - replaces the separate `defender_reader.c`/`security_reader.c`/`powershell_reader.c` files from the earlier design) that parses `eyxa.xml`, and for each declared channel+Event-ID, opens an `EvtSubscribe` subscription, extracts raw content via `EvtRender`, and pushes to the buffer - with no per-channel special-casing in code.
2. `sysmon_reader.c` is refactored to also use this same generic subscription mechanism (reading Sysmon's enabled Event IDs from `sysmon.xml` at startup, rather than hardcoding EventID checks) - confirm whether `sysmon_reader.c` becomes a thin wrapper around the same generic function, or is merged into it entirely; ask before assuming.
3. Test: enable a new Event ID in `eyxa.xml` only (no code change), restart the agent, trigger that event on the test machine, and show the raw event arriving at the backend - this is the concrete proof that the "config-only, zero-hardcoding" goal is actually met.

## Phase C - Raw capture verification for each new source

For each new channel (Defender EID 5001, Security EID 1102, Security EID 4698, PowerShell EID 4104), repeat exactly what was done for Sysmon EID 1/13 in the original Phase 4: trigger the real event on a test machine, capture the actual raw XML, and record it - do not rely on the documented/assumed formats already drafted in this conversation; verify for real before backend normalization work is built against them.

## Phase D - Backend normalization for all sources

Extend `backend/normalizer.py` to handle every verified raw format from Phase C, plus the existing Sysmon EID 1/8/10/12/13/14/22/25 and AMSI formats, producing the same common-columns + `payload` JSON structure already locked. Extend the `logs` VIEW with `json_extract()` entries for any newly-needed fields, derived from the Sigma rules selected in Phase F below - not speculatively added in advance.

## Phase E - System stats module

1. One-time hardware inventory collector (WMI-based or equivalent - research the current recommended API, don't assume): CPU, GPU, storage + serials, network adapters + MAC, RAM, OS build. Sent once on enrollment/reconnect.
2. Continuous live-usage collector (Performance Counters or equivalent): CPU/RAM/disk/network usage, streamed over the existing WebSocket connection at a defined interval (propose an interval, e.g. 5–10s, and get approval - don't assume).
3. Test: show real captured values from an actual test machine matching what Task Manager / equivalent reports, side by side, as evidence.

## Phase F - Response: arbitrary command execution

1. Extend the existing command-queue/WebSocket delivery mechanism (already built for kill/quarantine) to support a generic `run_command` action carrying an arbitrary command string.
2. Agent executes via `CreateProcess` (research and confirm the correct non-interactive, output-capturing invocation pattern - don't assume flags), captures stdout+stderr as raw bytes, returns them over the WebSocket connection exactly as produced, no modification.
3. No timeout, no output cap - per locked decision. Document the hang-risk caveat in `docs/README.md` as stated above.
4. Add the security-risk disclosure to `docs/README.md` now, not deferred to Phase 9 - this is a standing risk from the moment this feature exists, not just at final documentation time.
5. Test end-to-end with a real command against a real test endpoint, showing the exact raw output returned matches what running the same command locally produces.

## Phase G - Sigma rule selection for the 10 new techniques

Repeat the exact process already used and validated for the original 5 techniques (see the original directive's "Rule Selection & Sysmon Config Derivation" section) for all 10 techniques listed in `eyxa_10_additional_techniques.md`:
1. Pull candidate rules from the official SigmaHQ repository for each technique/sub-technique.
2. Apply the same quality filter (status, level, falsepositives, recency) with per-rule justification - no blanket justifications applied across multiple rules.
3. For any technique where no stable/high rule exists using currently-planned telemetry, explicitly flag it (as was done for T1562/T1685) rather than silently accepting a weaker rule or silently expanding telemetry - ask before adding a new source.
4. Derive exact required fields per rule directly from each rule's real `detection:` block - not from general assumptions about what a category "usually" contains (this was the specific error caught and corrected for the original T1055 rule).

## Phase H - Detection engine extension

Extend the Phase-5 detection engine to load and evaluate all 15 techniques' approved rules (5 original + 10 new) against the `logs` view, using the same 30-second polling design already built. No architecture change expected here beyond loading more rules - confirm this assumption is still true once Phase G's rules are known, and flag if any new rule needs a detection-engine capability not already built (e.g. cross-event correlation beyond single-row matching).

## Phase I - End-to-end validation, all 15 techniques

Same as the original directive's Phase 9: real, safely-triggered simulation of all 15 techniques (research the current standard safe simulation method per technique), real captured alerts as evidence, real measured false-positive/negative behavior reported - not assumed. Include the two new capabilities (system stats accuracy, arbitrary command execution) in this validation pass as well.
