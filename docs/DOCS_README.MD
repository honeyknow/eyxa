# Eyxa EDR - Docs Directory Documentation

This file documents the markdown files located in the `docs/` directory. These files serve as the architectural blueprints, design decisions, and scope limitations for the Eyxa EDR project.

---

## 1. `README.md`
- **File Name:** `README.md`
- **Location:** `./README.md`
- **Purpose:** Security and Reliability Caveats disclosure.
- **Simple Explanation:** A short file that explicitly warns anyone deploying the agent that the `run_command` feature acts as a potential backdoor (Remote Command Execution) and that running heavy commands can freeze the agent.
- **Code Explanation:** Uses GitHub-style markdown alerts (`> [!CAUTION]`) to prominently highlight the RCE surface and the execution hang risk (which corresponds to our recorded audit issues #16 and #46).

## 2. `eyxa_10_additional_techniques.md`
- **File Name:** `eyxa_10_additional_techniques.md`
- **Location:** `./eyxa_10_additional_techniques.md`
- **Purpose:** Planning document for expanding detection coverage.
- **Simple Explanation:** A prioritized list of 10 new hacker techniques (like Process Hollowing or DNS beaconing) that the EDR needs to catch, and exactly which Windows logs are needed to catch them.
- **Code Explanation:** Maps MITRE ATT&CK techniques (e.g., T1003.001 - OS Credential Dumping) to specific SigmaHQ rules and required ETW telemetry channels (e.g., Sysmon Event ID 10, Security Event ID 1102).

## 3. `eyxa_expansion_prompt.md`
- **File Name:** `eyxa_expansion_prompt.md`
- **Location:** `./eyxa_expansion_prompt.md`
- **Purpose:** Engineering specification for the next major build phase.
- **Simple Explanation:** A step-by-step instruction manual (Phases A through I) for migrating the agent from hardcoded log readers to a dynamic, configuration-driven reader (`eyxa.xml`), adding system stats, and implementing the `run_command` action.
- **Code Explanation:** Outlines the strict architectural locked decisions (e.g., agent does zero filtering, just buffering and sending) and the design requirements for the generic `channel_reader.c`.

## 4. `scope_limitations.md`
- **File Name:** `scope_limitations.md`
- **Location:** `./scope_limitations.md`
- **Purpose:** Documentation of accepted security/design tradeoffs.
- **Simple Explanation:** Records deliberate decisions to leave certain features insecure or incomplete for the sake of the college project scope (like tokens not expiring, or TLS being disabled).
- **Code Explanation:** Documents that the `enroll_token` has no expiry (justified because of a 3-endpoint limit), and that `SkipTlsVerify` must eventually be disabled. 
- **Known Issues:** The bottom of this file contains a raw, commented-out batch script snippet (`REG DELETE ...`) which appears to be leftover scratchpad notes.

## 5. `telemetry.md`
- **File Name:** `telemetry.md`
- **Location:** `./telemetry.md`
- **Purpose:** High-level summary of telemetry strategy.
- **Simple Explanation:** A quick reference table showing exactly what data the agent collects (Process creations, Registry edits, AMSI scripts, Defender alerts) and why it collects it (to catch specific malware behaviors).
- **Code Explanation:** Emphasizes the "Signal vs. Noise" philosophy, explaining that the agent avoids collecting gigabytes of useless background data by only subscribing to high-fidelity events.

## 6. `telemetry_architecture.md`
- **File Name:** `telemetry_architecture.md`
- **Location:** `./telemetry_architecture.md`
- **Purpose:** End-to-end technical data flow documentation.
- **Simple Explanation:** Explains the journey of a log from the moment it is generated on a Windows PC, to how it is buffered, sent over the network, processed by the backend, stored in the database, and evaluated by the detection engine.
- **Code Explanation:** Details the mechanics of `buffer.c`, `sender.c` (batching up to 500 records), the FastAPI `/api/ingest` endpoint, and how the SQLite `logs` View uses `json_extract()` to seamlessly feed the `pySigma` detection engine. It also includes a practical troubleshooting guide.
