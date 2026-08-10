# Eyxa EDR - Agent Directory Documentation

This file documents the files inside the `agent/` folder, which contains the core C source code and build system for the Windows EDR Agent.

---

## 1. `Makefile`
- **File Name:** `Makefile`
- **Location:** `./Makefile`
- **Purpose:** Drives the MSVC compilation of the Windows agent and its test binaries.
- **Simple Explanation:** A script that tells the Microsoft C compiler how to stitch all our raw C files together into the final `eyxa.exe` program.
- **Code Explanation:** Defines compilation flags for strict warnings (`/WX`), optimization, and includes Windows SDK paths. It contains targets for building the master unity-build `eyxa.exe` from `src/main.c`, as well as 4 isolated test binaries (`test_buffer.exe`, etc.) which output to the `garbage/` folder.
- **Technical Explanation:** Uses standard `nmake` syntax for MSVC. The project relies on a Unity Build pattern (where `main.c` #includes other source files or they are linked explicitly) to produce a monolithic standalone Win32 console executable using the `/SUBSYSTEM:CONSOLE` linker flag and linking core Windows subsystems (Advapi32, Ole32, Wevtapi).
- **Relation with Other Files:** Consumes the C files in `src/`. Expects the `garbage/` directory to exist for build artifacts.
- **Known Issues:** Issue 6, Issue 7

## 2. `src/main.c`
- **File Name:** `main.c`
- **Location:** `./src/main.c`
- **Purpose:** The core entry point and master orchestrator of the Windows EDR Agent (`eyxa.exe`).
- **Simple Explanation:** The main brain of the agent. It starts up all the different sensors (like Sysmon, AMSI, DNS), connects to the server, writes logs, and safely shuts everything down when the service stops.
- **Code Explanation:** Dual-mode execution (Windows Service via `StartServiceCtrlDispatcherW` or interactive console application). It initializes a shared memory IPC block for the system tray icon, boots 9 distinct modules/threads (Enrollment, Buffer, Sender, Sysmon, Channel, AMSI, WebSocket, DNS, Tamper), and enters a wait loop. It also includes heartbeat threads for health reporting and a 24-hour hardware inventory diff thread.
- **Technical Explanation:** Implements a "unity-build" translation unit by directly `#include`-ing all other `.c` module files to simplify the build process and enable aggressive compiler optimization. It heavily relies on the Win32 API for threading (`CreateThread`), synchronization (`CRITICAL_SECTION`, `Interlocked*`), IPC (`CreateFileMappingW`), and token privilege manipulation (`AdjustTokenPrivileges`).
- **Relation with Other Files:** Imports every single module file in `src/`. Acts as the executable produced by `Makefile`.
- **Known Issues:** Issue 8

## 3. `src/buffer.c`
- **File Name:** `buffer.c`
- **Location:** `./src/buffer.c`
- **Purpose:** Manages local durable storage for all EDR telemetry.
- **Simple Explanation:** A crash-proof "save file" mechanism. Before events are sent to the internet, they are saved to disk here. If the machine reboots or the internet drops, no events are lost; they will be sent when connection is restored.
- **Code Explanation:** Implements an append-only log in `C:\ProgramData\Eyxa\eyxa-events.bin` and tracks the network commit position in a companion file `eyxa-cursor.bin`. It serializes JSON events from various reader threads, caps uncommitted memory at 64MB to prevent resource exhaustion during long network outages, and uses `FlushFileBuffers` to guarantee disk persistence on every write.
- **Technical Explanation:** Provides thread-safe, non-volatile buffering (Phase 3 module 3). The cursor update is atomic (via `.tmp` file and `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`) providing robust crash-consistency. Reads are served directly from the disk using `SetFilePointerEx` to decouple the ingestion speed (fast ETW streams) from the egress speed (slow network POSTs).
- **Relation with Other Files:** Consumed by `sender.c`. Written to by all sensor modules (e.g., `sysmon_reader.c`, `amsi_reader.c`) via `main.c` sinks.
- **Known Issues:** Issue 9

## 4. `src/sender.c`
- **File Name:** `sender.c`
- **Location:** `./src/sender.c`
- **Purpose:** Securely transmits batched telemetry to the FastAPI backend over HTTPS.
- **Simple Explanation:** The delivery truck. It wakes up every 30 seconds, scoops up to 500 events from the disk buffer, wraps them in a JSON package, and ships them to the internet using the Windows HTTP API. If the delivery fails, it leaves the events on disk to try again later.
- **Code Explanation:** Runs on a dedicated background thread. Reads batches from `buffer.c`, dynamically constructs a JSON array string containing the raw JSON events and the agent's `machine_id`, and POSTs it to `{backend_url}/api/ingest`. Uses WinHTTP to abstract away system proxies and TLS negotiation. It advances the buffer's commit cursor only when it receives a definitive HTTP 200 OK.
- **Technical Explanation:** Implements guaranteed at-least-once delivery. Adheres to Project Rule 13 by employing aggressive network back-pressure: if a full batch of 500 records is successfully sent, it overrides the 30-second sleep timer and yields for only 50ms before looping instantly, allowing it to drain massive disk backlogs at full network speed. Also handles the `SkipTlsVerify` registry flag by injecting `SECURITY_FLAG_IGNORE_*` options into the WinHTTP request handle prior to transmission.
- **Relation with Other Files:** Reads from `buffer.c`. Uses identity data from `enrollment.c`. Instantiated by `main.c`.
- **Known Issues:** None

## 5. `src/enrollment.c`
- **File Name:** `enrollment.c`
- **Location:** `./src/enrollment.c`
- **Purpose:** Derives endpoint identity and negotiates the cryptographic authentication token with the backend.
- **Simple Explanation:** The onboarding process. When the agent runs for the first time, it grabs the machine's unique Windows ID, securely introduces itself to the server, and receives a VIP pass (the agent token). It saves this pass to disk so it doesn't have to re-register on every reboot.
- **Code Explanation:** Extracts the permanent `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`. If `agent-token.bin` does not exist in `ProgramData`, it constructs a JSON payload containing the hostname and an admin-provided `EnrollToken` (read from the registry), and POSTs it to `/api/enroll`. The returned UUID token is persisted atomically to disk.
- **Technical Explanation:** Enforces strong endpoint identity tracking (Phase 3 module 6). Uses the native WinHTTP API to bypass the need for user logon sessions. To prevent partial writes or race conditions during the initial bootstrap, it saves the token using a robust write-to-temp and atomic rename operation (`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`). It also implements a minimal, zero-allocation JSON string extractor to parse the server's response.
- **Relation with Other Files:** Invoked by `main.c` before any other module starts. Provides the `agent_token` struct used by `sender.c` and `ws_client.c`.
- **Known Issues:** Issue 10

## 6. `src/sysmon_reader.c`
- **File Name:** `sysmon_reader.c`
- **Location:** `./src/sysmon_reader.c`
- **Purpose:** Subscribes to the live Windows Sysmon ETW channel and ingests security events.
- **Simple Explanation:** The eyes of the EDR. It plugs directly into the Windows Event Log system to constantly watch for process creations, network connections, and file modifications generated by Sysmon. It reads them, turns them into raw XML strings, and drops them into the durable disk buffer for shipping.
- **Code Explanation:** Uses the native Windows Event (WEVT) API (`EvtSubscribe`) to attach to the `Microsoft-Windows-Sysmon/Operational` channel using a universal XPath wildcard (`*`). The agent does not filter events; it defers entirely to the XML ruleset loaded inside the Sysmon driver itself. To survive crashes without duplicate ingestion, it atomically maintains an `EvtBookmark` on disk (`sysmon-bookmark.xml`).
- **Technical Explanation:** Implements Phase 3 module 1. The subscription callback runs asynchronously on an OS-managed RPC thread pool. If the log file wraps/rotates while the agent is offline (triggering `ERROR_EVT_QUERY_RESULT_STALE`), the module gracefully catches the failure, deletes the stale bookmark, and cleanly re-subscribes from the tail of the log (`EvtSubscribeToFutureEvents`).
- **Relation with Other Files:** Reads ETW. Yields events to `EyxaBufferAppend` (in `buffer.c`) via the sink interface managed by `main.c`.
- **Known Issues:** Issue 11

## 7. `src/amsi_reader.c`
- **File Name:** `amsi_reader.c`
- **Location:** `./src/amsi_reader.c`
- **Purpose:** Hooks into the Windows Antimalware Scan Interface (AMSI) to intercept in-memory script execution (PowerShell, VBScript).
- **Simple Explanation:** A memory wiretap. Whenever a program like PowerShell tries to run a script, it first asks Windows AMSI if the script is safe. This module eavesdrops on that conversation to capture the raw, unencrypted script content *before* it executes, allowing the EDR to catch heavily obfuscated malware.
- **Code Explanation:** Sets up a Real-Time ETW session listening to the Microsoft AMSI provider (`2A576B87-09A7-520E-C21A-4942F0271D67`). An `EyxaAmsiConsumer` thread continuously pulls events into a memory queue, and an `EyxaAmsiWorker` thread pulls them out. The worker uses `EyxaAmsiProcessGuid` to cross-reference the script's execution time with the Sysmon event log, extracting the Sysmon ProcessGuid to link the script payload directly to its parent process tree.
- **Technical Explanation:** Implements Phase 3 module 2. It utilizes complex multi-threading (consumer/worker pattern) with a 64-event ring buffer to absorb sudden bursts of ETW activity (e.g. from highly layered malware) without dropping frames. It includes logic to gracefully handle dirty shutdowns (re-starting orphaned ETW trace sessions) and parses XML timestamps manually to map AMSI events to Sysmon events within a strict 500ms correlation window.
- **Relation with Other Files:** Invoked by `main.c`. Outputs to `buffer.c` via the sink. Cross-references data generated by `sysmon_reader.c`.
- **Known Issues:** Issue 12

## 8. `src/ws_client.c`
- **File Name:** `ws_client.c`
- **Location:** `./src/ws_client.c`
- **Purpose:** Maintains a persistent WebSocket connection to the backend for live Response Actions and host telemetry.
- **Simple Explanation:** The two-way radio. While the sender quietly ships logs in the background, this module stays constantly connected to the server. It listens for instant commands from the dashboard (like "kill this malware process immediately") and also broadcasts a live pulse (CPU and RAM usage) every 5 seconds so the admin knows the agent is online.
- **Code Explanation:** Uses `WinHttpWebSocketCompleteUpgrade` to establish the connection over the same proxy-aware Windows HTTP stack used by `sender.c`. It runs two threads: a receive thread that waits endlessly for JSON commands (handling WebSocket fragmentation reassembly), and a stats thread that periodically samples `GetSystemTimes` and `GlobalMemoryStatusEx`. 
- **Technical Explanation:** Implements Phase 3 module 5. It includes robust exponential backoff logic (1s -> 60s) to prevent the agent from accidentally DDOSing the backend if it goes down. A `CRITICAL_SECTION` is used specifically to serialize WinHTTP sends, safely allowing the stats thread and the receive thread to share the single socket handle concurrently.
- **Relation with Other Files:** Invoked by `main.c`. Uses the authentication token provided by `enrollment.c`. Relies on `stats.c` for sampling host metrics.
- **Known Issues:** Issue 13, Issue 14

## 9. `src/responder.c`
- **File Name:** `responder.c`
- **Location:** `./src/responder.c`
- **Purpose:** Executes the live Response Action commands received from the dashboard.
- **Simple Explanation:** The muscle of the EDR. When the backend sends a JSON command to "kill process 1234" or "run this command line", this module parses that JSON, executes the raw Windows APIs to terminate the malware, collects the results (or the command output), and formats it back into a JSON response.
- **Code Explanation:** It contains a custom, extremely lightweight JSON string parser (`EyxaJsonGetString`) to avoid bundling heavy third-party libraries. For `kill_process`, it uses `OpenProcess` and `TerminateProcess`. For `run_command`, it spawns a hidden `cmd.exe /c` using `CreateProcessW`, attaches an anonymous pipe to capture standard output and standard error, waits for completion, and then Base64-encodes the entire output to safely transport it over JSON.
- **Technical Explanation:** Implements Phase 6. It runs entirely within the context of the WebSocket receive thread (`ws_client.c` callback). This means it executes synchronously, inherently blocking the WebSocket thread from processing other inbound traffic or keep-alives until the current command completes.
- **Relation with Other Files:** Invoked exclusively by the receive thread of `ws_client.c`.
- **Known Issues:** Issue 15, Issue 16 (Ignored per Rule 20)

## 10. `src/normalizer.c`
- **File Name:** `normalizer.c`
- **Location:** `./src/normalizer.c`
- **Purpose:** Formats raw Sysmon XML and AMSI events into structured JSON payloads for the backend.
- **Simple Explanation:** The translator. Before throwing logs onto the disk buffer, this module takes the complex XML from Sysmon and the raw binary bytes from AMSI, and translates them into clean, universal JSON objects that the server-side detection engine can easily understand.
- **Code Explanation:** It implements string parsing (via `wcschr` and `wcsstr`) to extract XML elements natively without loading heavy XML parsers. It converts wide characters (UTF-16LE) to UTF-8 using `WideCharToMultiByte`, JSON-escapes control characters, identifies integer fields to emit them as JSON numbers (for SQL query compatibility), and generates the final JSON string safely into a fixed-size buffer. 
- **Technical Explanation:** Implements Phase 4. It emits metadata variables (`event_id`, `channel`, `time_created`) into a separate `EYXA_NORM_META` struct so they can be written into indexed database columns by the backend, while wrapping the rest of the fields into the `payload` blob. It also explicitly includes the `__raw__` original XML string for forensic fidelity.
- **Relation with Other Files:** Invoked by `main.c`'s `SysmonSink` and `AmsiSink` before writing to `buffer.c`.
- **Known Issues:** Issue 17, Issue 18

## 11. `src/channel_reader.c`
- **File Name:** `channel_reader.c`
- **Location:** `./src/channel_reader.c`
- **Purpose:** A dynamic, config-driven Windows Event Log (ETW) subscriber.
- **Simple Explanation:** While `sysmon_reader.c` is hardcoded to listen specifically to Sysmon, this module is flexible. It reads an XML config file (`eyxa.xml`), finds a list of extra Event Log channels (like Security, WMI, or PowerShell logs), builds complex queries on the fly, and plugs into them. This allows the EDR to expand its visibility without writing new C code.
- **Code Explanation:** It parses `eyxa.xml` (or auto-detects it in the binary directory) using a lightweight custom string search (`EyxaChParseConfig`). It extracts `<Channel>` blocks, collects the desired `<EventID>`s, formats them into a massive XPath query string (e.g. `*[System[(EventID=1 or EventID=2)]]`), and fires off `EvtSubscribe` for each channel. 
- **Technical Explanation:** Developed as "Expansion Phase B". It utilizes `EvtSubscribeToFutureEvents` exclusively (no bookmarks). It implements graceful shutdown by signaling all subscriptions and waiting for the `EvtClose` block to drain all in-flight asynchronous ETW callbacks cleanly.
- **Relation with Other Files:** Driven by `main.c`. Sends raw XML directly to `buffer.c` (via the same sink interface used by `sysmon_reader.c`).
- **Known Issues:** Issue 19, Issue 20

## 12. `src/dns_reader.c`
- **File Name:** `dns_reader.c`
- **Location:** `./src/dns_reader.c`
- **Purpose:** Captures DNS queries globally across the entire operating system.
- **Simple Explanation:** The network eavesdropper. Instead of trying to inject network hooks or parse packet captures, this module quietly subscribes to the Microsoft-Windows-DNS-Client ETW provider. It sees every domain name that any process tries to resolve, which is incredibly powerful for spotting malware trying to phone home to a Command and Control (C2) server.
- **Code Explanation:** It uses the same Real-Time ETW tracing architecture as the AMSI reader. It starts an `EyxaDNSSession`, enables the provider at the Informational level, and uses a consumer thread to pump events to `DnsEventCallback`. It manually uses the `TdhGetProperty` API to pull out the ProcessId, QueryName, and QueryResults, and rolls its own JSON string escaper (`DnsJsonEscape`).
- **Technical Explanation:** Developed as "A7" (Phase 3). Unlike Sysmon logs which are already rendered as XML by `EvtRender`, this provider emits raw binary ETW trace data. The module uses the Trace Data Helper (TDH) API to parse the binary payload. It deliberately ignores bookmarks because Real-Time ETW sessions do not support them.
- **Relation with Other Files:** Invoked by `main.c`. Pipes JSON output directly into `buffer.c`.
- **Known Issues:** Issue 21, Issue 22

## 13. `src/tamper_watcher.c`
- **File Name:** `tamper_watcher.c`
- **Location:** `./src/tamper_watcher.c`
- **Purpose:** Self-defense mechanism to monitor the EDR's local data directory (`C:\ProgramData\Eyxa`) for tampering.
- **Simple Explanation:** The alarm system. It locks down the folder where the EDR stores its buffer and authentication token, making sure regular users can't delete them. It also watches the folder like a hawk; if malware tries to delete the auth token or drop a malicious script into the directory, it immediately fires off an alert to the backend.
- **Code Explanation:** First, it uses `ConvertStringSecurityDescriptorToSecurityDescriptorW` and `SetNamedSecurityInfoW` to forcefully apply a secure DACL (SYSTEM/Admin full control, Users read-only). Then it spawns a thread running `ReadDirectoryChangesW` to monitor file creations, deletions, and modifications. It parses the `FILE_NOTIFY_INFORMATION` structs, filters for critical events (like `.exe` additions or token deletions), and formats them as JSON alerts using `_snprintf_s`.
- **Technical Explanation:** Implements Phase A9. It utilizes overlapping I/O (`FILE_FLAG_OVERLAPPED`) on the directory handle to allow graceful shutdown without blocking indefinitely on `ReadDirectoryChangesW`. Alerts are emitted as pseudo-ETW JSON payloads (`"EventID": 9999`) and injected directly into the sink for upstream delivery.
- **Relation with Other Files:** Invoked by `main.c`. Pipes JSON output directly into `buffer.c`.
- **Known Issues:** Issue 23, Issue 24

## 14. `src/stats.c`
- **File Name:** `stats.c`
- **Location:** `./src/stats.c`
- **Purpose:** Collects system hardware inventory and live performance metrics (CPU, RAM, Disk, Network).
- **Simple Explanation:** The heart rate monitor. It queries the operating system for the machine's specs (like CPU name, OS version, and hard drive serial numbers) and periodically checks how hard the CPU, disk, and network are working. It formats this data as JSON so the dashboard can display live graphs.
- **Code Explanation:** It uses basic Win32 APIs like `GlobalMemoryStatusEx` and `GetAdaptersAddresses`. For hardware inventory, it reads the Registry and uses `DeviceIoControl` to query the storage driver. For live stats, it uses the Performance Data Helper (PDH) API to query English-localized performance counters (`\Processor Information(_Total)\% Processor Time`).
- **Technical Explanation:** It provides the data payloads for the `ws_client.c` periodic stats thread. It utilizes `RtlGetVersion` directly from `ntdll.dll` to accurately get the OS build (bypassing Windows 10/11 manifest lying).
- **Relation with Other Files:** Invoked exclusively by `ws_client.c` to populate the WebSocket "inventory" and "stats" payloads.
- **Known Issues:** Issue 25, Issue 26

## 15. `src/tray.c`
- **File Name:** `tray.c`
- **Location:** `./src/tray.c`
- **Purpose:** Compiles into `terminator.exe`, the System Tray application that provides real-time agent status to the end user.
- **Simple Explanation:** The UI for the agent. It runs in the user's desktop session, showing a shield icon in the bottom right corner. If the EDR crashes or goes offline, it pops up a warning balloon. It also has a right-click menu to change the server IP or view detailed module health. Finally, it acts as a watchdog: if the background service dies, `terminator.exe` automatically restarts it.
- **Code Explanation:** It uses the Win32 `Shell_NotifyIconW` API for the tray UI. Because it runs in Session 1+ (User) while the agent runs in Session 0 (SYSTEM), they cannot communicate via normal IPC easily. Instead, `tray.c` uses a lock-free "Seqlock" pattern to read a chunk of memory (`Global\EyxaStatusBlock`) continuously updated by the agent. 
- **Technical Explanation:** Developed independently to solve the Session 0 Isolation problem. The "Change Server IP" feature utilizes `ShellExecuteExW` with the `runas` verb to prompt for UAC before spawning an elevated `cmd.exe` to edit `HKLM\SOFTWARE\Eyxa`.
- **Relation with Other Files:** Reads the `EyxaStatusBlock` shared memory written by `shared_status.h` (populated by `main.c`).
- **Known Issues:** Issue 27
