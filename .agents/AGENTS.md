# Eyxa Project - Agent Rules

These rules apply to ALL work on the Eyxa project (c:\product\).
They derive directly from `eyxa_build_prompt.md` and override any
general agent behaviors that would conflict with them.

---

## Rule 1 - Phase and module gates (strict, no exceptions)

- Never proceed to the next phase or the next module within a phase
  until the current one's real output has been shown to the user AND
  the user has explicitly confirmed to proceed.
- For Phase 3 specifically: build ONE module → compile → run → show
  the actual captured output → wait for explicit user approval → THEN
  build the next module.  Never build two modules in one turn.
- "The tests passed" is NOT explicit approval to move on.  Wait for
  the user to say so.

---

## Rule 2 - Design decisions require proposal + approval

- If a design choice (API selection, file format, URL schema, field
  name, config value, JSON structure, registry path) is NOT already
  specified in `eyxa_build_prompt.md`, do NOT implement it.
- Stop, state exactly what decision is needed, give a single reasoned
  proposal citing an official source, and wait for explicit approval
  before writing any code.

---

## Rule 3 - "Done" means verified with real output

- A module is only done when it has been actually compiled, actually
  run on real hardware, and its real output has been captured and
  shown to the user.
- Code that compiles and looks correct is NOT done.
- Never use the words "done", "complete", or "working" for any module
  that has not produced verified real execution output.

---

## Rule 4 - All APIs and paths must be verified against official docs

- Every Windows API, registry path, library name, ETW provider GUID,
  Sysmon event ID, or best practice used must be verified against
  official Microsoft documentation (learn.microsoft.com) at build time.
- Cite the URL in code comments.
- Do not rely on training-knowledge alone for anything that could have
  changed or be wrong.
- Do not use blogs, forum posts, Stack Overflow, or unverified
  third-party sources as authoritative references.

---

## Rule 5 - Garbage folder is mandatory for all test/temp files

- Every temporary, test, or throwaway file must go inside `garbage/`.
- Every file placed in `garbage/` must start with a header comment
  stating: (a) that it is a temporary file, and (b) the specific reason
  and purpose it was created for.
- No test or debug files anywhere inside `agent/`, `backend/`, or
  `dashboard/`.  No exceptions.

---

## Rule 6 - No parallelism between modules or phases

- Never build multiple modules or phases simultaneously, even if the
  implementation appears obvious.
- One module → test → approval → next module.  Always.

---

## Rule 7 - Fixed decisions in eyxa_build_prompt.md are locked

Do not re-propose, re-litigate, or silently deviate from:

- Transport split: HTTPS bulk telemetry / WebSocket for commands + live stats
- Server stack: Python/FastAPI + SQLite (WAL mode) + official SigmaHQ pySigma SQLite backend
- Detection cadence: 30-second polling window
- Response actions: manual only, no autonomous actions
- Multi-tenancy: single DB, tenant isolation via ownership column on every query
- Repository layout: as specified in eyxa_build_prompt.md § Repository structure
- Agent: single `eyxa.exe` binary, single Windows service, all logic as internal threads

---

## Rule 8 - Phase 3 current state (updated as modules are verified)

| Module | File | Status |
|--------|------|--------|
| 1 - Sysmon reader | `agent/src/sysmon_reader.c` | Code written; re-test pending (admin + Sysmon required) |
| 2 - AMSI reader | `agent/src/amsi_reader.c` | **VERIFIED** - PID-to-Sysmon-GUID correlation confirmed (2026-07-27) |
| 3 - Buffer | `agent/src/buffer.c` | **VERIFIED** - 33/33 passed (2026-07-27) |
| 4 - Sender | `agent/src/sender.c` | **VERIFIED** - 3 events POSTed to /api/ingest, HTTP 200 (2026-07-27) |
| 5 - WS client | `agent/src/ws_client.c` | Code written; **NOT DONE** - not yet compiled or run |
| 6 - Enrollment | `agent/src/enrollment.c` | **VERIFIED** - backend POST confirmed; agent_token saved to disk (2026-07-27) |

**Next required step:** Phase 5 engine **VERIFIED** (2026-07-27) -
5/5 rules compiled; T1059.001 alert fired on seeded event.

**Phase 5 remaining:** Real technique simulation required per build prompt §Phase 5 rule 3.
Each rule must fire on a real safely-triggered event before Phase 5 is complete:

| Rule | Technique | Simulation | Status |
|------|-----------|------------|--------|
| `t1059_powershell_encode.yml` | T1059.001 | `powershell -enc <base64>` | **VERIFIED** - alert fired, events=[6] (2026-07-27) |
| `t1036_system_exe_anomaly.yml` | T1036 | Copy powershell.exe outside System32, run it | **VERIFIED** - alert fired, events=[8] (2026-07-27) |
| `t1055_create_remote_thread.yml` | T1055 | Safe CreateRemoteThread test binary | **VERIFIED** - alert fired, events=[11] (2026-07-27) |
| `t1547_asep_reg_modification.yml` | T1547.001 | Write HKCU Run key | **VERIFIED** - alert fired, events=[7] (2026-07-27) |
| `t1685_defender_rtp_disabled.yml` | T1685 | `Set-MpPreference -DisableRealtimeMonitoring $true` | **VERIFIED** - alert fired, events=[10] (2026-07-27) |

**Phase 6 (Response Actions):** **VERIFIED** (2026-07-27) - WebSocket delivery + Win32 TerminateProcess + DB command completion confirmed end-to-end.

**Phase 7 (Production Agent Binary - eyxa.exe):** **VERIFIED** (2026-07-28) -
Full unity-build `eyxa.exe` compiled from `agent/src/main.c` and run as admin.
All 6 modules confirmed running on real hardware:
- Enrollment: POST /api/enroll 200 OK, agent_token saved to disk
- Buffer: ProgramData\Eyxa\eyxa-events.bin open
- Sender: **11 records flushed, HTTP 200** to /api/ingest
- Sysmon reader: EID 1,8,13 subscribed
- AMSI reader: ETW session started
- WebSocket: wss://localhost:8443/ws/agent/<token> connected, response actions active


**Phase 8 (Multi-tenant and admin behavior):** **VERIFIED** (2026-07-28) - APIs implemented; multi-user isolation testing skipped per user instruction (college project scope).

> **HARDENING STATUS (Phase 9 Prep):**
> `HKLM\SOFTWARE\Eyxa\SkipTlsVerify=1` is currently active. While normally a critical failure point in production, this TLS validation requirement has been explicitly **waived** for the college project demo. We will proceed to Phase 9 with it enabled.


---

## Rule 9 - No narration before results

Never write "root cause identified", "violations found", "here is what I
discovered", or any analysis header before executing a fix.  Fix it, run
it, show the output.  One-line summary after.  No exception for this project.

---

## Rule 10 - Every decision must cite an official source

Every API choice, format string, registry path, ETW provider, or protocol
decision in code must have a `// Source: https://...` comment pointing to
the official Microsoft documentation that validates it.  No
training-knowledge-only decisions.  If the official source cannot be found
via web research, stop and say so explicitly - do not guess.

---

## Rule 11 - Garbage rule covers ALL build artifacts

All `.exe`, `.obj`, `.bat`, `.txt`, and any other file produced purely for
building or running tests must land inside `garbage/` - including the `.obj`
files cl.exe emits.  Always pass `/Fo"%GARBAGE%\\"` to cl.exe.

Every file in `garbage/` must start with a header comment that states:
  (a) it is a temporary file, AND
  (b) the specific behavior being tested or the exact reason it was created.
A one-liner is not sufficient - the purpose must be specific enough that
someone reading only the header understands what is being verified.

---

## Rule 12 - Strict "Do Not Code" Policy

Do not write, modify, or refactor any code until the user explicitly says "code it", "go ahead", or otherwise explicitly commands the execution of the proposed solution. Even if an implementation plan is approved, wait for the final verbal trigger before editing files.

---

## Rule 13 - Agent Architecture: Avoid Hardcoded Throttles

Hardcoded sleep timers (like a strict 30s sleep between batches) will inevitably choke high-throughput EDR telemetry and cause massive disk backlogs. Always implement aggressive flushing / network back-pressure (e.g., instantly looping without sleep when a full batch is successfully sent) to drain disk buffers at network speed.

---

## Rule 14 - Strict Terminology: "User" instead of "Tenant"

- Never use the words "tenant" or "tenant_id" in code, comments, documentation, API responses, or architecture discussions.
- The project's isolation model relies entirely on `user_id` as the boundary for data isolation. Always refer to it as "user isolation".

---

## Rule 15 - Temporal Context Anchoring

When building timelines, event context views, or performing temporal correlation around an alert, NEVER use the alert's `detected_at` timestamp as the anchor. `detected_at` represents engine processing time, which may be delayed.

ALWAYS extract the primary keys of the triggering events (from `matching_event_ids`), query the `events` table for those specific logs, and use their true `received_at` or `TimeCreated` timestamps to anchor the time window.

---

## Rule 16 - Phase 12 Docker Context (Completed)

**Working folder:** `c:\product\docker-eyxa\` — This is a clean copy of `eyxa\` dedicated to Docker work. The original `c:\product\eyxa\` folder must NOT be touched during Phase 12.

**Approved design decisions (locked for Phase 12):**

- **Single container** — No separate nginx. The FastAPI backend already serves the built React SPA from `backend/static/`. One Docker image covers both.
- **Multi-stage Dockerfile** — Stage 1: `node:20` image runs `npm ci` + `npm run build` inside `dashboard/`. Stage 2: `python:3.11-slim` copies backend + built static files, installs `requirements.txt`, starts uvicorn.
- **Vite build output** — `vite.config.ts` already sets `outDir: '../backend/static'`. This works correctly in Docker since both `dashboard/` and `backend/` are siblings inside the image build context.
- **Fresh database** — Do NOT copy the existing `eyxa.db` into the image. The backend's `init_db()` auto-creates the schema on first boot. A named Docker volume (`eyxa_db`) is mounted at the `backend/db/` path so data persists across container restarts.
- **TLS** — The existing self-signed `cert.pem` + `key.pem` from `backend/certs/` are copied into the image. `SkipTlsVerify=1` is still active on the agent side. Acceptable for the college project demo.
- **Port** — `8443` exposed for HTTPS (dashboard + API + WebSocket).
- **Files to create:**
  - `docker-eyxa/Dockerfile` — multi-stage build
  - `docker-eyxa/docker-compose.yml` — single-service, named volume, port 8443

**Files that must NOT be created inside `agent/`, `backend/`, or `dashboard/`** — Docker config files go at the root of `docker-eyxa/` only.

**Phase 12 Deployment Verification & Issues Resolved (Aug 2026):**
- **Windows Defender Quarantines:** Defender deleted `eyxa.exe` and `terminator.exe` leading to missing binaries in Git. *Solved:* Recovered via Git history, repacked `eyxa-agent.zip`, and provided `Add-MpPreference -ExclusionPath` for the host machine.
- **CRLF/LF Bug in `install.bat`:** Git checkout on Codespaces converted `install.bat` to LF, breaking `findstr` byte offset file injection. *Solved:* Replaced fragile batch offsets with a robust PowerShell `-replace` script inside the batch file.
- **Dirty Log Files in ZIP:** Repacking the zip globally (`*`) included test logs (`install.log`, `uninstall.log`). *Solved:* Removed logs locally and re-zipped explicitly.
- **Backend Ignoring Disabled Rules:** The detection engine (`engine.py`) spam-alerted on Cloudflare DNS telemetry despite being disabled in UI because the engine didn't query the database's `enabled` flag. *Solved:* Patched `engine.py` to query the SQLite `rules` table before evaluating Sigma rules.
- **Cloudflare Integration:** Added `cloudflared` tunnel directly to `docker-compose.yml` for unified startup.

---

## Rule 17 - Cross-Platform Scripting (CRLF vs LF)

Never use byte-offset dependent logic (like `findstr /b /o`) in Windows `.bat` files for text manipulation if the repository might be cloned in a Linux/Codespaces environment. Git automatically converts `CRLF` to `LF`, breaking offset math. Always use robust PowerShell blocks (e.g., `-replace`) for injecting or modifying text within scripts.

---

## Rule 18 - Strict Database Flag Compliance

When implementing backend engines, evaluation loops, or data processors, ALWAYS explicitly verify `enabled`, `is_active`, or `status` flags from the database. Do not blindly evaluate files from the filesystem without joining or checking their active state in the database (e.g., the `engine.py` bug).

---

## Rule 19 - Dynamic Backend URL Updates (Tray Icon)

When the backend URL changes (e.g., due to a Cloudflare Quick Tunnel restart in Codespaces), the agent must be updated using the Windows Tray Icon (`terminator.exe`), not via manual registry edits or reinstall scripts.

**Standard Operating Procedure:**
1. Right-click the Eyxa tray icon -> select **"Change Server IP..."**.
2. Provide **only the hostname** (e.g., `xyz.trycloudflare.com`). **NEVER** include the `https://` prefix, as the C code automatically prepends it, which would cause a malformed `https://https://` URL.
3. Right-click the Eyxa tray icon -> select **"Restart Agent Service"** to apply the changes.

---

## Rule 20 - Agent Command Execution Architecture (Known Freeze Flaw)

The `run_command` action in `responder.c` executes synchronously on the WebSocket receive thread and relies on a fixed 64KB pipe buffer and a 30-second `WaitForSingleObject` timeout. This causes a Win32 Pipe Deadlock for commands producing large output (e.g., `dir /s C:\`), and freezes the agent's command pipeline for 30 seconds for any long-running command or interactive GUI spawn. This is a known limitation. Do not change this architecture unless explicitly requested to build an asynchronous worker thread fix.

---

## Rule 21 - Session 0 Isolation (GUI Popups)

The agent runs as a Windows Service in Session 0. It is impossible to pop up a visible interactive window on the user's desktop (Session 1) using standard commands due to strict Session 0 Isolation. Do not attempt to bypass this with command string manipulation. If the user explicitly requests the ability to pop interactive GUI windows from the dashboard, it must be implemented via a new `run_interactive` action in `responder.c` using `WTSGetActiveConsoleSessionId` and `CreateProcessAsUserW`.

---

## Rule 22 - The Brutally Honest EDR Expert Persona

When discussing, designing, or brainstorming AI integrations or EDR features:
1. **Never be a yes-man.** Do not blindly agree with the user's proposals. Actively look for flaws, bottlenecks, and naive assumptions in their ideas.
2. **Be brutally honest and critical.** If an idea is generic "AI slop" (e.g., "summarize this log in English"), reject it outright. SOC analysts are professionals who need data structure, deobfuscation, and automated correlation, not bedtime stories.
3. **Contradict and challenge.** Force the user to justify their architectural decisions. Challenge them on rate limits, false positive rates, and workflow friction.
4. **Strict No-Code-Until-Told.** This reinforces Rule 12. During design phases, absolutely NO code shall be written or proposed in artifacts/diffs until the user explicitly says "code it" or gives a definitive green light to a finalized architecture.
