# Eyxa Telemetry Architecture: End-to-End Flow

This document details how telemetry flows from the endpoint (Windows agent) to the backend database, specifically for the purpose of debugging collection, transmission, or ingestion issues.

## 1. Collection & Buffering (Agent Side)

**What is collected?**
To maintain a high signal-to-noise ratio, the agent specifically targets high-value events mapped to MITRE ATT&CK techniques (as detailed in `telemetry.md`):
*   **Sysmon:**
    *   Event 1 (Process Creation): Focus on admin/scripting tools (`powershell.exe`, `cmd.exe`).
    *   Event 8 (Create Remote Thread): Focus on injection sources.
    *   Event 12, 13, 14 (Registry): Filtered to ASEPs (Run keys).
*   **AMSI:**
    *   Event 1101 (Script Content Capture): Captures de-obfuscated script payloads.
*   **Defender:**
    *   Event 5001: Operational logs indicating RTP (Real-Time Protection) disabled.

**How is it buffered?**
The telemetry events are intercepted, normalized into flat JSON objects (via `normalizer.c`), and written to a durable local buffer (`buffer.c`). This ensures that if the machine goes offline, telemetry is not lost.

## 2. Transmission (Agent Side: `sender.c`)

The agent sends telemetry in batches to the backend via a dedicated sender thread.

*   **Trigger:** A background thread wakes up every 30 seconds (`EYXA_SENDER_INTERVAL_MS`).
*   **Batching:** It reads up to 500 pending records from the buffer (`EYXA_SENDER_BATCH_RECORDS`).
*   **Payload Format:** It constructs a JSON body containing the `machine_id` and the array of pre-serialized JSON event objects:
    ```json
    {
      "machine_id": "<MachineGuid>",
      "events": [
        { "EventID": 1, "Channel": "...", "TimeCreated": "...", "source": "sysmon", "__raw__": "...", ... },
        ...
      ]
    }
    ```
*   **Transport:** 
    *   It uses **WinHTTP** to POST the payload to `https://<backend_url>/api/ingest`.
    *   It authenticates using the header: `Authorization: Bearer <agent_token>`.
    *   TLS verification can be disabled for debugging by setting the registry key `HKLM\SOFTWARE\Eyxa\SkipTlsVerify = 1`.
*   **Reliability:** The buffer cursor is only advanced if the backend returns an HTTP 200 OK. Any network failure or non-200 response leaves the cursor in place, guaranteeing at-least-once delivery on the next attempt.

## 3. Ingestion (Backend Side: `api/ingest.py`)

The backend receives the POST request and persists it to the database.

*   **Endpoint:** `POST /api/ingest` (FastAPI route).
*   **Authentication & User Isolation:** 
    *   Validates the `<agent_token>` against the `agents` table.
    *   Retrieves the `agent_id` and the `user_id` associated with that token. This strictly isolates data to the specific user (`user_id`).
*   **Processing:** For each event in the `events` array:
    *   It extracts promoted meta-columns for fast indexing: `EventID`, `Channel`, `TimeCreated`, and `source`.
    *   It extracts `__raw__` or `raw_json` containing the original XML/ETW string.
    *   The remaining keys are bundled into a `payload` JSON string.
*   **Insertion:** Each event is inserted as a distinct row into the `events` table.
*   **Heartbeat:** The `last_seen` timestamp of the agent is updated in the `agents` table.
*   **Response:** Returns `{"accepted": N}`.

## 4. Storage & Analysis (Backend Side: `db/schema.sql`)

The database is built on SQLite (WAL mode enabled) and is designed to interface directly with the Sigma detection engine.

*   **`events` Table:** Stores the core telemetry.
    *   Columns: `id`, `agent_id`, `user_id`, `received_at`, `EventID`, `Channel`, `TimeCreated`, `source`, `payload` (JSON), `raw_json` (XML).
    *   Indexes: heavily indexed on `(user_id, received_at)` and `(user_id, EventID, received_at)`.
*   **`logs` View:** A virtual table that flattens the `payload` JSON column into distinct SQL columns using SQLite's `json_extract()` (e.g., `json_extract(payload, '$.CommandLine') AS CommandLine`).
    *   *Purpose:* This view (`SELECT * FROM logs`) perfectly mirrors the schema expected by `pySigma-backend-sqlite`. This allows Sigma YAML rules to be seamlessly compiled into SQL queries that run directly against the `logs` view.
*   **`alerts` Table:** When the pySigma backend evaluates rules against the `logs` view, hits are stored in the `alerts` table (recording rule info, technique, and matched event IDs).

## Debugging Guide

If telemetry is not appearing on the dashboard, check the following points in order:

1.  **Agent Network:** Is the agent capable of reaching `https://<backend>/api/ingest`? (Check firewall, proxy, or use `SkipTlsVerify` for local dev).
2.  **Agent Sender Thread:** Is the 30-second interval firing? Check agent local logs for winhttp status codes (if the `event_cb` in `sender.c` writes to a log).
3.  **Backend Ingest Logs:** Are `POST /api/ingest` requests hitting the FastAPI backend? 
    *   If 401: Token mismatch (re-enroll the agent).
    *   If 400: Malformed JSON from `normalizer.c`.
4.  **Database Inspection:** 
    *   Run `SELECT COUNT(*) FROM events WHERE agent_id = X;`
    *   Verify the JSON extraction in the view: `SELECT Image, CommandLine FROM logs LIMIT 5;`
