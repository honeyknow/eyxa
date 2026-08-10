# Eyxa Backend - Module Documentation

This document outlines the purpose, architecture, and known vulnerabilities of every Python source file within the EDR backend server.

## Overview
The backend is a FastAPI application running on Python 3.11+. It handles agent enrollment, live WebSocket telemetry ingestion, data normalization, Sigma rule evaluation (via pySigma and SQLite), and serves the React dashboard.

## File Index

### 1. `main.py`
- **File Name:** `main.py`
- **Location:** `./main.py`
- **Purpose:** The entry point for the FastAPI server and React SPA host.
- **Simple Explanation:** This is the main script that starts the backend. It tells Python to listen on port 8443, sets up the database, loads all the detection rules, starts the background engine that hunts for malware, and points all the web traffic (like `/api/...` or the dashboard UI) to the right place. 
- **Code Explanation:** Uses `uvicorn` to run a `FastAPI` instance. It configures Cross-Origin Resource Sharing (CORS) middleware, includes API routers from `api/`, and defines a `spa_fallback` route that catches any unmapped URLs (like `/alerts` or `/hunt`) and returns `index.html` or files from the `static/` directory so the React router can take over.
- **Technical Explanation:** It manages the application lifecycle (`@asynccontextmanager`). On startup, it synchronizes Sigma rules from disk into SQLite and spawns the `engine_loop` asyncio background task.
- **Relation with Other Files:** Bootstraps `api/*`, `detection/engine.py`, and `db/database.py`.
- **Known Issues:** Issue 28, Issue 29

### 2. `db/database.py`
- **File Name:** `database.py`
- **Location:** `./db/database.py`
- **Purpose:** Core database connection manager and schema initializer.
- **Simple Explanation:** This file manages all communication with the backend's SQLite database (`eyxa.db`). When the server boots up, this script checks if the database exists; if not, it builds it from scratch (`schema.sql`). It also automatically creates the first administrator account so you can log in to the dashboard.
- **Code Explanation:** It exposes `get_connection()` which creates a new `sqlite3` connection. Crucially, it sets SQLite PRAGMAs (`journal_mode=WAL`, `busy_timeout=5000`) on every connection to prevent "database is locked" errors under heavy multithreaded load. The `init_db()` function applies `schema.sql` and performs dynamic `ALTER TABLE` schema migrations (e.g. adding AI configuration columns).
- **Technical Explanation:** It implements a regex-based `_migrate_logs_view` function that drops and recreates the SQL view `logs` to ensure it is synchronized with the latest `schema.sql`. It also seeds a hardcoded `admin@eyxa` user using `bcrypt`.
- **Relation with Other Files:** Used universally across the backend. Imported heavily by all routes in `api/*` and the detection engine `detection/engine.py`.
- **Known Issues:** Issue 30, Issue 31

### 3. `db/schema.sql`
- **File Name:** `schema.sql`
- **Location:** `./db/schema.sql`
- **Purpose:** Defines the SQL database architecture for the EDR platform.
- **Simple Explanation:** This is the blueprint for the database. It dictates how users, enrolled agent machines, raw telemetry logs, triggered security alerts, and system rules are organized and stored in SQLite.
- **Code Explanation:** It uses standard SQL Data Definition Language (`CREATE TABLE`, `CREATE INDEX`). It explicitly forces a `user_id` foreign key on most tables to support tenant isolation. Crucially, it defines a SQL `VIEW` called `logs` which uses SQLite's `json_extract()` function to parse the raw JSON event payload and expose it as a flat table.
- **Technical Explanation:** The flat `logs` view is the linchpin that allows the `pySigma-backend-sqlite` library to query the database using standard Sigma logic. By offloading JSON parsing to the SQLite engine via `json_extract`, the backend avoids having to load millions of rows into Python memory for evaluation.
- **Relation with Other Files:** Read and executed by `database.py`. The `rules` table is seeded from disk by `api/rules_api.py`.
- **Known Issues:** Issue 32

### 4. `db/auth.py` & `api/auth.py`
- **File Name:** `auth.py`
- **Location:** `./db/auth.py` and `./api/auth.py`
- **Purpose:** Handles user logins, password validation, and issues JSON Web Tokens (JWTs) for API authorization.
- **Simple Explanation:** The bouncer at the club. When you type your email and password into the dashboard, `api/auth.py` checks if they are correct. If so, it gives you a digital wristband (a JWT cookie) created by `db/auth.py`. Every time your browser asks for sensitive data later, `get_current_user` checks if your wristband is still valid.
- **Code Explanation:** `api/auth.py` defines the `/auth/login` and `/auth/logout` endpoints. It uses `bcrypt.checkpw` to validate the password against the database hash. `db/auth.py` uses `python-jose` to encode the user's ID, email, and role into an `HS256` signed JWT, dropping it into an `HttpOnly` cookie.
- **Technical Explanation:** Implements standard cookie-based JWT stateless authentication. It includes an `/auth/impersonate` route that allows an administrator to switch their token's `user_id` to that of a tenant for debugging, while retaining their `admin` role claim to allow them to unimpersonate later.
- **Relation with Other Files:** Heavily relied upon via FastAPI dependency injection (`Depends(get_current_user)`) across all dashboard routes in `api/*`.
- **Known Issues:** Issue 33, Issue 34

### 5. `api/enroll.py`
- **File Name:** `enroll.py`
- **Location:** `./api/enroll.py`
- **Purpose:** Handles new agent registrations (`POST /api/enroll`).
- **Simple Explanation:** The front desk for new endpoints. When an agent starts up for the very first time, it talks to this file using a deployment token. This file checks if the user hasn't exceeded their 3-agent limit, generates a unique 64-character secret token for that specific machine, and saves it.
- **Code Explanation:** It exposes a single FastAPI endpoint that checks `machine_id` against the database to allow idempotent re-enrollments. It uses `secrets.token_hex(32)` to generate a cryptographically secure `agent_token`.
- **Technical Explanation:** Enforces the "locked capacity decision" of exactly 3 agents per user. It prevents noisy re-enrollment collisions by simply returning the existing `agent_token` if a known `machine_id` attempts to register again under the same user.
- **Relation with Other Files:** Receives data from `agent/src/enrollment.c`.
- **Known Issues:** Issue 35

### 6. `api/ingest.py`
- **File Name:** `ingest.py`
- **Location:** `./api/ingest.py`
- **Purpose:** High-throughput JSON telemetry ingest endpoint (`POST /api/ingest`).
- **Simple Explanation:** The cargo bay. Thousands of times a minute, agents send massive arrays of security logs here. This file authenticates the agent using their secret token, unpacks the JSON logs, and saves them into the database so the detection engine can hunt through them.
- **Code Explanation:** Uses FastAPI's `HTTPBearer` dependency to intercept the `Authorization: Bearer <agent_token>` header. It iterates over the array of events, extracts promoted columns (EventID, Channel, TimeCreated), dumps the remaining fields into a `payload` JSON string, and executes an `INSERT` into the SQLite `events` table.
- **Technical Explanation:** Strips internal metadata keys (like `__raw__`) before storage. By scoping every event to the `user_id` fetched from the authenticated token, it guarantees tenant isolation at the data layer. It also automatically updates the `last_seen` timestamp of the agent.
- **Relation with Other Files:** Receives data from `agent/src/sender.c`. Feeds data into the `events` table for `detection/engine.py` to evaluate.
- **Known Issues:** Issue 36

### 7. `detection/engine.py`
- **File Name:** `engine.py`
- **Location:** `./detection/engine.py`
- **Purpose:** The core background loop that evaluates telemetry against Sigma rules to generate alerts.
- **Simple Explanation:** The brain of the EDR. It wakes up every 30 seconds, reads all the security rules (Sigma YAML files), converts them into database queries, and searches the last 30 seconds of telemetry logs for matches. If it finds a match, it generates an alert.
- **Code Explanation:** It defines an `engine_loop()` coroutine that runs continuously in the background of FastAPI. It uses `SigmaCollection` and `sqliteBackend` (from `pySigma`) to translate YAML logic into raw SQL. In `_poll_once()`, it joins these queries with `user_id` filters and time windows, executing them against the database. 
- **Technical Explanation:** It translates abstract Sigma metadata (`logsource.category`) into concrete Sysmon Event IDs (e.g., `process_creation` -> `EID 1`) using the `CATEGORY_EVENTID` map. It extracts the first matching ATT&CK technique tag from the YAML to enrich the resulting `alerts` table row.
- **Relation with Other Files:** Started by `main.py`. Reads rules from `detection/rules/`. Queries `events` and writes to `alerts` and `rules` (hit counts).
- **Known Issues:** Issue 37, Issue 38

### 8. `api/rules_api.py`
- **File Name:** `rules_api.py`
- **Location:** `./api/rules_api.py`
- **Purpose:** Exposes endpoints to manage Sigma detection rules (Upload, Edit, Toggle, Delete).
- **Simple Explanation:** This file powers the "Rules" page on the dashboard. It lets analysts see which rules are active, read their YAML code, turn them off if they are noisy, and upload their own custom threat-hunting rules.
- **Code Explanation:** Exposes standard CRUD operations (`GET`, `PUT`, `POST`, `DELETE`). The `seed_rules_from_disk()` function is called at startup to parse all `.yml` files in the `detection/rules/` folder and insert them into the SQLite database. 
- **Technical Explanation:** It implements the "Ghost Rule flaw" fix by ensuring that any custom rule uploaded via `POST /rules/upload` is physically written to the `detection/rules/` folder, allowing the background engine (which only reads from disk) to pick it up on the next 30-second poll cycle. It calculates complex "noise scores" (false positive ratios) for the UI.
- **Relation with Other Files:** Modifies the `.yml` files in `detection/rules/` and updates the `rules` table, which directly impacts what `engine.py` evaluates.
- **Known Issues:** Issue 39

### 9. `api/responder.py`
- **File Name:** `responder.py`
- **Location:** `./api/responder.py`
- **Purpose:** Handles the persistent Command & Control (C2) WebSocket connections and manual response actions.
- **Simple Explanation:** This is the walkie-talkie connecting the dashboard to the agents. When an agent boots up, it connects to this file over a persistent WebSocket. If an analyst clicks "Kill Process" in the dashboard, the command goes into this file, which immediately radios the agent to execute it.
- **Code Explanation:** It uses FastAPI's `WebSocket` endpoints (`/ws/agent/{agent_token}`). A `CommandManager` class maintains a dictionary mapping `agent_id` to live connections. It exposes REST API endpoints (`POST /api/commands`) to insert commands into the database and push them to the WebSocket instantly.
- **Technical Explanation:** It implements a reliable delivery queue. If an agent is offline when a command is issued, it sits in the `commands` table as `pending`. The moment the agent connects via `/ws/agent/...`, the server fetches all pending commands and drains the queue down the socket. It also broadcasts live telemetry stats from agents directly to the UI via `/ws/dashboard`.
- **Relation with Other Files:** Talks directly to the agent (`ws_client.c` and `responder.c`).
- **Known Issues:** Issue 40

### 10. `api/admin.py`
- **File Name:** `admin.py`
- **Location:** `./api/admin.py`
- **Purpose:** Exposes administrative user management routes.
- **Simple Explanation:** Allows an admin to list all tenants/users and delete them from the database.
- **Code Explanation:** Enforces a strict `_require_admin` dependency that verifies the JWT token contains `"role": "admin"`. Uses SQLite `DELETE FROM users WHERE id = ?`, relying on `ON DELETE CASCADE` in the schema to clean up all associated agents, events, and alerts automatically.

### 11. `api/alerts_api.py`
- **File Name:** `alerts_api.py`
- **Location:** `./api/alerts_api.py`
- **Purpose:** Exposes endpoints for analysts to view and manage security alerts generated by the engine.
- **Simple Explanation:** This provides the data for the "Alerts" dashboard page. It handles searching/filtering alerts, fetching the detailed "evidence" (like what process or IP triggered the alert), grouping related alerts together, and allowing analysts to mark alerts as "investigated".
- **Code Explanation:** Includes a clever `_migrate_alerts_columns` function that runs on import to auto-patch older database schemas. The heavy lifter is `GET /alerts/{id}/evidence`, which extracts the triggering event IDs from the `alerts` table, queries the `events` table for those IDs, and then dynamically extracts JSON payload artifacts (processes, IPs, registry keys) using a combination of `json_extract()` and Python logic.
- **Technical Explanation:** It exposes a `POST /test/trigger-alert` route, intended for dev/demo purposes, which allows injecting a fake "PowerShell execution" event into the `events` table to force an alert to fire.
- **Relation with Other Files:** Reads data generated by `detection/engine.py`.

### 12. `api/hunt.py`
- **File Name:** `hunt.py`
- **Location:** `./api/hunt.py`
- **Purpose:** Exposes threat hunting capabilities and raw telemetry searching.
- **Simple Explanation:** If an analyst wants to dig deeper than an alert, they use this file. It powers the "Timeline" view showing every event on a host chronologically, and allows pivoting (e.g., clicking a process to see everything that process did).
- **Code Explanation:** Generates complex, dynamic SQL queries based on time windows (`since_epoch`, `hours`), cursors (pagination), and `process_guid` filters. 
- **Technical Explanation:** The `GET /timeline` route supports a powerful `direction=initial` mechanism that, given an `alert_id`, fetches the exact triggering event and automatically stitches together the 250 events immediately preceding it and the 250 events following it, creating a seamless context window.
- **Relation with Other Files:** Queries raw `events` data ingested by `ingest.py`.
- **Known Issues:** Issue 41

### 13. `api/admin_api.py`
- **File Name:** `admin_api.py`
- **Location:** `./api/admin_api.py`
- **Purpose:** Extended Admin Panel API for managing users, agents, and viewing system health stats.
- **Simple Explanation:** This file powers the deeper Admin Settings page. It lets the system administrator view CPU/RAM usage, see how big the database is, manually create new tenant accounts, reset passwords, and forcefully revoke/delete compromised agents.
- **Code Explanation:** All routes enforce the `_admin(request)` dependency which checks the `EYXA_ADMIN_EMAIL` role. It uses Python's `psutil` library to pull live host resource metrics for the dashboard. It exposes dangerous actions like `/admin/vacuum` to shrink the SQLite database and `/admin/users/{user_id}/purge` to forcefully wipe a tenant's data.
- **Technical Explanation:** The `POST /admin/allowed-users` route automatically provisions a secure random `enroll_token` using `secrets.token_hex(16)` when a new user is created.
- **Relation with Other Files:** Built on top of `db/auth.py`'s `require_admin` logic.
- **Known Issues:** Issue 42

### 14. `api/ai_api.py`
- **File Name:** `ai_api.py`
- **Location:** `./api/ai_api.py`
- **Purpose:** Integrates LLM capabilities (Groq) for automated alert investigation.
- **Simple Explanation:** This file powers the "AI Investigate" button on alerts. It gathers all telemetry surrounding an alert, shrinks it down so it fits into the AI's "brain" (context window), and asks the AI to write a human-readable forensic report of what happened.
- **Code Explanation:** The `investigate_alert` route fetches the alert and uses the `ProcessGuid` to pull the "blast radius" (all events associated with that process). It applies a YAML schema (`ai_schema.yml`) to strip out noisy JSON keys, hashes the stripped events to deduplicate identical behaviors, and formats them into a dense string `[COUNTx] EID:id | Key: Value`.
- **Technical Explanation:** It uses the `groq` Python library to send the prompt to Llama-3 models. It implements a strict 18,000 character truncation to prevent crashing against Groq's 12k TPM rate limits on free tiers.
- **Relation with Other Files:** Uses the `groq_api_key` and `groq_model` stored via `db/database.py`.
- **Known Issues:** Issue 43, Issue 44

### 15. `api/dashboard.py`
- **File Name:** `dashboard.py`
- **Location:** `./api/dashboard.py`
- **Purpose:** Dashboard overview routes (Stats, Health, and Hosts).
- **Simple Explanation:** This file feeds the main dashboard landing page. It provides the total counts for events and alerts, calculates the health status (e.g., checking if agents have gone offline), and lets a user view/delete their enrolled endpoints.
- **Code Explanation:** It uses basic SQL aggregation (`COUNT(*)`, `GROUP BY`) to bucket telemetry into dynamic categories (Process, Network, File) and calculate severity breakdowns. The health check compares the UTC timestamp of the last received event to the current time, flagging a warning if the lag exceeds 5 minutes.
- **Technical Explanation:** All queries meticulously enforce the `user_id=?` filter, maintaining strict multi-tenant isolation.
- **Relation with Other Files:** Reads broadly from `events`, `alerts`, and `agents` tables.
- **Known Issues:** None found during audit.

### 16. `api/export.py`
- **File Name:** `export.py`
- **Location:** `./api/export.py`
- **Purpose:** User data export.
- **Simple Explanation:** Allows a user to download a complete JSON backup of all their endpoints, alerts, and events.
- **Code Explanation:** Simple `SELECT` queries across the main tables, constrained by `user_id=?`. For events, it exports the `logs` view (which flattens the JSON payload into columns) rather than the raw `events` table, making the export more readable.
- **Technical Explanation:** Fully parameterized and strictly enforces tenant isolation.
- **Relation with Other Files:** Standard CRUD API.
- **Known Issues:** None found during audit.
