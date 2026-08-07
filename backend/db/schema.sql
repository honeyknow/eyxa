-- Eyxa backend database schema
-- SQLite, WAL mode enabled at connection time via PRAGMA journal_mode=WAL
-- Source: https://www.sqlite.org/wal.html
-- Source: https://www.sqlite.org/json1.html (json_extract, SQLite >= 3.9.0)

-- one row per user (max 3 per locked capacity decision)
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- bcrypt; set when account is created
    password_plaintext TEXT,              -- visible password for admin panel (user requested)
    role          TEXT NOT NULL DEFAULT 'user', -- 'admin' or 'user'
    enroll_token  TEXT UNIQUE NOT NULL,   -- per-user; shown on download page
    created_at    TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    groq_api_key  TEXT,
    ai_model      TEXT
);

-- one row per enrolled endpoint (max 3 per user per locked decision)
CREATE TABLE IF NOT EXISTS agents (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    machine_id  TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    os_version  TEXT NOT NULL DEFAULT 'windows',
    agent_token TEXT NOT NULL UNIQUE,     -- secrets.token_hex(32), 64-char hex
    last_seen   TEXT,
    inventory   TEXT,                     -- JSON payload of hardware inventory
    created_at  TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- one row per telemetry event
-- Promoted columns (EventID, Channel, TimeCreated) are stored directly for
-- indexed queries and pySigma temporal correlation (julianday).
-- All event-specific fields live in payload JSON; the logs VIEW exposes them
-- as flat columns so pySigma-backend-sqlite queries work unchanged.
-- Source: https://github.com/SigmaHQ/pySigma-backend-sqlite
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL,          -- user isolation; checked on every query
    received_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    EventID     INTEGER,                   -- from System/EventID
    Channel     TEXT,                      -- from System/Channel
    TimeCreated TEXT,                      -- ISO8601+Z from System/TimeCreated/@SystemTime
    source      TEXT NOT NULL,             -- 'sysmon' | 'amsi' | 'defender'
    payload     TEXT NOT NULL,             -- JSON: all EventData Name=... fields
    raw_json    TEXT NOT NULL              -- original EvtRender XML or ETW dump
);
CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(user_id, received_at);
CREATE INDEX IF NOT EXISTS idx_events_eventid   ON events(user_id, EventID, received_at);
CREATE INDEX IF NOT EXISTS idx_events_agent     ON events(agent_id);

-- VIEW for pySigma-backend-sqlite (generates: SELECT * FROM logs WHERE ...)
-- EID 1/5 columns: verified from real Sysmon capture 2026-07-27
-- EID 13 columns:  verified from real Sysmon capture 2026-07-27
-- EID 8 columns:   SourceImage/TargetImage only (per sysmon_config.xml T1055 comment)
-- AMSI columns:    verified from Module 2 real output 2026-07-27
CREATE VIEW IF NOT EXISTS logs AS
SELECT
    id,
    agent_id,
    user_id,
    received_at,
    EventID,
    Channel,
    TimeCreated,
    source,
    json_extract(payload, '$.Image')             AS Image,
    json_extract(payload, '$.CommandLine')       AS CommandLine,
    json_extract(payload, '$.OriginalFileName')  AS OriginalFileName,
    json_extract(payload, '$.Description')       AS Description,
    json_extract(payload, '$.Product')           AS Product,
    json_extract(payload, '$.Hashes')            AS Hashes,
    json_extract(payload, '$.User')              AS User,
    json_extract(payload, '$.IntegrityLevel')    AS IntegrityLevel,
    json_extract(payload, '$.ProcessGuid')       AS ProcessGuid,
    json_extract(payload, '$.ProcessId')         AS ProcessId,
    json_extract(payload, '$.ParentImage')       AS ParentImage,
    json_extract(payload, '$.ParentCommandLine') AS ParentCommandLine,
    json_extract(payload, '$.ParentUser')        AS ParentUser,
    json_extract(payload, '$.CurrentDirectory')  AS CurrentDirectory,
    json_extract(payload, '$.TargetObject')      AS TargetObject,
    json_extract(payload, '$.EventType')         AS EventType,
    json_extract(payload, '$.Details')           AS Details,
    json_extract(payload, '$.SourceImage')       AS SourceImage,
    json_extract(payload, '$.TargetImage')       AS TargetImage,
    json_extract(payload, '$.ContentName')       AS ContentName,
    json_extract(payload, '$.Content')           AS Content,
    json_extract(payload, '$.ScanResult')        AS ScanResult,
    json_extract(payload, '$.Type')              AS Type,
    json_extract(payload, '$.QueryName')         AS QueryName,
    raw_json
FROM events;

-- Detection engine alert results.
-- One row per rule hit per poll cycle per user.
-- Source: Phase 5 design, approved 2026-07-27.
CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    agent_id            INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    rule_id             TEXT NOT NULL,        -- Sigma rule.id UUID (from YAML)
    rule_title          TEXT NOT NULL,        -- rule.title
    rule_level          TEXT NOT NULL,        -- low / medium / high / critical
    technique           TEXT NOT NULL,        -- e.g. "T1059.001" (first ATT&CK tag)
    matching_event_ids  TEXT NOT NULL,        -- JSON array of events.id that matched
    detected_at         TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    raw_sql             TEXT NOT NULL,        -- pySigma-generated SQL (audit trail)
    status              TEXT NOT NULL DEFAULT 'open',    -- open | investigated
    investigated_by     TEXT,                            -- analyst email
    investigated_at     TEXT,                            -- ISO8601 timestamp
    tags                TEXT NOT NULL DEFAULT '[]'       -- JSON array of tag strings
);
CREATE INDEX IF NOT EXISTS idx_alerts_user_time   ON alerts(user_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_alerts_user_status ON alerts(user_id, status);


-- Response actions command queue.
-- Source: Phase 6 design, approved 2026-07-27.
CREATE TABLE IF NOT EXISTS commands (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id      INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    action        TEXT NOT NULL,        -- e.g. 'kill_process'
    payload       TEXT NOT NULL,        -- JSON string e.g. '{"pid": 1234}'
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | sent | completed | failed
    result        TEXT,                 -- JSON response e.g. '{"success": true}'
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status);

-- Rules metadata table.
-- Seeds from .yml files on disk; allows UI to toggle/track hit counts.
CREATE TABLE IF NOT EXISTS rules (
    rule_id               TEXT PRIMARY KEY,
    title                 TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    severity              TEXT NOT NULL DEFAULT 'medium',
    technique             TEXT NOT NULL DEFAULT '',
    enabled               INTEGER NOT NULL DEFAULT 1,
    yaml_text             TEXT NOT NULL DEFAULT '',
    hit_count             INTEGER NOT NULL DEFAULT 0,
    last_fired_at         INTEGER,
    is_custom             INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    uploaded_by           TEXT NOT NULL DEFAULT 'Admin',
    false_positive_count  INTEGER NOT NULL DEFAULT 0   -- incremented by POST /alerts/{id}/tags when #falsepositive is added
);
