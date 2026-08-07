"""
Eyxa backend - Alerts API routes.

GET  /alerts                      : paginated alert list with optional filters
GET  /alerts/{id}                 : single alert by ID
GET  /alerts/{id}/evidence        : structured evidence block (source event + artifacts)
GET  /alerts/correlations         : group alerts into incident chains by host+time window
POST /alerts/{id}/status          : mark alert as investigated or reopen
POST /test/trigger-alert          : inject test event and fire detection (dev/demo only)

All routes require a valid JWT session cookie.
All queries are scoped by user_id for user isolation.
"""

import json
import datetime
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Optional
from db.database import get_connection
from db.auth import get_current_user

router = APIRouter()


def _migrate_alerts_columns() -> None:
    """Add columns to existing alerts tables that pre-date schema changes."""
    conn = get_connection()
    try:
        if not conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'").fetchone():
            return
        cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "status" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
        if "investigated_by" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN investigated_by TEXT")
        if "investigated_at" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN investigated_at TEXT")
        if "tags" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'")
        # Ensure false_positive_count column exists on rules table
        rcols = {r[1] for r in conn.execute("PRAGMA table_info(rules)").fetchall()}
        if "false_positive_count" not in rcols:
            conn.execute("ALTER TABLE rules ADD COLUMN false_positive_count INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    finally:
        conn.close()


_migrate_alerts_columns()


def _user(r: Request) -> dict:
    return get_current_user(r)


def _fmt_alert(row) -> dict:
    """Convert an alerts DB row to the JSON shape the UI expects."""
    event_ids = []
    try:
        event_ids = json.loads(row["matching_event_ids"])
    except Exception:
        pass

    score = {"critical": 9, "high": 7, "medium": 5, "low": 2}.get(
        (row["rule_level"] or "").lower(), 2
    )
    # Safe access to optional columns added by migration
    try:
        status = row["status"] or "open"
    except (IndexError, KeyError):
        status = "open"
    try:
        investigated_by = row["investigated_by"]
    except (IndexError, KeyError):
        investigated_by = None
    try:
        investigated_at = row["investigated_at"]
    except (IndexError, KeyError):
        investigated_at = None

    try:
        tags_raw = row["tags"] or "[]"
    except (IndexError, KeyError):
        tags_raw = "[]"
    try:
        tags = json.loads(tags_raw)
    except Exception:
        tags = []

    return {
        "alert_id":        str(row["id"]),
        "rule_id":         row["rule_id"],
        "rule_name":       row["rule_title"],
        "source_layer":    "sigma",
        "technique_id":    row["technique"] or None,
        "severity_score":  score,
        "raw_event_ref":   None,
        "source_table":    "events",
        "host_id":         None,
        "created_at":      row["detected_at"],
        "suppressed":      False,
        "event_id":        event_ids[0] if event_ids else None,
        "channel":         None,
        "summary":         f"{row['rule_title']} - {row['technique']}",
        "status":          status,
        "investigated_by": investigated_by,
        "investigated_at": investigated_at,
        "tags":            tags,
    }


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------
@router.get("/alerts")
def list_alerts(
    request: Request,
    limit:        int = Query(50, le=500),
    offset:       int = Query(0),
    severity_min: int = Query(0),
    layer:        str = Query(None),
    technique:    str = Query(None),
):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        base   = "FROM alerts WHERE user_id=?"
        params = [uid]

        if technique:
            base += " AND technique LIKE ?"
            params.append(f"%{technique}%")

        # severity_min maps score→level
        if severity_min >= 9:
            base += " AND rule_level='critical'"
        elif severity_min >= 7:
            base += " AND rule_level IN ('critical','high')"
        elif severity_min >= 5:
            base += " AND rule_level IN ('critical','high','medium')"

        total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
        rows  = conn.execute(
            f"SELECT * {base} ORDER BY detected_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

        # Enrich host_id from the first matching event
        alerts = []
        for row in rows:
            a = _fmt_alert(row)
            event_ids = json.loads(row["matching_event_ids"] or "[]")
            if event_ids:
                ev = conn.execute(
                    "SELECT e.*, a.machine_id as host_id FROM events e"
                    " JOIN agents a ON e.agent_id = a.id"
                    " WHERE e.id=? AND e.user_id=?",
                    (event_ids[0], uid)
                ).fetchone()
                if ev:
                    a["host_id"]  = ev["host_id"]
                    a["event_id"] = ev["EventID"]
                    a["channel"]  = ev["Channel"]
                    try:
                        p = json.loads(ev["payload"] or "{}")
                        a["raw_event_ref"] = p.get("ProcessGuid")
                        a["process_chain"] = {
                            "self": {
                                "image": p.get("Image") or p.get("ContentName") or "",
                                "command_line": p.get("CommandLine") or ""
                            }
                        }
                    except Exception:
                        pass
            alerts.append(a)

        return {"total": total, "limit": limit, "offset": offset, "alerts": alerts}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}
# ---------------------------------------------------------------------------
@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, request: Request):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id=? AND user_id=?",
            (int(alert_id), uid)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        a = _fmt_alert(row)
        event_ids = json.loads(row["matching_event_ids"] or "[]")
        if event_ids:
            ev = conn.execute(
                "SELECT e.*, ag.machine_id as host_id FROM events e"
                " JOIN agents ag ON e.agent_id = ag.id"
                " WHERE e.id=? AND e.user_id=?",
                (event_ids[0], uid)
            ).fetchone()
            if ev:
                a["host_id"]  = ev["host_id"]
                a["event_id"] = ev["EventID"]
                a["channel"]  = ev["Channel"]
                try:
                    p = json.loads(ev["payload"] or "{}")
                    a["raw_event_ref"] = p.get("ProcessGuid")
                    a["process_chain"] = {
                        "self": {
                            "image": p.get("Image") or p.get("ContentName") or "",
                            "command_line": p.get("CommandLine") or ""
                        }
                    }
                except Exception:
                    pass
        return a
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /alerts/{alert_id}/evidence
# ---------------------------------------------------------------------------
@router.get("/alerts/{alert_id}/evidence")
def get_alert_evidence(alert_id: str, request: Request):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        alert_row = conn.execute(
            "SELECT * FROM alerts WHERE id=? AND user_id=?",
            (int(alert_id), uid)
        ).fetchone()
        if not alert_row:
            raise HTTPException(status_code=404, detail="Alert not found")

        event_ids = json.loads(alert_row["matching_event_ids"] or "[]")
        source_event = None
        host_id = None
        agent_id = None

        # Pull the primary matching event
        if event_ids:
            ev = conn.execute(
                "SELECT e.*, a.machine_id as host_id FROM events e"
                " JOIN agents a ON e.agent_id = a.id"
                " WHERE e.id=? AND e.user_id=?",
                (event_ids[0], uid)
            ).fetchone()
            if ev:
                source_event = dict(ev)
                host_id = ev["host_id"]
                agent_id = ev["agent_id"]

        # Gather all matching events for process/registry/network artifacts
        artifacts = {}
        if agent_id and event_ids:
            for eid in event_ids:
                ev = conn.execute(
                    # Source: schema.sql - artifacts are in the events table;
                    # the logs VIEW is pySigma-only and has a different column set
                    "SELECT *, "
                    "json_extract(payload,'$.Image') AS Image, "
                    "json_extract(payload,'$.CommandLine') AS CommandLine, "
                    "json_extract(payload,'$.ProcessId') AS ProcessId, "
                    "json_extract(payload,'$.User') AS User, "
                    "json_extract(payload,'$.ParentImage') AS ParentImage, "
                    "json_extract(payload,'$.TargetFilename') AS TargetFilename, "
                    "json_extract(payload,'$.DestinationIp') AS DestinationIp, "
                    "json_extract(payload,'$.DestinationPort') AS DestinationPort, "
                    "json_extract(payload,'$.Protocol') AS Protocol, "
                    "json_extract(payload,'$.TargetObject') AS TargetObject, "
                    "json_extract(payload,'$.Details') AS Details, "
                    "json_extract(payload,'$.EventType') AS EventType, "
                    "json_extract(payload,'$.SourceImage') AS SourceImage, "
                    "json_extract(payload,'$.TargetImage') AS TargetImage "
                    "FROM events WHERE id=? AND user_id=?",
                    (eid, uid)
                ).fetchone()
                if not ev:
                    continue
                ev = dict(ev)
                eid_num = ev.get("EventID")

                if eid_num in (1, 5, 8):  # process create/terminate/injection
                    if "process" not in artifacts: artifacts["process"] = []
                    artifacts["process"].append({
                        "process_image":        ev.get("Image") or ev.get("SourceImage"),
                        "command_line":         ev.get("CommandLine") or ("Injected into: " + str(ev.get("TargetImage") or "Unknown")),
                        "pid":                  ev.get("ProcessId") or ev.get("SourceProcessId"),
                        "user_name":            ev.get("User"),
                        "parent_image":         ev.get("ParentImage"),
                        "timestamp":            ev.get("TimeCreated"),
                    })
                elif eid_num == 3:  # network
                    if "network" not in artifacts: artifacts["network"] = []
                    artifacts["network"].append({
                        "destination_ip":   ev.get("DestinationIp"),
                        "destination_port": ev.get("DestinationPort"),
                        "protocol":         ev.get("Protocol"),
                        "image":            ev.get("Image"),
                        "timestamp":        ev.get("TimeCreated"),
                    })
                elif eid_num in (11, 23):  # file
                    if "file" not in artifacts: artifacts["file"] = []
                    artifacts["file"].append({
                        "target_filename": ev.get("TargetFilename"),
                        "image":           ev.get("Image"),
                        "timestamp":       ev.get("TimeCreated"),
                    })
                elif eid_num in (12, 13, 14):  # registry
                    if "registry" not in artifacts: artifacts["registry"] = []
                    artifacts["registry"].append({
                        "target_object": ev.get("TargetObject"),
                        "details":       ev.get("Details"),
                        "event_type":    ev.get("EventType"),
                        "image":         ev.get("Image"),
                        "timestamp":     ev.get("TimeCreated"),
                    })
                else:
                    # Dynamic fallback for unknown telemetry (e.g. DNS, WMI, Custom)
                    try:
                        cat = ev.get("event_type") or None
                    except Exception:
                        cat = None

                    if not cat:
                        src = ev.get("source")
                        if src == "amsi":
                            cat = "amsi"
                        elif src == "sysmon":
                            if eid_num == 22: cat = "dns"
                            elif eid_num == 25: cat = "tampering"
                            else: cat = f"sysmon_{eid_num}"
                        else:
                            cat = src or "other"
                    cat = cat.lower()
                    
                    if cat not in artifacts:
                        artifacts[cat] = []
                        
                    try:
                        raw_payload = json.loads(ev.get("payload") or "{}")
                        # Add timestamp for consistent rendering
                        raw_payload["_timestamp"] = ev.get("TimeCreated")
                    except Exception:
                        raw_payload = {"_error": "failed to parse payload"}
                    
                    artifacts[cat].append(raw_payload)

        alert_dict = _fmt_alert(alert_row)
        alert_dict["host_id"] = host_id

        return {
            "alert":            alert_dict,
            "source_event":     source_event,
            "root_process_guid": None,
            "host_id":          host_id,
            "process_tree":     {"nodes": [], "edges": [], "alert_guids": []},
            "artifacts":        artifacts,
            "amsi":             [],
            "completeness": {
                "level":                "partial",
                "has_source_event":     source_event is not None,
                "has_process_guid":     False,
                "has_process_node":     False,
                "host_scoped":          host_id is not None,
                "edge_host_scope_complete": False,
                "missing_network":      len(artifacts.get("network", [])) == 0,
                "missing_file":         len(artifacts.get("file", [])) == 0,
                "missing_registry":     len(artifacts.get("registry", [])) == 0,
                "missing_amsi":         True,
                "notes":                [],
            },
            "counts": {k: len(v) for k, v in artifacts.items()},
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /alerts/correlations
# ---------------------------------------------------------------------------
@router.get("/alerts/correlations")
def get_correlations(request: Request, window_seconds: int = Query(300)):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT a.*, ag.machine_id as host_id"
            " FROM alerts a"
            " JOIN agents ag ON a.agent_id = ag.id"
            " WHERE a.user_id=? ORDER BY a.detected_at ASC",
            (uid,)
        ).fetchall()

        chains = []
        current: dict | None = None

        for row in rows:
            host  = row["host_id"]
            ts_str = row["detected_at"]
            try:
                ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                continue

            alert = _fmt_alert(row)
            alert["host_id"] = host

            if current is None:
                current = {"host_id": host, "start": ts_str, "end": ts_str, "alerts": [alert]}
            else:
                last_ts = datetime.datetime.fromisoformat(current["end"].replace("Z", "+00:00"))
                if host == current["host_id"] and (ts - last_ts).total_seconds() <= window_seconds:
                    current["alerts"].append(alert)
                    current["end"] = ts_str
                else:
                    if len(current["alerts"]) > 1:
                        chains.append(current)
                    current = {"host_id": host, "start": ts_str, "end": ts_str, "alerts": [alert]}

        if current and len(current.get("alerts", [])) > 1:
            chains.append(current)

        return {"chains": chains}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /alerts/{alert_id}/status
# ---------------------------------------------------------------------------
class AlertStatusRequest(BaseModel):
    status: str  # "investigated" | "open"


@router.post("/alerts/{alert_id}/status")
def update_alert_status(alert_id: str, body: AlertStatusRequest, request: Request):
    """Mark an alert as investigated or reopen it. Stores analyst identity and timestamp."""
    if body.status not in ("investigated", "open"):
        raise HTTPException(status_code=400, detail="status must be 'investigated' or 'open'")
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id FROM alerts WHERE id=? AND user_id=?",
            (int(alert_id), uid)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        if body.status == "investigated":
            conn.execute(
                "UPDATE alerts SET status=?, investigated_by=?, investigated_at=? WHERE id=? AND user_id=?",
                ("investigated", user["email"],
                 datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                 int(alert_id), uid)
            )
        else:
            conn.execute(
                "UPDATE alerts SET status='open', investigated_by=NULL, investigated_at=NULL WHERE id=? AND user_id=?",
                (int(alert_id), uid)
            )
        conn.commit()
        return {"status": body.status, "alert_id": alert_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /alerts/{alert_id}/tags
# ---------------------------------------------------------------------------
class AlertTagRequest(BaseModel):
    action: str   # "add" | "remove"
    tag: str      # e.g. "#falsepositive"


@router.post("/alerts/{alert_id}/tags")
def update_alert_tags(alert_id: str, body: AlertTagRequest, request: Request):
    """Add or remove a tag from an alert. #falsepositive syncs with rule false_positive_count."""
    if body.action not in ("add", "remove"):
        raise HTTPException(status_code=400, detail="action must be 'add' or 'remove'")
    tag = body.tag.strip().lower()
    if not tag or len(tag) > 64:
        raise HTTPException(status_code=400, detail="Invalid tag")

    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, rule_id, tags FROM alerts WHERE id=? AND user_id=?",
            (int(alert_id), uid)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        try:
            tags = json.loads(row["tags"] or "[]")
        except Exception:
            tags = []

        was_fp = "#falsepositive" in tags

        if body.action == "add" and tag not in tags:
            tags.append(tag)
        elif body.action == "remove" and tag in tags:
            tags.remove(tag)

        is_fp = "#falsepositive" in tags

        conn.execute(
            "UPDATE alerts SET tags=? WHERE id=? AND user_id=?",
            (json.dumps(tags), int(alert_id), uid)
        )

        # Sync false_positive_count on the rule
        rule_id = row["rule_id"]
        if is_fp and not was_fp:
            conn.execute(
                "UPDATE rules SET false_positive_count = false_positive_count + 1 WHERE rule_id=?",
                (rule_id,)
            )
        elif was_fp and not is_fp:
            conn.execute(
                "UPDATE rules SET false_positive_count = MAX(0, false_positive_count - 1) WHERE rule_id=?",
                (rule_id,)
            )

        conn.commit()
        return {"tags": tags, "alert_id": alert_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /test/trigger-alert  (dev/demo)
# ---------------------------------------------------------------------------
@router.post("/test/trigger-alert")
def trigger_test_alert(request: Request):
    """Insert a synthetic PowerShell test event and let the detection engine catch it next poll."""
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        agent = conn.execute(
            "SELECT id FROM agents WHERE user_id=? LIMIT 1", (uid,)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=400, detail="No enrolled agent - cannot inject test event")

        payload = json.dumps({
            "Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand dGVzdA==",
            "User":        "TESTUSER",
        })
        conn.execute(
            "INSERT INTO events (agent_id, user_id, EventID, Channel, TimeCreated, source, payload, raw_json)"
            " VALUES (?,?,?,?,strftime('%Y-%m-%dT%H:%M:%SZ','now'),?,?,?)",
            (agent["id"], uid, 1, "Microsoft-Windows-Sysmon/Operational", "sysmon", payload, "")
        )
        conn.commit()
        return {"status": "injected", "message": "Test event inserted. Detection engine will process it within 30 seconds."}
    finally:
        conn.close()
