"""
Eyxa backend - Threat Hunting API routes.

GET /timeline                     : chronological event list for a specific host
GET /amsi                         : paginated AMSI events (detected scripts)
GET /events/{process_guid}        : pivot events tied to a specific process GUID
GET /process-tree                 : stub (returns empty - not yet implemented)

All routes require a valid JWT session cookie.
All queries are scoped by user_id for user isolation.
"""

import json
import datetime
import sqlite3
from fastapi import APIRouter, HTTPException, Query, Request
from db.database import get_connection
from db.auth import get_current_user

router = APIRouter()


def _user(r: Request) -> dict:
    return get_current_user(r)


def _agent_id_for_host(conn, host_id: str, user_id: int):
    row = conn.execute(
        "SELECT id FROM agents WHERE (id=? OR machine_id=?) AND user_id=?",
        (host_id, host_id, user_id)
    ).fetchone()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# GET /timeline
# ---------------------------------------------------------------------------
@router.get("/timeline")
def get_timeline(
    request: Request,
    host_id:     str = Query("all"),
    hours:       int = Query(24),
    since_epoch: int = Query(None),
    alert_id:    int = Query(None),
    cursor:      str = Query(None),
    direction:   str = Query("initial"),
    limit:       int = Query(100),
):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        matching_event_ids = set()
        dt_str = None
        
        if host_id and host_id != "all":
            agent_id = _agent_id_for_host(conn, host_id, uid)
            if not agent_id:
                raise HTTPException(status_code=404, detail="Host not found")
            host_filter = f"AND agent_id={agent_id}"
        else:
            host_filter = ""

        if alert_id:
            alert = conn.execute(
                "SELECT agent_id, detected_at, matching_event_ids FROM alerts WHERE id=? AND user_id=?",
                (alert_id, uid)
            ).fetchone()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            host_filter = f"AND agent_id={alert['agent_id']}"
            try:
                matching_event_ids = set(json.loads(alert["matching_event_ids"] or "[]"))
            except Exception:
                pass
        else:
            # For Firehose: fetch recent alerts to highlight trigger events live.
            recent_alerts = conn.execute(
                "SELECT matching_event_ids FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 200", (uid,)
            ).fetchall()
            for r_al in recent_alerts:
                try:
                    for eid in json.loads(r_al["matching_event_ids"] or "[]"):
                        matching_event_ids.add(eid)
                except Exception:
                    pass
                
        dt = datetime.datetime.utcnow()
        dt_str = dt.isoformat(timespec='seconds') + 'Z'
        
        if matching_event_ids:
            first_id = list(matching_event_ids)[0]
            ev_row = conn.execute("SELECT received_at FROM events WHERE id=? AND user_id=?", (first_id, uid)).fetchone()
            if ev_row and ev_row["received_at"]:
                dt_str = ev_row["received_at"]

        base_query = (
            f"SELECT id, EventID, Channel, TimeCreated, source, payload, received_at, "
            f" CAST(strftime('%s', REPLACE(received_at, 'Z', '')) AS INTEGER) AS epoch"
            f" FROM events"
            f" WHERE user_id=? {host_filter}"
        )

        rows = []
        if direction == "initial" and alert_id and dt_str and matching_event_ids:
            first_id = list(matching_event_ids)[0]
            
            trigger_q = f"{base_query} AND id = {first_id}"
            trigger_ev = conn.execute(trigger_q, (uid,)).fetchall()

            q_after = f"{base_query} AND (received_at > '{dt_str}' OR (received_at = '{dt_str}' AND id > {first_id})) ORDER BY received_at ASC, id ASC LIMIT 250"
            r_after = conn.execute(q_after, (uid,)).fetchall()
            
            q_before = f"{base_query} AND (received_at < '{dt_str}' OR (received_at = '{dt_str}' AND id < {first_id})) ORDER BY received_at DESC, id DESC LIMIT 250"
            r_before = conn.execute(q_before, (uid,)).fetchall()
            
            # r_after is ASC, reverse to DESC. r_before is DESC.
            rows = r_after[::-1] + trigger_ev + r_before
        elif direction == "older":
            if cursor:
                q = f"{base_query} AND received_at < '{cursor}' ORDER BY received_at DESC LIMIT {limit}"
            else:
                q = f"{base_query} ORDER BY received_at DESC LIMIT {limit}"
            rows = conn.execute(q, (uid,)).fetchall()
        elif direction == "newer":
            if cursor:
                q = f"{base_query} AND received_at > '{cursor}' ORDER BY received_at ASC LIMIT {limit}"
            else:
                q = f"{base_query} ORDER BY received_at DESC LIMIT {limit}"
            r_newer = conn.execute(q, (uid,)).fetchall()
            rows = r_newer[::-1]
        else:
            # Fallback
            time_filter = ""
            if since_epoch:
                start_str = datetime.datetime.utcfromtimestamp(since_epoch).isoformat(timespec='seconds') + 'Z'
                time_filter = f"AND received_at >= '{start_str}'"
            else:
                start_str = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat(timespec='seconds') + 'Z'
                time_filter = f"AND received_at >= '{start_str}'"
                
            q = f"{base_query} {time_filter} ORDER BY received_at DESC LIMIT 500"
            rows = conn.execute(q, (uid,)).fetchall()

        events = []
        for r in rows:
            payload = {}
            try:
                payload = json.loads(r["payload"] or "{}")
            except Exception:
                pass

            eid = r["EventID"]
            source = r["source"]
            
            # Derive event_type from EID - safe even if column doesn't exist in older DB
            try:
                event_type = r["event_type"] or None
            except (IndexError, sqlite3.OperationalError):
                event_type = None
            
            if not event_type:
                if source == "amsi":
                    event_type = "amsi"
                elif source == "sysmon":
                    if eid in (1, 5, 8, 10):   event_type = "process"
                    elif eid == 3:              event_type = "network"
                    elif eid in (11, 23):       event_type = "file"
                    elif eid in (12, 13, 14):   event_type = "registry"
                    elif eid == 22:             event_type = "dns"
                    else:                       event_type = f"sysmon_{eid}"
                else:
                    event_type = source or "other"


            image = payload.get("Image") or payload.get("ContentName") or ""
            if not image:
                label = f"EID {eid}"
            else:
                base_image = image.split('\\')[-1]
                label = f"{base_image} (EID {eid})"

            # Ensure UTC parsing in frontend
            raw_ts = r["TimeCreated"] or r["received_at"]
            event_ts = raw_ts.replace(' ', 'T')
            if not event_ts.endswith('Z'):
                event_ts += 'Z'

            events.append({
                "event_type":       event_type,
                "id":               str(r["id"]),
                "label":            label,
                "event_timestamp":  event_ts,
                "raw_json":         r["payload"],
                "severity_score":   None,
                "wazuh_ts_epoch":   r["epoch"],
                "is_alert_trigger": r["id"] in matching_event_ids,
            })

        # Fetch Alerts
        if since_epoch:
            alert_time = f"AND detected_at >= datetime({since_epoch}, 'unixepoch')"
        else:
            alert_time = f"AND detected_at >= datetime('now', '-{hours} hours')"
            
        alerts_rows = conn.execute(
            f"SELECT id, rule_title, rule_level, detected_at, "
            f" CAST(strftime('%s', detected_at) AS INTEGER) AS epoch"
            f" FROM alerts WHERE user_id=? {alert_time}",
            (uid,)
        ).fetchall()

        for ar in alerts_rows:
            if host_id and host_id != "all":
                continue  # skip alert if a specific host is selected (alerts lack direct agent_id)
                
            level = (ar["rule_level"] or "low").lower()
            score = {"critical": 9, "high": 7, "medium": 5, "low": 2}.get(level, 2)
            events.append({
                "event_type":      "alert",
                "id":              f"alert-{ar['id']}",
                "label":           f"ALERT: {ar['rule_title']}",
                "event_timestamp": ar["detected_at"],
                "raw_json":        None,
                "severity_score":  score,
                "wazuh_ts_epoch":  ar["epoch"],
            })

        return {"events": events}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /amsi
# ---------------------------------------------------------------------------
@router.get("/amsi")
def get_amsi(
    request:      Request,
    host_id:      str = Query(None),
    detected_only: bool = Query(False),
    process_guid: str = Query(None),
    limit:        int = Query(50, le=500),
    offset:       int = Query(0),
):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        base = "FROM events WHERE user_id=? AND source='amsi'"
        params = [uid]

        if host_id:
            agent_id = _agent_id_for_host(conn, host_id, uid)
            if agent_id:
                base += " AND agent_id=?"
                params.append(agent_id)

        if detected_only:
            base += " AND json_extract(payload,'$.ScanResult') != '0'"

        if process_guid:
            base += " AND json_extract(payload,'$.ProcessGuid') LIKE ?"
            params.append(f"%{process_guid}%")

        total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
        rows  = conn.execute(
            f"SELECT * {base} ORDER BY received_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

        def _fmt(r) -> dict:
            p = {}
            try:
                p = json.loads(r["payload"] or "{}")
            except Exception:
                pass
            return {
                "pid":            p.get("ProcessId", 0),
                "process_guid":   p.get("ProcessGuid", ""),
                "content_name":   p.get("ContentName", ""),
                "content_hex":    p.get("Content", ""),
                "scan_result":    int(p.get("ScanResult", 0)),
                "host_id":        "",
                "event_timestamp": r["TimeCreated"] or r["received_at"],
            }

        return {
            "total": total, "limit": limit, "offset": offset,
            "events": [_fmt(r) for r in rows],
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /events/{process_guid}
# ---------------------------------------------------------------------------
@router.get("/events/{process_guid}")
def get_pivot_events(
    process_guid: str,
    request:      Request,
    type:         str = Query("process"),
):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        type_filter = {
            "process":  "EventID IN (1, 5)",
            "network":  "EventID = 3",
            "file":     "EventID IN (11, 23)",
            "registry": "EventID = 13",
        }.get(type, "1=1")

        rows = conn.execute(
            f"SELECT * FROM events WHERE user_id=?"
            f" AND json_extract(payload,'$.ProcessGuid') LIKE ?"
            f" AND {type_filter}"
            f" ORDER BY received_at ASC LIMIT 200",
            (uid, f"%{process_guid}%")
        ).fetchall()

        events = []
        for r in rows:
            p = {}
            try:
                p = json.loads(r["payload"] or "{}")
            except Exception:
                pass
            eid = r["EventID"]
            try:
                et = r["event_type"] or None
            except (IndexError, Exception):
                et = None
            if not et:
                et = {
                    1: "process", 5: "process", 8: "process", 10: "process",
                    3: "network", 11: "file", 23: "file",
                    12: "registry", 13: "registry", 14: "registry",
                    22: "dns",
                }.get(eid, r["source"] or "other")
            events.append({**p, "__eid": eid, "__ts": r["TimeCreated"], "event_type": et})

        return {"events": events}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /process-tree
# ---------------------------------------------------------------------------
@router.get("/process-tree")
def get_process_tree(request: Request, root_guid: str = Query(None), host_id: str = Query(None)):
    user = _user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        nodes = {}
        edges = set()
        alert_guids = set()

        def fetch_proc(guid: str):
            if not guid: return None
            row = conn.execute(
                "SELECT payload, TimeCreated, received_at FROM events WHERE user_id=? AND EventID IN (1, 5) AND json_extract(payload,'$.ProcessGuid')=? LIMIT 1",
                (uid, guid)
            ).fetchone()
            if not row: return None
            try:
                p = json.loads(row["payload"] or "{}")
            except Exception:
                p = {}
            return {
                "process_guid": p.get("ProcessGuid", ""),
                "parent_process_guid": p.get("ParentProcessGuid", ""),
                "image": p.get("Image", ""),
                "command_line": p.get("CommandLine", ""),
                "pid": p.get("ProcessId"),
                "user_name": p.get("User", ""),
                "host_id": "",
                "event_timestamp": row["TimeCreated"] or row["received_at"],
            }

        def fetch_children(guid: str):
            if not guid: return []
            rows = conn.execute(
                "SELECT payload, TimeCreated, received_at FROM events WHERE user_id=? AND EventID IN (1, 5) AND json_extract(payload,'$.ParentProcessGuid')=?",
                (uid, guid)
            ).fetchall()
            children = []
            for row in rows:
                try:
                    p = json.loads(row["payload"] or "{}")
                except Exception:
                    p = {}
                children.append({
                    "process_guid": p.get("ProcessGuid", ""),
                    "parent_process_guid": p.get("ParentProcessGuid", ""),
                    "image": p.get("Image", ""),
                    "command_line": p.get("CommandLine", ""),
                    "pid": p.get("ProcessId"),
                    "user_name": p.get("User", ""),
                    "host_id": "",
                    "event_timestamp": row["TimeCreated"] or row["received_at"],
                })
            return children

        if root_guid:
            # Walk UP to find parents (max depth 3)
            current_guid = root_guid
            for _ in range(3):
                proc = fetch_proc(current_guid)
                if not proc: break
                nodes[proc["process_guid"]] = proc
                if proc["parent_process_guid"]:
                    edges.add((proc["parent_process_guid"], proc["process_guid"]))
                    current_guid = proc["parent_process_guid"]
                else:
                    break

            # Walk DOWN to find children (max depth 3)
            queue = [root_guid]
            depths = {root_guid: 0}
            while queue:
                curr = queue.pop(0)
                if depths[curr] >= 3:
                    continue
                children = fetch_children(curr)
                for child in children:
                    cg = child["process_guid"]
                    nodes[cg] = child
                    if child["parent_process_guid"]:
                        edges.add((child["parent_process_guid"], cg))
                    if cg not in depths:
                        depths[cg] = depths[curr] + 1
                        queue.append(cg)

        return {
            "nodes": list(nodes.values()),
            "edges": [{"source": s, "target": t} for s, t in edges],
            "alert_guids": list(alert_guids)
        }
    finally:
        conn.close()
