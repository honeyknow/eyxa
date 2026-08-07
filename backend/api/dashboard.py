"""
Eyxa backend - Dashboard overview routes.

GET /stats         : alert counts, event row counts, severity breakdown
GET /health        : pipeline lag, last event/alert, system warnings
GET /hosts         : list of registered endpoints for current user
DELETE /hosts/{id} : remove endpoint and cascade-delete all its events

All routes require a valid JWT session cookie (get_current_user).
All queries are scoped by user_id for user isolation.
"""

import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from db.database import get_connection
from db.auth import get_current_user

router = APIRouter()


def _user(request: Request) -> dict:
    return get_current_user(request)


# ---------------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------------
@router.get("/stats")
def get_stats(request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        alerts_total = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE user_id=?", (uid,)
        ).fetchone()[0]

        sev = {"crit": 0, "high": 0, "med": 0, "low": 0}
        for row in conn.execute(
            "SELECT rule_level, COUNT(*) AS cnt FROM alerts WHERE user_id=? GROUP BY rule_level",
            (uid,)
        ):
            lvl = row["rule_level"].lower()
            if lvl == "critical":   sev["crit"] += row["cnt"]
            elif lvl == "high":     sev["high"] += row["cnt"]
            elif lvl == "medium":   sev["med"]  += row["cnt"]
            else:                   sev["low"]  += row["cnt"]

        events_total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE user_id=?", (uid,)
        ).fetchone()[0]

        def count_eid(eid: int) -> int:
            return conn.execute(
                "SELECT COUNT(*) FROM events WHERE user_id=? AND EventID=?",
                (uid, eid)
            ).fetchone()[0]

        last_alert_row = conn.execute(
            "SELECT detected_at FROM alerts WHERE user_id=? ORDER BY detected_at DESC LIMIT 1",
            (uid,)
        ).fetchone()
        last_alert = last_alert_row["detected_at"] if last_alert_row else None

        # Dynamic telemetry mix
        mix_rows = conn.execute(
            "SELECT source, EventID, COUNT(*) as cnt FROM events WHERE user_id=? GROUP BY source, EventID",
            (uid,)
        ).fetchall()
        
        mix_buckets = {}
        for r in mix_rows:
            src = r["source"]
            eid = r["EventID"]
            cnt = r["cnt"]
            
            if src == "amsi":
                cat = "AMSI"
            elif src == "dns":
                cat = "DNS"
            elif src == "sysmon":
                if eid in (1, 5, 8, 10):   cat = "Process"
                elif eid == 3:             cat = "Network"
                elif eid in (11, 23):      cat = "File"
                elif eid in (12, 13, 14):  cat = "Registry"
                elif eid == 22:            cat = "DNS"
                else:                      cat = f"Sysmon (EID {eid})"
            else:
                cat = src.capitalize() if src else "Other"
                
            mix_buckets[cat] = mix_buckets.get(cat, 0) + cnt
            
        # Format for frontend array
        dynamic_mix = [{"category": k, "count": v} for k, v in sorted(mix_buckets.items(), key=lambda x: x[1], reverse=True)]

        return {
            "row_counts": {
                "events":          events_total,
                "alerts":          alerts_total,
            },
            "dynamic_mix": dynamic_mix,
            "severity_counts": sev,
            "last_alert": last_alert,
            "utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------
@router.get("/health")
def get_health(request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        last_ev = conn.execute(
            "SELECT received_at, EventID, Channel FROM events WHERE user_id=? ORDER BY received_at DESC LIMIT 1",
            (uid,)
        ).fetchone()

        last_al = conn.execute(
            "SELECT detected_at, rule_title FROM alerts WHERE user_id=? ORDER BY detected_at DESC LIMIT 1",
            (uid,)
        ).fetchone()

        lag = None
        warnings = []
        if last_ev:
            try:
                ts = datetime.datetime.fromisoformat(last_ev["received_at"].replace("Z", "+00:00"))
                lag = int((datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds())
                if lag > 300:
                    warnings.append(f"No events in the last {lag // 60} minutes - agent may be offline")
            except Exception:
                pass

        agent_count = conn.execute(
            "SELECT COUNT(*) FROM agents WHERE user_id=?", (uid,)
        ).fetchone()[0]
        if agent_count == 0:
            warnings.append("No endpoints enrolled - deploy the agent to start receiving telemetry")

        status = "empty" if not last_ev else ("degraded" if lag and lag > 300 else "healthy")

        return {
            "status": status,
            "db_exists": True,
            "utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pipeline": {"events": 0},
            "last_event": dict(last_ev) if last_ev else None,
            "last_alert": dict(last_al) if last_al else None,
            "lag_seconds": lag,
            "warnings": warnings,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /hosts
# ---------------------------------------------------------------------------
@router.get("/hosts")
def get_hosts(request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, machine_id, hostname, last_seen, created_at, inventory FROM agents WHERE user_id=? ORDER BY last_seen DESC",
            (uid,)
        ).fetchall()
        return {
            "hosts": [
                {
                    "agent_id":     row["id"],
                    "host_id":      row["machine_id"],
                    "pc_name":      row["hostname"],
                    "registered_at": row["created_at"],
                    "last_seen":    row["last_seen"],
                    "inventory":    row["inventory"],
                }
                for row in rows
            ]
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /hosts/{host_id}
# ---------------------------------------------------------------------------
@router.delete("/hosts/{host_id}")
def delete_host(host_id: str, request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        agent = conn.execute(
            "SELECT id FROM agents WHERE machine_id=? AND user_id=?",
            (host_id, uid)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Host not found")
        conn.execute("DELETE FROM agents WHERE machine_id=? AND user_id=?", (host_id, uid))
        conn.commit()
        return {"status": "deleted", "host_id": host_id}
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# DELETE /hosts/{host_id}/purge
# ---------------------------------------------------------------------------
@router.delete("/hosts/{host_id}/purge")
def purge_host(host_id: str, request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        agent = conn.execute(
            "SELECT id FROM agents WHERE machine_id=? AND user_id=?",
            (host_id, uid)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Host not found")
        aid = agent["id"]
        conn.execute("DELETE FROM events WHERE user_id=? AND agent_id=?", (uid, aid))
        conn.execute("DELETE FROM alerts WHERE user_id=? AND agent_id=?", (uid, aid))
        conn.execute("DELETE FROM commands WHERE user_id=? AND agent_id=?", (uid, aid))
        conn.commit()
        return {"status": "purged", "host_id": host_id}
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# GET /hosts/{host_id}/revoke
# ---------------------------------------------------------------------------
@router.get("/hosts/{host_id}/revoke")
def revoke_host(host_id: str, request: Request):
    user = _user(request)
    uid = user["user_id"]
    conn = get_connection()
    try:
        agent = conn.execute(
            "SELECT id FROM agents WHERE machine_id=? AND user_id=?",
            (host_id, uid)
        ).fetchone()
        if not agent:
            raise HTTPException(status_code=404, detail="Host not found")
        conn.execute("UPDATE agents SET agent_token='REVOKED' WHERE machine_id=? AND user_id=?", (host_id, uid))
        conn.commit()
        return {"status": "revoked", "host_id": host_id}
    finally:
        conn.close()
