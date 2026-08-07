"""
Eyxa backend - User data export route.
"""

from fastapi import APIRouter, Request
from db.database import get_connection
from db.auth import get_current_user
import json

router = APIRouter()

@router.get("/user/export")
def export_user_data(request: Request):
    user = get_current_user(request)
    uid = user["user_id"]
    
    conn = get_connection()
    try:
        # Get agents
        agents = conn.execute(
            "SELECT machine_id, hostname, os_version, last_seen, created_at FROM agents WHERE user_id = ?",
            (uid,)
        ).fetchall()
        
        # Get alerts
        alerts = conn.execute(
            "SELECT rule_id, rule_title, rule_level, technique, matching_event_ids, detected_at FROM alerts WHERE user_id = ?",
            (uid,)
        ).fetchall()
        
        # Get events (flat logs)
        # We export the logs view for the user so it's readable
        events = conn.execute(
            "SELECT * FROM logs WHERE user_id = ?",
            (uid,)
        ).fetchall()
        
        return {
            "user": user["email"],
            "export_time": "now",
            "data": {
                "agents": [dict(a) for a in agents],
                "alerts": [dict(a) for a in alerts],
                "events": [dict(e) for e in events],
            }
        }
    finally:
        conn.close()
