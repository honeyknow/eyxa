"""
Eyxa backend - Admin Panel API routes.

GET    /admin/users                   : list all users with agent counts
DELETE /admin/users/{id}              : purge a user and all their data
GET    /admin/agents/{agent_id}/revoke  : revoke a specific agent
DELETE /admin/agents/{agent_id}         : admin hard-delete an agent
GET    /admin/allowed-users             : list all users in the system
POST   /admin/allowed-users             : add a new user with password
DELETE /admin/allowed-users/{email}     : remove a user account

All routes require admin role (EYXA_ADMIN_EMAIL env var).
"""

import bcrypt
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional
from db.database import get_connection
from db.auth import require_admin

router = APIRouter()


def _admin(r: Request) -> dict:
    return require_admin(r)





# ---------------------------------------------------------------------------
# GET /admin/agents/{agent_id}/revoke
# ---------------------------------------------------------------------------
@router.get("/admin/agents/{agent_id}/revoke")
def revoke_agent(agent_id: str, request: Request):
    _admin(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM agents WHERE id=?", (int(agent_id),)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent not found")
        # Mark as revoked by deleting the token so it can no longer ingest
        conn.execute("UPDATE agents SET agent_token='REVOKED' WHERE id=?", (int(agent_id),))
        conn.commit()
        return {"status": "revoked", "agent_id": agent_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /admin/stats
# ---------------------------------------------------------------------------
@router.get("/admin/stats")
def admin_stats(request: Request):
    _admin(request)
    import psutil
    import os
    
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    
    import pathlib
    db_path = pathlib.Path(__file__).parent.parent / "db" / "eyxa.db"
    db_size = os.path.getsize(db_path) / (1024 * 1024) if os.path.exists(db_path) else 0
    
    conn = get_connection()
    try:
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    finally:
        conn.close()
        
    return {
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "ram_used_gb": round(mem.used / (1024**3), 2),
        "ram_total_gb": round(mem.total / (1024**3), 2),
        "db_size_mb": round(db_size, 2),
        "events": events,
        "alerts": alerts
    }


# ---------------------------------------------------------------------------
# DELETE /admin/agents/{agent_id}
# ---------------------------------------------------------------------------
@router.delete("/admin/agents/{agent_id}")
def delete_agent(agent_id: str, request: Request):
    _admin(request)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM agents WHERE id=?", (int(agent_id),))
        conn.commit()
        return {"status": "deleted", "agent_id": agent_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /admin/agents/{agent_id}/purge
# ---------------------------------------------------------------------------
@router.delete("/admin/agents/{agent_id}/purge")
def admin_purge_agent(agent_id: str, request: Request):
    _admin(request)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM events WHERE agent_id=?", (int(agent_id),))
        conn.execute("DELETE FROM alerts WHERE agent_id=?", (int(agent_id),))
        conn.commit()
        return {"status": "purged", "agent_id": agent_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /admin/vacuum
# ---------------------------------------------------------------------------
@router.post("/admin/vacuum")
def vacuum_database(request: Request):
    _admin(request)
    conn = get_connection()
    try:
        conn.execute("VACUUM")
        conn.commit()
        return {"status": "vacuumed"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /admin/allowed-users  (all user accounts)
# ---------------------------------------------------------------------------
@router.get("/admin/allowed-users")
def list_allowed_users(request: Request):
    _admin(request)
    conn = get_connection()
    try:
        users = conn.execute(
            "SELECT id, email, created_at, role, password_plaintext FROM users ORDER BY created_at DESC"
        ).fetchall()
        
        agents = conn.execute("SELECT id, user_id, hostname, agent_token FROM agents").fetchall()
        
        result = []
        for u in users:
            u_agents = [
                {
                    "agent_id": str(a["id"]),
                    "hostname": a["hostname"],
                    "agent_token": a["agent_token"]
                }
                for a in agents if a["user_id"] == u["id"]
            ]
            result.append({
                "id": u["id"],
                "email": u["email"],
                "role": u["role"],
                "password_plaintext": u["password_plaintext"] or "",
                "added_at": u["created_at"],
                "agents": u_agents,
                "agent_count": len(u_agents),
            })
        return result
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /admin/allowed-users  (create new user account)
# ---------------------------------------------------------------------------
class AddUserRequest(BaseModel):
    email:    str
    password: Optional[str] = None
    note:     Optional[str] = None


@router.post("/admin/allowed-users")
def add_user(body: AddUserRequest, request: Request):
    _admin(request)
    email = body.email.strip().lower()
    password = body.password or "ChangeMe123!"

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    import secrets
    enroll_token = secrets.token_hex(16)

    conn = get_connection()
    try:
        existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="User already exists")
        conn.execute(
            "INSERT INTO users (email, password_hash, enroll_token) VALUES (?,?,?)",
            (email, pw_hash, enroll_token)
        )
        conn.commit()
        return {"status": "created", "email": email}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /admin/allowed-users/{email}  (remove user account)
# ---------------------------------------------------------------------------
@router.delete("/admin/allowed-users/{email:path}")
def remove_user(email: str, request: Request):
    _admin(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("DELETE FROM users WHERE email=?", (email,))
        conn.commit()
        return {"status": "deleted", "email": email}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/role
# ---------------------------------------------------------------------------
class UpdateRoleRequest(BaseModel):
    role: str

@router.put("/admin/users/{user_id}/role")
def admin_update_role(user_id: int, body: UpdateRoleRequest, request: Request):
    _admin(request)
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Invalid role")
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, user_id))
        conn.commit()
        return {"status": "updated"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PUT /admin/users/{user_id}/password
# ---------------------------------------------------------------------------
class UpdatePasswordRequest(BaseModel):
    password: str

@router.put("/admin/users/{user_id}/password")
def admin_update_password(user_id: int, body: UpdatePasswordRequest, request: Request):
    _admin(request)
    pw_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET password_hash=?, password_plaintext=? WHERE id=?", (pw_hash, body.password, user_id))
        conn.commit()
        return {"status": "updated"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /admin/users/{user_id}/purge
# ---------------------------------------------------------------------------
@router.delete("/admin/users/{user_id}/purge")
def admin_purge_user(user_id: int, request: Request):
    _admin(request)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM events WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM alerts WHERE user_id=?", (user_id,))
        conn.commit()
        return {"status": "purged"}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /agents  (user's own agents - for account menu)
# ---------------------------------------------------------------------------
@router.get("/agents")
def list_my_agents(request: Request):
    from db.auth import get_current_user
    user = get_current_user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, hostname, last_seen, created_at FROM agents WHERE user_id=? ORDER BY created_at DESC",
            (uid,)
        ).fetchall()
        return {
            "agents": [
                {
                    "agent_id":      str(r["id"]),
                    "hostname":      r["hostname"],
                    "pc_name":       r["hostname"],
                    "last_seen_at":  None,
                    "registered_at": 0,
                    "is_revoked":    0,
                }
                for r in rows
            ],
            "count": len(rows),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /delete-my-data  (user deletes own account)
# ---------------------------------------------------------------------------
@router.delete("/delete-my-data")
def delete_my_data(request: Request, response: Response):
    from db.auth import get_current_user, COOKIE_NAME
    user = get_current_user(request)
    uid  = user["user_id"]
    conn = get_connection()
    try:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.commit()
        # Clear the JWT cookie immediately so the session cannot be reused
        # Source: https://fastapi.tiangolo.com/tutorial/security/
        response.delete_cookie(COOKIE_NAME)
        return {"status": "deleted", "message": "Your account and all data have been removed."}
    finally:
        conn.close()



# ---------------------------------------------------------------------------
# GET /download-db (stub - returns 501, not implemented)
# ---------------------------------------------------------------------------
@router.get("/download-db")
def download_db(request: Request):
    raise HTTPException(status_code=501, detail="DB export not available in this version")
