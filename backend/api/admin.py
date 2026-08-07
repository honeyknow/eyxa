"""
Eyxa backend - Admin routes for user management.
"""

from fastapi import APIRouter, HTTPException, Request
from db.database import get_connection
from db.auth import get_current_user

router = APIRouter()

def _require_admin(request: Request):
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

@router.get("/admin/users")
def list_users(request: Request):
    _require_admin(request)
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, email, created_at FROM users ORDER BY id ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@router.delete("/admin/users/{user_id}")
def delete_user(request: Request, user_id: int):
    me = _require_admin(request)
    if me["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
    
    conn = get_connection()
    try:
        # Check if user exists
        row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
            
        # ON DELETE CASCADE handles deleting agents, events, alerts
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return {"status": "success", "deleted_user": row["email"]}
    finally:
        conn.close()
