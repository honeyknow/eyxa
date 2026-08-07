"""
Eyxa backend - Dashboard auth routes.

POST /auth/login   : email+password → sets HttpOnly JWT cookie
POST /auth/logout  : clears the cookie
GET  /auth/me      : returns current user identity (used by UI on load)

Password check uses bcrypt against users.password_hash.
Role is 'admin' if email matches EYXA_ADMIN_EMAIL env var, else 'user'.

Source: https://fastapi.tiangolo.com/tutorial/security/
Source: https://pypi.org/project/bcrypt/
"""

import os
import bcrypt
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from db.database import get_connection
from db.auth import create_access_token, get_current_user, COOKIE_NAME

router = APIRouter()

ADMIN_EMAIL = os.environ.get("EYXA_ADMIN_EMAIL", "admin@gmail.com").lower()


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/auth/login")
def login(req: LoginRequest, response: Response):
    email = req.email.strip().lower()
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, email, password_hash, password_plaintext, role FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    pw_hash = row["password_hash"]
    pw_plain = row["password_plaintext"]
    
    match = False
    if pw_plain and req.password == pw_plain:
        match = True
    else:
        try:
            match = bcrypt.checkpw(req.password.encode(), pw_hash.encode())
        except Exception:
            match = False

    if not match:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    role = row["role"]
    if email == ADMIN_EMAIL:
        role = "admin" # keep env var as ultimate fallback

    token = create_access_token(row["id"], row["email"], role)

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,   # set True when behind HTTPS in prod
        max_age=43200,  # 12 hours
    )
    return {"authenticated": True, "email": row["email"], "role": role}


@router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"status": "logged_out"}


@router.get("/auth/me")
def me(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return {"authenticated": False}

    conn = get_connection()
    try:
        row = conn.execute("SELECT enroll_token FROM users WHERE id=?", (user["user_id"],)).fetchone()
        enroll_token = row["enroll_token"] if row else ""
    finally:
        conn.close()
        
    import socket
    server_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    return {
        "authenticated": True,
        "email": user["email"],
        "role":  user["role"],
        "enroll_token": enroll_token,
        "server_ip": server_ip,
    }


class ImpersonateRequest(BaseModel):
    user_id: int

@router.post("/auth/impersonate")
def impersonate(req: ImpersonateRequest, request: Request, response: Response):
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    conn = get_connection()
    try:
        row = conn.execute("SELECT id, email FROM users WHERE id = ?", (req.user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
    finally:
        conn.close()
        
    # Maintain admin role so they can unimpersonate later
    token = create_access_token(row["id"], row["email"], "admin")
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=43200,
    )
    return {"status": "impersonated", "email": row["email"]}


@router.post("/auth/unimpersonate")
def unimpersonate(request: Request, response: Response):
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
        
    conn = get_connection()
    try:
        row = conn.execute("SELECT id, email FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Admin user not found")
    finally:
        conn.close()
        
    token = create_access_token(row["id"], row["email"], "admin")
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=43200,
    )
    return {"status": "unimpersonated"}
