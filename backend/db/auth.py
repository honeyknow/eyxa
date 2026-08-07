"""
Eyxa backend - JWT auth helpers for dashboard API routes.

Provides:
  create_access_token(user_id, email, role) -> str
  get_current_user(request)                -> {"user_id", "email", "role"}
  require_admin(request)                   -> {"user_id", "email", "role"}

Token is stored as an HttpOnly cookie named "eyxa_token".
Secret key is read from env var EYXA_JWT_SECRET (fallback for dev only).

Source: https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
Source: https://python-jose.readthedocs.io/en/latest/
"""

import os
import datetime
from fastapi import HTTPException, Request
from jose import JWTError, jwt

_SECRET = os.environ.get("EYXA_JWT_SECRET", "eyxa-dev-secret-change-in-prod")
_ALGO   = "HS256"
_TTL    = datetime.timedelta(hours=12)

COOKIE_NAME = "eyxa_token"


def create_access_token(user_id: int, email: str, role: str) -> str:
    """Return a signed JWT encoding user identity. Expires in 12 hours."""
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "exp": datetime.datetime.utcnow() + _TTL,
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGO])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired session")


def get_current_user(request: Request) -> dict:
    """Extract and validate JWT from cookie. Returns user dict or raises 401."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    data = _decode_token(token)
    return {
        "user_id": int(data["sub"]),
        "email":   data["email"],
        "role":    data.get("role", "user"),
    }


def require_admin(request: Request) -> dict:
    """Same as get_current_user but also enforces admin role."""
    user = get_current_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
