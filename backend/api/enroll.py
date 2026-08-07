"""
Eyxa backend - POST /api/enroll

Accepts an agent's first-run enrollment request.  Looks up the user by
enroll_token, enforces the max-3-agents-per-user limit, creates the agent
row, and returns a fresh agent_token.

Wire format (from enrollment.c EyxaDoEnroll):
    POST /api/enroll
    Content-Type: application/json
    Body: {
        "enroll_token": "<per-user token from download page>",
        "machine_id":   "<Windows MachineGuid>",
        "hostname":     "<ComputerName>",
        "os_version":   "windows"
    }
    Response 200: {"agent_token": "<64-char hex>"}
    Response 404: enroll_token not found
    Response 409: machine_id already enrolled (returns existing agent_token)
    Response 429: user already has 3 agents

Token generation: secrets.token_hex(32) - 64-char lowercase hex.
Source: https://docs.python.org/3/library/secrets.html#secrets.token_hex

Agent limit: 3 per user (locked capacity decision).
"""

import secrets
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from db.database import get_connection

router = APIRouter()

MAX_AGENTS_PER_USER = 3


class EnrollRequest(BaseModel):
    enroll_token: str
    machine_id:   str
    hostname:     str
    os_version:   str = "windows"


class EnrollResponse(BaseModel):
    agent_token: str


@router.post("/api/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest) -> EnrollResponse:
    if not req.enroll_token or not req.machine_id or not req.hostname:
        raise HTTPException(status_code=400, detail="missing required fields")

    conn = get_connection()
    try:
        # 1. Resolve user from enroll_token.
        row = conn.execute(
            "SELECT id FROM users WHERE enroll_token = ?",
            (req.enroll_token,)
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="enroll_token not found")
        user_id = row["id"]

        # 2. Re-enrollment: if this machine_id is already registered under this
        #    user, return the existing agent_token (idempotent).
        existing = conn.execute(
            "SELECT agent_token FROM agents WHERE user_id = ? AND machine_id = ?",
            (user_id, req.machine_id)
        ).fetchone()
        if existing:
            return EnrollResponse(agent_token=existing["agent_token"])

        # 3. Enforce per-user agent limit.
        count = conn.execute(
            "SELECT COUNT(*) FROM agents WHERE user_id = ?",
            (user_id,)
        ).fetchone()[0]
        if count >= MAX_AGENTS_PER_USER:
            raise HTTPException(
                status_code=429,
                detail=f"user already has {MAX_AGENTS_PER_USER} agents enrolled"
            )

        # 4. Generate a fresh agent_token and insert the agent row.
        # Source: https://docs.python.org/3/library/secrets.html#secrets.token_hex
        agent_token = secrets.token_hex(32)
        conn.execute(
            """INSERT INTO agents (user_id, machine_id, hostname, os_version, agent_token)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, req.machine_id, req.hostname, req.os_version, agent_token)
        )
        conn.commit()
        return EnrollResponse(agent_token=agent_token)
    finally:
        conn.close()
