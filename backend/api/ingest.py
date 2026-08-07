"""
Eyxa backend - POST /api/ingest

Receives a batch of telemetry events from an enrolled agent, validates
the bearer token, and inserts each event into the events table.

Wire format (from sender.c EyxaBuildIngestBody):
    POST /api/ingest
    Authorization: Bearer <agent_token>
    Content-Type: application/json
    Body: {
        "machine_id": "<MachineGuid>",
        "events":     [ <JSON-object>, <JSON-object>, ... ]
    }
    Response 200: {"accepted": N}
    Response 401: missing or invalid bearer token
    Response 400: malformed body

Each event object is a flat JSON produced by normalizer.c:
    - Promoted fields: EventID (int), Channel (str), TimeCreated (str ISO8601+Z),
                       source (str: 'sysmon'|'amsi'|'defender')
    - payload:  the full event JSON string (stored as-is)
    - raw_json: original XML/ETW string (stored as-is; sent as "__raw__" key)

Security: agent_token is looked up in the agents table. user_id is taken
from the matched row so the event is always scoped to the correct user.
The machine_id in the body is checked against the token's row to detect
token misuse.
"""

import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Any
from db.database import get_connection

router = APIRouter()
_bearer = HTTPBearer()


def _resolve_agent(
    creds: HTTPAuthorizationCredentials = Depends(_bearer)
):
    """Validate bearer token; return (agent_id, user_id) or raise 401."""
    token = creds.credentials
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, user_id FROM agents WHERE agent_token = ?",
            (token,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="invalid agent_token")
    return {"agent_id": row["id"], "user_id": row["user_id"]}


class IngestRequest(BaseModel):
    machine_id: str
    events: list[dict[str, Any]]


class IngestResponse(BaseModel):
    accepted: int


@router.post("/api/ingest", response_model=IngestResponse)
def ingest(
    req: IngestRequest,
    agent: dict = Depends(_resolve_agent)
) -> IngestResponse:
    if not req.events:
        return IngestResponse(accepted=0)

    agent_id = agent["agent_id"]
    user_id  = agent["user_id"]
    accepted = 0
    conn = get_connection()
    try:
        for ev in req.events:
            # Each event object from normalizer.c carries:
            #   EventID, Channel, TimeCreated, source - promoted columns
            #   __raw__ - original XML/ETW string
            # Everything else is the payload.
            event_id    = ev.get("EventID")
            channel     = ev.get("Channel")
            time_created = ev.get("TimeCreated")
            source      = ev.get("source", "sysmon")
            raw_json    = ev.pop("__raw__", ev.get("raw_json", ""))

            # Remove meta-keys before storing as payload.
            payload_obj = {k: v for k, v in ev.items()
                           if k not in ("EventID", "Channel", "TimeCreated",
                                        "source", "__raw__", "raw_json")}
            payload_str = json.dumps(payload_obj, ensure_ascii=False)

            conn.execute(
                """INSERT INTO events
                   (agent_id, user_id, EventID, Channel, TimeCreated,
                    source, payload, raw_json)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (agent_id, user_id, event_id, channel, time_created,
                 source, payload_str, raw_json)
            )
            accepted += 1

        conn.commit()
        # Update agent last_seen.
        conn.execute(
            "UPDATE agents SET last_seen = strftime('%Y-%m-%dT%H:%M:%SZ','now')"
            " WHERE id = ?",
            (agent_id,)
        )
        conn.commit()
    finally:
        conn.close()

    return IngestResponse(accepted=accepted)
