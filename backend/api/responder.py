"""
Eyxa backend - Response Actions & WebSocket Endpoint (Phase 6).

Implements:
1. GET /ws/agent/{agent_token} - Persistent WebSocket endpoint for agents.
   - Receives live stats from agent.
   - Delivers queued commands to agent.
   - Receives command execution results from agent.
2. POST /api/commands - REST endpoint to queue manual response action.
3. GET /api/commands - REST endpoint to list command history.

Source (FastAPI WebSockets):
  https://fastapi.tiangolo.com/advanced/websockets/
"""

import json
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from db.database import get_connection

logger = logging.getLogger("eyxa.responder")
router = APIRouter()


class CommandManager:
    """Manages active WebSocket connections per agent_id."""

    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.dashboard_clients: set[WebSocket] = set()

    async def connect(self, agent_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        logger.info("[ws] agent %d connected", agent_id)

    def disconnect(self, agent_id: int):
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            logger.info("[ws] agent %d disconnected", agent_id)

    async def send_command(self, agent_id: int, command_data: dict) -> bool:
        ws = self.active_connections.get(agent_id)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(command_data))
            return True
        except Exception as exc:
            logger.warning("[ws] error sending to agent %d: %s", agent_id, exc)
            self.disconnect(agent_id)
            return False

    async def broadcast_stats(self, agent_id: int, stats_data: dict):
        """Broadcast live stats to all connected dashboards."""
        msg = json.dumps({"type": "live_stats", "host_id": str(agent_id), "stats": stats_data})
        dead = set()
        # Iterate over a copy of the set to prevent RuntimeError if the set changes size during await
        for client in list(self.dashboard_clients):
            try:
                await client.send_text(msg)
            except Exception:
                dead.add(client)
        for client in dead:
            self.dashboard_clients.discard(client)


ws_manager = CommandManager()


class CreateCommandRequest(BaseModel):
    agent_id: int
    action: str  # e.g. "kill_process"
    payload: Dict[str, Any]  # e.g. {"pid": 1234}


class CommandResponse(BaseModel):
    id: int
    agent_id: int
    action: str
    payload: str
    status: str
    result: Optional[str] = None
    created_at: str


@router.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """WebSocket for the dashboard to receive live stats."""
    await websocket.accept()
    ws_manager.dashboard_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text() # keep-alive
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("[ws] dashboard client error: %s", e)
    finally:
        ws_manager.dashboard_clients.discard(websocket)


@router.websocket("/ws/agent/{agent_token}")
async def websocket_endpoint(websocket: WebSocket, agent_token: str):
    """
    WebSocket connection endpoint for the agent.
    Validates agent_token against DB before accepting connection.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, user_id FROM agents WHERE agent_token = ?",
            (agent_token,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        logger.warning("[ws] reject connection: invalid token %s...", agent_token[:8])
        await websocket.close(code=4001)
        return

    agent_id = row["id"]
    user_id = row["user_id"]

    await ws_manager.connect(agent_id, websocket)

    # Deliver any pending unsent commands from DB
    conn = get_connection()
    try:
        pending = conn.execute(
            "SELECT id, action, payload FROM commands WHERE agent_id = ? AND status = 'pending'",
            (agent_id,),
        ).fetchall()
        for cmd in pending:
            payload_obj = json.loads(cmd["payload"]) if cmd["payload"] else {}
            msg = {
                "type": "command",
                "command_id": cmd["id"],
                "action": cmd["action"],
                "payload": payload_obj,
            }
            if await ws_manager.send_command(agent_id, msg):
                conn.execute(
                    "UPDATE commands SET status = 'sent', updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?",
                    (cmd["id"],),
                )
        conn.commit()
    finally:
        conn.close()

    try:
        while True:
            data_str = await websocket.receive_text()
            try:
                msg = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type")

            if msg_type == "stats":
                # Heartbeat / live stats: update agent last_seen
                c = get_connection()
                try:
                    c.execute(
                        "UPDATE agents SET last_seen = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?",
                        (agent_id,),
                    )
                    c.commit()
                finally:
                    c.close()
                # Broadcast live stats to dashboards
                # agent sends agent_id in stats indirectly (we know it)
                # the stats payload is the whole msg
                await ws_manager.broadcast_stats(agent_id, msg)
                continue

            elif msg_type == "inventory":
                logger.info("[ws] agent %d inventory received", agent_id)
                # Store the inventory JSON in the DB
                c = get_connection()
                try:
                    c.execute(
                        "UPDATE agents SET inventory = ? WHERE id = ?",
                        (json.dumps(msg.get("data", msg)), agent_id)
                    )
                    c.commit()
                except Exception as e:
                    logger.warning("[ws] Error saving inventory for agent %d: %s", agent_id, e)
                finally:
                    c.close()
                continue

            elif msg_type == "command_result":
                command_id = msg.get("command_id")
                status = msg.get("status", "completed")
                result_obj = msg.get("result", {})

                if command_id:
                    c = get_connection()
                    try:
                        c.execute(
                            """
                            UPDATE commands
                            SET status = ?, result = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
                            WHERE id = ? AND agent_id = ?
                            """,
                            (status, json.dumps(result_obj), command_id, agent_id),
                        )
                        c.commit()
                        logger.info(
                            "[ws] command %d updated -> status=%s", command_id, status
                        )
                    finally:
                        c.close()

    except WebSocketDisconnect:
        ws_manager.disconnect(agent_id)
    except Exception as exc:
        logger.warning("[ws] connection error for agent %d: %s", agent_id, exc)
        ws_manager.disconnect(agent_id)


@router.post("/api/commands", response_model=CommandResponse)
async def create_command(req: CreateCommandRequest):
    """
    Queue a manual response action command.
    If the target agent is currently connected via WebSocket, dispatches immediately.
    """
    conn = get_connection()
    try:
        agent_row = conn.execute(
            "SELECT user_id FROM agents WHERE id = ?", (req.agent_id,)
        ).fetchone()
        if not agent_row:
            raise HTTPException(status_code=404, detail="agent not found")

        user_id = agent_row["user_id"]
        payload_json = json.dumps(req.payload)

        cursor = conn.execute(
            """
            INSERT INTO commands (user_id, agent_id, action, payload, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (user_id, req.agent_id, req.action, payload_json),
        )
        cmd_id = cursor.lastrowid
        conn.commit()

        cmd_row = conn.execute(
            "SELECT id, agent_id, action, payload, status, result, created_at FROM commands WHERE id = ?",
            (cmd_id,),
        ).fetchone()
    finally:
        conn.close()

    # Try dispatching immediately over WebSocket if online
    msg = {
        "type": "command",
        "command_id": cmd_id,
        "action": req.action,
        "payload": req.payload,
    }
    sent = await ws_manager.send_command(req.agent_id, msg)
    if sent:
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE commands SET status = 'sent', updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?",
                (cmd_id,),
            )
            conn.commit()
        finally:
            conn.close()

    return dict(cmd_row)


@router.get("/api/commands")
def list_commands(agent_id: Optional[int] = None):
    """List response action commands."""
    conn = get_connection()
    try:
        if agent_id:
            rows = conn.execute(
                "SELECT id, agent_id, action, payload, status, result, created_at FROM commands WHERE agent_id = ? ORDER BY id DESC",
                (agent_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, agent_id, action, payload, status, result, created_at FROM commands ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@router.delete("/api/commands")
def delete_queued_commands(agent_id: int):
    """Delete all pending/queued commands for an agent."""
    conn = get_connection()
    try:
        conn.execute(
            "DELETE FROM commands WHERE agent_id = ? AND status = 'pending'",
            (agent_id,),
        )
        conn.commit()
        return {"status": "success"}
    finally:
        conn.close()

@router.delete("/api/commands/{cmd_id}")
def delete_command(cmd_id: int):
    """Delete a specific command by ID."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM commands WHERE id = ?", (cmd_id,))
        conn.commit()
        return {"status": "success", "id": cmd_id}
    finally:
        conn.close()
