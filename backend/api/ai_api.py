from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
import json
import hashlib
import os
import yaml
from typing import Dict, Any, List
from db.database import get_connection, get_ai_config, set_ai_config, get_ai_prompt, set_ai_prompt
from db.auth import get_current_user
from fastapi import Request
from groq import Groq

router = APIRouter()

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "ai_schema.yml")
PROMPT_PATH = os.path.join(CONFIG_DIR, "ai_system_prompt.txt")

class SchemaUpdate(BaseModel):
    yaml_content: str

class ConfigUpdate(BaseModel):
    api_key: str
    model_id: str

class PromptUpdate(BaseModel):
    prompt: str

@router.get("/config/ai_schema")
def get_ai_schema():
    """Returns the raw YAML string of the AI Schema for the frontend editor."""
    if not os.path.exists(CONFIG_PATH):
        raise HTTPException(status_code=404, detail="ai_schema.yml not found")
    with open(CONFIG_PATH, "r") as f:
        content = f.read()
    return {"yaml_content": content}

@router.get("/config/ai_schema/sample")
def get_ai_schema_sample(event_id: int = None, db: sqlite3.Connection = Depends(get_connection)):
    """Returns a raw JSON payload from the database so the user can see actual Sysmon fields."""
    if event_id is not None:
        row = db.execute("SELECT payload FROM events WHERE EventID = ? AND payload IS NOT NULL LIMIT 1", (event_id,)).fetchone()
    else:
        row = db.execute("SELECT payload FROM events WHERE payload IS NOT NULL LIMIT 1").fetchone()
    if not row:
        return {"sample": "{}"}
    return {"sample": row["payload"]}

@router.post("/config/ai_schema")
def update_ai_schema(payload: SchemaUpdate):
    """Saves the raw YAML string sent from the frontend editor."""
    try:
        yaml.safe_load(payload.yaml_content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
    with open(CONFIG_PATH, "w") as f:
        f.write(payload.yaml_content)
    return {"status": "success"}

@router.get("/config/ai_key")
def get_ai_config_route(request: Request, user: dict = Depends(get_current_user)):
    """Returns the current Groq API Key and Model for the authenticated user."""
    return get_ai_config(user["user_id"])

@router.post("/config/ai_key")
def update_ai_config_route(payload: ConfigUpdate, request: Request, user: dict = Depends(get_current_user)):
    """Saves the Groq API Key and Model for the authenticated user."""
    set_ai_config(user["user_id"], payload.api_key.strip(), payload.model_id.strip())
    return {"status": "success"}

@router.get("/config/ai_models")
def list_ai_models(request: Request, user: dict = Depends(get_current_user)):
    """Fetches available models from Groq using the user's saved API key."""
    ai_config = get_ai_config(user["user_id"])
    groq_api_key = ai_config["api_key"]
    if not groq_api_key:
        raise HTTPException(status_code=400, detail="No API key configured. Save your Groq key first.")
    try:
        client = Groq(api_key=groq_api_key)
        models = client.models.list()
        model_list = sorted(
            [{"id": m.id, "owned_by": getattr(m, "owned_by", "groq")} for m in models.data],
            key=lambda x: x["id"]
        )
        return {"models": model_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Groq API Error: {str(e)}")

DEFAULT_SYSTEM_PROMPT = """You are an elite forensic engine embedded in the Eyxa EDR platform.
Analyze the telemetry below and return ONLY a single valid JSON object — no prose, no markdown fences, no explanation outside the JSON.

ALERT CONTEXT:
- Rule   : {rule}
- MITRE  : {technique}
- Severity: {severity}
- Data: Layer 1 = exact Sigma trigger events | Layer 2 = ±2 min context window
{truncation_note}

TELEMETRY:
{telemetry}

Return this EXACT JSON schema (all fields required, use empty arrays [] if nothing found):
{{
  "verdict": "<CONFIRMED_ATTACK | SUSPICIOUS | FALSE_POSITIVE>",
  "attack_title": "<one punchy sentence describing what actually happened>",
  "urgency": "<CRITICAL | HIGH | MEDIUM | LOW>",
  "attack_stage": "<Reconnaissance | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Exfiltration | Command and Control | Impact>",
  "kill_chain_phase": "<Recon | Weaponize | Deliver | Exploit | Install | Command & Control | Actions on Objectives>",
  "attacker_objective": "<one sentence — what the attacker was trying to achieve>",
  "mitre_chain": ["<T-ID>"],
  "similar_techniques": ["<T-ID of related techniques to watch for>"],
  "timeline": [
    {{"time": "<HH:MM:SS from TimeCreated or best estimate>", "event": "<what happened, be specific>", "suspicious": <true|false>}}
  ],
  "iocs": {{
    "files": ["<full path>"],
    "ips": ["<ip or domain>"],
    "commands": ["<exact command line>"],
    "registry_keys": ["<full key path>"]
  }},
  "raw_ioc_summary": "<all IOCs combined as a single comma-separated one-liner for threat intel copy-paste>",
  "process_chain": "<grandparent.exe → parent.exe → child.exe>",
  "affected_users": ["<username>"],
  "affected_hosts": ["<hostname or machine ID>"],
  "persistence_mechanism": "<specific persistence method or null if none detected>",
  "evasion_techniques": ["<specific evasion tactic observed>"],
  "lateral_movement_risk": "<YES | NO | UNKNOWN>",
  "data_at_risk": "<what sensitive data could be exposed, or 'None identified'>",
  "analyst_summary": "<3-4 sentences, brutal and precise — what happened, how, what is the risk, and what the attacker achieved>",
  "false_positive_reason": "<if verdict is FALSE_POSITIVE explain why, otherwise null>",
  "recommended_actions": ["<concrete actionable step>"]
}}"""

@router.get("/config/ai_prompt")
def get_prompt_route(request: Request, user: dict = Depends(get_current_user)):
    """Returns the user's custom system prompt, or the default if not customised."""
    custom = get_ai_prompt(user["user_id"])
    return {"prompt": custom if custom else DEFAULT_SYSTEM_PROMPT, "is_custom": bool(custom)}

@router.post("/config/ai_prompt")
def set_prompt_route(payload: PromptUpdate, request: Request, user: dict = Depends(get_current_user)):
    """Saves the user's custom system prompt. Send empty string to reset to default."""
    value = payload.prompt.strip() if payload.prompt.strip() else None
    set_ai_prompt(user["user_id"], value)
    return {"status": "success", "is_custom": value is not None}

@router.post("/config/ai_prompt/reset")
def reset_prompt_route(request: Request, user: dict = Depends(get_current_user)):
    """Resets the user's system prompt to the default."""
    set_ai_prompt(user["user_id"], None)
    return {"status": "reset", "prompt": DEFAULT_SYSTEM_PROMPT}

def load_schema() -> Dict[int, List[str]]:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r") as f:
        data = yaml.safe_load(f)
    return data.get("event_schemas", {})

def compress_events(events_to_analyze: list, schema: dict) -> tuple[list, str]:
    """
    Deduplicates events using the YAML schema and returns
    (compressed_payload_list, dense_string).
    """
    grouped_events = {}
    for ev in events_to_analyze:
        eid = ev.get("EventID")
        allowed_keys = schema.get(eid)
        if allowed_keys is None:
            stripped_ev = ev
        else:
            stripped_ev = {k: v for k, v in ev.items() if k in allowed_keys}
            stripped_ev["EventID"] = eid

        ev_str = json.dumps(stripped_ev, sort_keys=True)
        h = hashlib.md5(ev_str.encode()).hexdigest()
        if h not in grouped_events:
            grouped_events[h] = {"count": 1, "behavior": stripped_ev}
        else:
            grouped_events[h]["count"] += 1

    compressed_payload = list(grouped_events.values())

    dense_lines = []
    for item in compressed_payload:
        count = item["count"]
        beh = dict(item["behavior"])
        eid = beh.pop("EventID", "Unknown")
        pairs = [f"{k}:{v}" for k, v in beh.items()]
        dense_lines.append(f"[{count}x] EID:{eid} | " + " | ".join(pairs))

    return compressed_payload, "\n".join(dense_lines)


@router.post("/alerts/{alert_id}/ai_investigate")
def investigate_alert(
    alert_id: int,
    request: Request,
    user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_connection)
):
    """
    2-Layer forensic data collection:
      Layer 1: Exact events that triggered the Sigma rule (matching_event_ids)
      Layer 2: ±2 minute time window around the trigger for immediate context

    Sends a structured JSON prompt to Groq and returns a parsed forensic object.
    """
    # ── Fetch Alert ────────────────────────────────────────────────────────────
    alert = db.execute("SELECT * FROM alerts WHERE id = ? AND user_id = ?", (alert_id, user["user_id"])).fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    agent_id = alert["agent_id"]
    try:
        matching_event_ids = json.loads(alert["matching_event_ids"])
    except Exception:
        matching_event_ids = []

    if not matching_event_ids:
        raise HTTPException(status_code=400, detail="No events attached to this alert")

    # ── LAYER 1: Exact trigger events ──────────────────────────────────────────
    layer1_events = []
    anchor_time = None

    placeholders = ",".join("?" * len(matching_event_ids))
    rows = db.execute(
        f"SELECT id, payload, TimeCreated FROM events WHERE agent_id=? AND id IN ({placeholders}) ORDER BY TimeCreated ASC",
        [agent_id] + matching_event_ids
    ).fetchall()

    for row in rows:
        if row["payload"]:
            parsed = json.loads(row["payload"])
            parsed["EventID"] = parsed.get("EventID") or db.execute("SELECT EventID FROM events WHERE id=?", (row["id"],)).fetchone()["EventID"]
            layer1_events.append(parsed)
            if anchor_time is None and row["TimeCreated"]:
                anchor_time = row["TimeCreated"]

    # ── LAYER 2: ±2 minute context window ──────────────────────────────────────
    layer2_events = []
    if anchor_time:
        context_rows = db.execute(
            f"""SELECT payload, EventID FROM events
               WHERE agent_id = ?
               AND TimeCreated BETWEEN datetime(?, '-2 minutes') AND datetime(?, '+2 minutes')
               AND id NOT IN ({placeholders})
               ORDER BY TimeCreated ASC
               LIMIT 60""",
            [agent_id, anchor_time, anchor_time] + matching_event_ids
        ).fetchall()

        for row in context_rows:
            if row["payload"]:
                parsed = json.loads(row["payload"])
                parsed["EventID"] = parsed.get("EventID") or row["EventID"]
                layer2_events.append(parsed)

    all_events = layer1_events + layer2_events

    if not all_events:
        raise HTTPException(status_code=400, detail="No telemetry events could be fetched for this alert")

    # ── Compress & Deduplicate ─────────────────────────────────────────────────
    schema = load_schema()
    compressed_payload, dense_payload_str = compress_events(all_events, schema)

    # Safety cap: ~8,000 chars ≈ ~3,200 tokens — leaves plenty of room for output
    MAX_CHARS = 8000
    truncated = False
    if len(dense_payload_str) > MAX_CHARS:
        dense_payload_str = dense_payload_str[:MAX_CHARS]
        truncated = True

    # ── Groq API ───────────────────────────────────────────────────────────────
    ai_config = get_ai_config(user["user_id"])
    groq_api_key = ai_config["api_key"]
    target_model = ai_config["model_id"]

    if not groq_api_key:
        raise HTTPException(
            status_code=500,
            detail="Groq API key not configured. Click the gear icon to add your key."
        )

    # Use the user's custom prompt if set, otherwise use the default
    custom_prompt = get_ai_prompt(user["user_id"])
    prompt_template = custom_prompt if custom_prompt else DEFAULT_SYSTEM_PROMPT
    system_prompt = prompt_template.format(
        rule=alert["rule_title"],
        technique=alert["technique"],
        severity=alert["rule_level"],
        truncation_note="- NOTE: Payload was truncated to fit token limits." if truncated else "",
        telemetry=dense_payload_str
    )

    try:
        client = Groq(api_key=groq_api_key)
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Analyze the telemetry and return the JSON forensic report only."}
            ],
            model=target_model,
            temperature=0.0,
            max_tokens=3000,
            top_p=0.9
        )

        raw_response = chat_completion.choices[0].message.content.strip()

        # Strip accidental markdown fences if the model wraps the JSON
        if raw_response.startswith("```"):
            raw_response = raw_response.split("```")[1]
            if raw_response.startswith("json"):
                raw_response = raw_response[4:]
        raw_response = raw_response.strip()

        try:
            analysis = json.loads(raw_response)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=500,
                detail=f"AI returned malformed JSON. Raw response: {raw_response[:300]}"
            )

        usage = chat_completion.usage
        prompt_tokens     = usage.prompt_tokens     if usage else 0
        completion_tokens = usage.completion_tokens if usage else 0
        total_tokens      = usage.total_tokens      if usage else 0

        print(f"[AI] alert_id={alert_id} model={target_model} "
              f"prompt={prompt_tokens} completion={completion_tokens} total={total_tokens} "
              f"layer1={len(layer1_events)} layer2={len(layer2_events)} compressed={len(compressed_payload)} truncated={truncated}")

        return {
            "analysis": analysis,
            "raw_event_count": len(all_events),
            "compressed_event_count": len(compressed_payload),
            "layer1_count": len(layer1_events),
            "layer2_count": len(layer2_events),
            "truncated": truncated,
            "tokens": {
                "prompt": prompt_tokens,
                "completion": completion_tokens,
                "total": total_tokens
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Groq API Error: {str(e)}")
