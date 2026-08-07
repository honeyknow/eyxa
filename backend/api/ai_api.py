from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
import json
import hashlib
import os
import yaml
from typing import Dict, Any, List
from db.database import get_connection, get_ai_config, set_ai_config
from db.auth import get_current_user
from fastapi import Request
from groq import Groq

router = APIRouter()

router = APIRouter()

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "ai_schema.yml")

class SchemaUpdate(BaseModel):
    yaml_content: str

class ConfigUpdate(BaseModel):
    api_key: str
    model_id: str

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
        # Validate that it is valid YAML
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

def load_schema() -> Dict[int, List[str]]:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r") as f:
        data = yaml.safe_load(f)
    return data.get("event_schemas", {})

@router.post("/alerts/{alert_id}/ai_investigate")
def investigate_alert(alert_id: int, request: Request, user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_connection)):
    """
    Compresses all events tied to an alert using the YAML schema,
    then sends the perfectly deduplicated payload to Groq.
    """
    # 1. Get Alert
    alert = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    agent_id = alert["agent_id"]
    try:
        matching_event_ids = json.loads(alert["matching_event_ids"])
    except:
        matching_event_ids = []

    if not matching_event_ids:
        raise HTTPException(status_code=400, detail="No events attached to alert")
    
    # 2. Get the ProcessGuid of the triggering event to pull the Blast Radius
    anchor_event = db.execute("SELECT payload FROM events WHERE agent_id=? AND id=?", (agent_id, matching_event_ids[0])).fetchone()
    if not anchor_event:
        raise HTTPException(status_code=400, detail="Anchor event not found")
    
    anchor_payload = json.loads(anchor_event["payload"])
    process_guid = anchor_payload.get("ProcessGuid")
    
    if not process_guid:
        # If no ProcessGuid, just use the matching events
        events_to_analyze = []
        for eid in matching_event_ids:
            ev = db.execute("SELECT payload FROM events WHERE agent_id=? AND id=?", (agent_id, eid)).fetchone()
            if ev:
                events_to_analyze.append(json.loads(ev["payload"]))
    else:
        # Pull entire blast radius
        rows = db.execute("SELECT payload FROM events WHERE agent_id=? AND json_extract(payload, '$.ProcessGuid') = ?", (agent_id, process_guid)).fetchall()
        events_to_analyze = [json.loads(r["payload"]) for r in rows]

    if not events_to_analyze:
        raise HTTPException(status_code=400, detail="No blast radius events found")

    # 3. Compress using the YAML Schema
    schema = load_schema()
    grouped_events = {}
    
    for ev in events_to_analyze:
        eid = ev.get("EventID")
        allowed_keys = schema.get(eid)
        
        if allowed_keys is None:
            # If we don't have a schema for this EventID, we must keep it entirely (fallback)
            stripped_ev = ev
        else:
            # STRIP EVERYTHING NOT IN THE YAML ARRAY
            stripped_ev = {k: v for k, v in ev.items() if k in allowed_keys}
            # Always keep EventID so the AI knows what it is
            stripped_ev["EventID"] = eid
            
        # Hash and count
        ev_str = json.dumps(stripped_ev, sort_keys=True)
        h = hashlib.md5(ev_str.encode()).hexdigest()
        
        if h not in grouped_events:
            grouped_events[h] = {"count": 1, "behavior": stripped_ev}
        else:
            grouped_events[h]["count"] += 1
            
    compressed_payload = list(grouped_events.values())
    
    # Convert the payload to a dense, token-efficient string (strip all JSON brackets, quotes, and whitespace)
    # Format: [COUNTx] EID: <id> | Key: Value | Key: Value
    dense_lines = []
    for item in compressed_payload:
        count = item["count"]
        beh = item["behavior"]
        eid = beh.pop("EventID", "Unknown")
        pairs = [f"{k}:{v}" for k, v in beh.items()]
        dense_lines.append(f"[{count}x] EID:{eid} | " + " | ".join(pairs))
        
    dense_payload_str = "\n".join(dense_lines)
    
    # SAFETY: Groq's free tier has a hard 12k TPM limit. 
    # Because our dense payload format tokenizes poorly (~2.4 chars per token), 18,000 chars is roughly 7,500 tokens.
    MAX_CHARS = 18000
    if len(dense_payload_str) > MAX_CHARS:
        dense_payload_str = dense_payload_str[:MAX_CHARS] + "\n\n... [WARNING: PAYLOAD TRUNCATED TO FIT API RATE LIMITS] ..."
    
    # 4. Fire to Groq
    ai_config = get_ai_config(user["user_id"])
    groq_api_key = ai_config["api_key"]
    target_model = ai_config["model_id"]

    if not groq_api_key:
        raise HTTPException(status_code=500, detail="Groq API key is not configured for your account. Please set it in the AI Engine settings.")
        
    try:
        client = Groq(api_key=groq_api_key)
        
        system_prompt = f"""You are an elite, omniscient Incident Response AI natively embedded in the Eyxa EDR platform.
You are analyzing a mathematically deduplicated telemetry payload representing a full attack chain (Blast Radius).
The payload contains unique Windows behaviors and a 'count' of how many times each behavior occurred.

CRITICAL INSTRUCTIONS:
1. NO FLUFF. Do not write generic introductions or conclusions (e.g., "Here is the analysis..."). 
2. BE BRUTAL AND PRECISE. Describe exactly what the malware did step-by-step.
3. EXTRACT IOCs. Clearly list all files, registry keys, IPs, and command lines involved.
4. CORRELATE. Connect the parent/child execution flows. If powershell wrote a file and a registry key, explicitly state that correlation.
5. FORMATTING. Use clean Markdown styling (bolding, inline code blocks for paths/commands) for maximum readability by a SOC analyst.

ALERT CONTEXT:
- Name: {alert["rule_title"]}
- Category: {alert["technique"]}
- Severity: {alert["rule_level"]}

DEDUPLICATED TELEMETRY PAYLOAD:
{dense_payload_str}
"""

        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "Analyze the telemetry payload and generate the forensic report."}
            ],
            model=target_model,
            temperature=0.0,
            max_tokens=2048,
            top_p=0.9
        )
        
        report = chat_completion.choices[0].message.content
        
        return {
            "report": report,
            "compressed_event_count": len(compressed_payload),
            "raw_event_count": len(events_to_analyze)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Groq API Error: {str(e)}")
