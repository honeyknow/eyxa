"""
Eyxa backend - Sigma Rules Engine API routes.

GET  /rules              : list all rules (seeded from .yml files on first call)
GET  /rules/stats        : same as /rules (alias for UI compatibility)
GET  /rules/{id}/yaml    : return raw YAML for a rule
PUT  /rules/{id}/yaml    : update YAML for a rule
PUT  /rules/{id}/meta    : update title/description/severity
POST /rules/{id}/toggle  : enable or disable a rule
POST /rules/upload       : upload a new YAML rule (multipart or text field)
DELETE /rules/{id}       : delete a custom rule (built-in rules cannot be deleted)

Rules are seeded from detection/rules/*.yml on startup.
Built-in rules are read-only (is_custom=0).

Source: https://sigmahq.io/docs/basics/rules.html
"""

import pathlib
import re
import yaml
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional
from db.database import get_connection
from db.auth import get_current_user
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

router = APIRouter()

RULES_DIR = pathlib.Path(__file__).parent.parent / "detection" / "rules"


def _user(r: Request) -> dict:
    return get_current_user(r)


def _parse_yaml_meta(yaml_text: str) -> dict:
    """Extract title, description, severity, and technique from Sigma YAML."""
    try:
        doc = yaml.safe_load(yaml_text)
    except Exception:
        return {}

    rule_id  = doc.get("id", "")
    title    = doc.get("title", "Untitled Rule")
    desc     = doc.get("description", "")
    severity = doc.get("level", "medium")

    # Extract first T-code from tags
    technique = ""
    for tag in doc.get("tags", []):
        m = re.search(r"(T\d{4}(?:\.\d{3})?)", str(tag), re.IGNORECASE)
        if m:
            technique = m.group(1).upper()
            break

    return {
        "rule_id":   rule_id,
        "title":     title,
        "description": desc,
        "severity":  severity,
        "technique": technique,
    }


def seed_rules_from_disk(conn) -> None:
    """One-time seed of .yml files from detection/rules/ into the rules table."""
    if not RULES_DIR.exists():
        return
    for yml_file in RULES_DIR.glob("*.yml"):
        try:
            yaml_text = yml_file.read_text(encoding="utf-8")
            meta = _parse_yaml_meta(yaml_text)
            if not meta.get("rule_id"):
                continue
            conn.execute("""
                INSERT OR IGNORE INTO rules
                    (rule_id, title, description, severity, technique, yaml_text, is_custom)
                VALUES (?,?,?,?,?,?,0)
            """, (
                meta["rule_id"], meta["title"], meta["description"],
                meta["severity"], meta["technique"], yaml_text,
            ))
        except Exception:
            continue
    conn.commit()


def _extract_tags(row) -> list:
    if "yaml_text" in row.keys() and row["yaml_text"]:
        try:
            doc = yaml.safe_load(row["yaml_text"])
            if isinstance(doc, dict):
                return doc.get("tags", [])
        except Exception:
            pass
    return []

def _fmt_rule(row) -> dict:
    return {
        "rule_id":      row["rule_id"],
        "title":        row["title"],
        "description":  row["description"],
        "severity":     row["severity"],
        "technique_ids": [row["technique"]] if row["technique"] else [],
        "tags":         _extract_tags(row),
        "enabled":      bool(row["enabled"]),
        "is_custom":    bool(row["is_custom"]),
        "is_global":    not bool(row["is_custom"]),  # custom = user-scoped; built-in = global
        "user_id":      None,
        "uploaded_by":  row["uploaded_by"] if "uploaded_by" in row.keys() else "Admin",
        "hit_count":    row["hit_count"],
        "last_fired_at": row["last_fired_at"],
        "false_positive_count": row["false_positive_count"] if "false_positive_count" in row.keys() else 0,
        "noise_score":  0.0,
        "created_at":   row["created_at"] if "created_at" in row.keys() else None,
        "updated_at":   None,
        "date":         "",
    }


# ---------------------------------------------------------------------------
# GET /rules
# ---------------------------------------------------------------------------
@router.get("/rules")
def list_rules(request: Request):
    _user(request)  # auth check
    conn = get_connection()
    try:

        rows = conn.execute(
            "SELECT * FROM rules ORDER BY severity DESC, title ASC"
        ).fetchall()
        rules = [_fmt_rule(r) for r in rows]
        return {"count": len(rules), "rules": rules}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /rules/stats
# ---------------------------------------------------------------------------
def _human_time(minutes: float) -> str:
    if minutes < 1:
        return "<1m"
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = int(minutes // 60)
    mins = int(minutes % 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days = hours // 24
    rem_hours = hours % 24
    return f"{days}d {rem_hours}h"

@router.get("/rules/stats")
def list_rule_stats(request: Request):
    _user(request)
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM rules ORDER BY hit_count DESC"
        ).fetchall()
        stats = []
        now = datetime.now(timezone.utc)
        for r in rows:
            # Parse created_at and calculate minutes active
            created_str = r["created_at"] if "created_at" in r.keys() else None
            if created_str:
                dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                minutes_active = (now - dt).total_seconds() / 60.0
            else:
                minutes_active = 0
                
            fp_count = r["false_positive_count"] if "false_positive_count" in r.keys() else 0
            days_active = minutes_active / 1440.0
            safe_days = days_active if days_active >= 0.01 else 0.01
            
            noise = (fp_count / safe_days) if r["hit_count"] > 0 else 0.0
            
            stats.append({
                "rule_id":      r["rule_id"],
                "title":        r["title"],
                "severity":     r["severity"],
                "technique_ids": [r["technique"]] if r["technique"] else [],
                "tags":         _extract_tags(r),
                "hit_count":    r["hit_count"],
                "last_fired_at": r["last_fired_at"],
                "false_positive_count": fp_count,
                "noise_score":  round(noise, 2),
                "enabled":      r["enabled"],
                "is_custom":    r["is_custom"],
                "uploaded_by":  r["uploaded_by"] if "uploaded_by" in r.keys() else "Admin",
                "user_id":      None,
                "days_active":  round(days_active, 2),
                "hours_active": round(minutes_active / 60.0, 2),
                "active_time_str": _human_time(minutes_active),
                "is_dead":      bool(r["hit_count"] == 0 and minutes_active > 10 and r["enabled"] == 1),
                "is_new":       bool(minutes_active <= 10),
                "is_high_noise": bool(noise > 5.0),
            })
        return {"stats": stats}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# GET /rules/{rule_id}/yaml
# ---------------------------------------------------------------------------
@router.get("/rules/{rule_id}/yaml")
def get_rule_yaml(rule_id: str, request: Request):
    _user(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        return {"rule_id": rule_id, "yaml": row["yaml_text"]}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PUT /rules/{rule_id}/yaml
# ---------------------------------------------------------------------------
class YamlUpdateRequest(BaseModel):
    yaml: str


@router.put("/rules/{rule_id}/yaml")
def update_rule_yaml(rule_id: str, body: YamlUpdateRequest, request: Request):
    _user(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        if not row["is_custom"]:
            raise HTTPException(status_code=403, detail="Built-in rules cannot be edited")
        meta = _parse_yaml_meta(body.yaml)
        conn.execute(
            "UPDATE rules SET yaml_text=?, title=?, description=?, severity=?, technique=? WHERE rule_id=?",
            (body.yaml, meta.get("title", row["title"]), meta.get("description", row["description"]),
             meta.get("severity", row["severity"]), meta.get("technique", row["technique"]), rule_id)
        )
        conn.commit()
        return {"status": "updated", "rule_id": rule_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PUT /rules/{rule_id}/meta
# ---------------------------------------------------------------------------
class MetaUpdateRequest(BaseModel):
    title:       Optional[str] = None
    description: Optional[str] = None
    severity:    Optional[str] = None
    tags:        Optional[list] = None
    technique_ids: Optional[list] = None


@router.put("/rules/{rule_id}/meta")
def update_rule_meta(rule_id: str, body: MetaUpdateRequest, request: Request):
    _user(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        updates = {}
        if body.title is not None:       updates["title"] = body.title
        if body.description is not None: updates["description"] = body.description
        if body.severity is not None:    updates["severity"] = body.severity
        if body.technique_ids:           updates["technique"] = body.technique_ids[0]
        if updates:
            set_clause = ", ".join(f"{k}=?" for k in updates)
            conn.execute(
                f"UPDATE rules SET {set_clause} WHERE rule_id=?",
                list(updates.values()) + [rule_id]
            )
            conn.commit()
        return {"status": "updated", "rule_id": rule_id}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /rules/{rule_id}/toggle
# ---------------------------------------------------------------------------
class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, body: ToggleRequest, request: Request):
    _user(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT rule_id FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        conn.execute(
            "UPDATE rules SET enabled=? WHERE rule_id=?",
            (1 if body.enabled else 0, rule_id)
        )
        conn.commit()
        return {"status": "ok", "rule_id": rule_id, "enabled": body.enabled}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /rules/upload
# ---------------------------------------------------------------------------
@router.post("/rules/upload")
async def upload_rule(
    request: Request,
    yaml_text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    user = _user(request)
    RULES_DIR = pathlib.Path(__file__).parent.parent / "detection" / "rules"
    if file:
        yaml_text = (await file.read()).decode("utf-8")
    if not yaml_text:
        raise HTTPException(status_code=400, detail="No YAML content provided")

    meta = _parse_yaml_meta(yaml_text)
    if not meta.get("rule_id"):
        raise HTTPException(status_code=400, detail="YAML must have an 'id' field")

    conn = get_connection()
    try:
        conn.execute("""
            INSERT OR REPLACE INTO rules
                (rule_id, title, description, severity, technique, yaml_text, is_custom, uploaded_by)
            VALUES (?,?,?,?,?,?,1,?)
        """, (
            meta["rule_id"], meta["title"], meta["description"],
            meta["severity"], meta["technique"], yaml_text, user.get("email", "Admin")
        ))
        conn.commit()
        
        # FIX: Ghost Rule flaw - write the physical .yml file for engine.py
        rule_path = RULES_DIR / f"{meta['rule_id']}.yml"
        rule_path.write_text(yaml_text, encoding="utf-8")
        
        return {
            "status": "uploaded", "rule_id": meta["rule_id"],
            "title": meta["title"], "rules_loaded": 1,
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# DELETE /rules/{rule_id}
# ---------------------------------------------------------------------------
@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str, request: Request):
    _user(request)
    RULES_DIR = pathlib.Path(__file__).parent.parent / "detection" / "rules"
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        if not row["is_custom"]:
            raise HTTPException(status_code=403, detail="Built-in rules cannot be deleted")
        conn.execute("DELETE FROM rules WHERE rule_id=?", (rule_id,))
        conn.commit()

        # FIX: Ghost Rule flaw - delete the physical .yml file
        rule_path = RULES_DIR / f"{rule_id}.yml"
        if rule_path.exists():
            rule_path.unlink()

        return {"status": "deleted", "rule_id": rule_id}
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# GET /rules/{rule_id}/sql
# ---------------------------------------------------------------------------
@router.get("/rules/{rule_id}/sql")
def get_rule_sql(rule_id: str, request: Request):
    _user(request)
    conn = get_connection()
    try:
        row = conn.execute("SELECT yaml_text FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Rule not found")
        yaml_text = row["yaml_text"]
        if not yaml_text:
            return {"rule_id": rule_id, "sql": "Error: Rule has no YAML text."}
            
        try:
            collection = SigmaCollection.from_yaml(yaml_text)
            backend = sqliteBackend()
            results = backend.convert(collection)
            if not results:
                raw_sql = "Error: pySigma backend returned no queries."
            else:
                raw_sql = results[0].replace("<TABLE_NAME>", "logs")
        except Exception as e:
            raw_sql = f"Error compiling rule: {str(e)}"
            
        return {"rule_id": rule_id, "sql": raw_sql}
    finally:
        conn.close()

