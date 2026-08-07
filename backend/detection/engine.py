# eyxa/backend/detection/engine.py
# Phase 5 - 30-second polling detection engine.
# Loads Sigma rules from detection/rules/*.yml, compiles each through
# pySigma-backend-sqlite, then every 30 seconds evaluates the last 30-second
# window of events for every enrolled (user_id, agent_id) pair.
# Approved design: Phase 5 plan 2026-07-27.
#
# Source (pySigma-backend-sqlite API):
#   https://github.com/SigmaHQ/pySigma-backend-sqlite
# Source (pySigma SigmaCollection):
#   https://github.com/SigmaHQ/pySigma

import asyncio
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import yaml

from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

logger = logging.getLogger("eyxa.detection")

RULES_DIR   = Path(__file__).parent / "rules"
POLL_SECS   = 30
DB_PATH     = Path(__file__).parent.parent / "db" / "eyxa.db"

# Map Sigma logsource category → Sysmon EventID injected into every query.
# Source: Sysmon event schema 4.91, verified Phase 3.
CATEGORY_EVENTID: dict[str, int] = {
    "process_creation":    1,
    "create_remote_thread": 8,
    "registry_set":        13,
    "registry_add":        12,
    "registry_delete":     12,
    # Source: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    # EID 25 = ProcessTampering (process image replaced in memory - hollowing).
    # Required for rule: t1055_process_hollowing.yml (logsource.category: process_tampering)
    "process_tampering":   25,
}

# Map Sigma logsource service → (EventID, Channel) for non-Sysmon sources.
SERVICE_FILTER: dict[str, tuple[int, str]] = {
    "windefend": (5001, "Microsoft-Windows-Windows Defender/Operational"),
}

# ATT&CK tag regex - first match wins.
_ATT_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _extract_technique(tags: list) -> str:
    """Return first ATT&CK technique tag, e.g. 'T1059.001', or 'unknown'."""
    for tag in tags or []:
        m = _ATT_RE.search(str(tag))
        if m:
            return m.group(1).upper()
    return "unknown"


class CompiledRule:
    """A Sigma rule compiled to a raw SQLite WHERE clause."""

    def __init__(self, path: Path):
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        self.path      = path
        self.rule_id   = raw.get("id", "")
        self.title     = raw.get("title", path.stem)
        self.level     = raw.get("level", "medium")
        self.technique = _extract_technique(raw.get("tags", []))

        logsource  = raw.get("logsource", {})
        self.category = logsource.get("category", "")
        self.service  = logsource.get("service", "")

        # Determine EventID filter to inject.
        self.event_id: Optional[int] = None
        self.channel:  Optional[str] = None
        if self.category in CATEGORY_EVENTID:
            self.event_id = CATEGORY_EVENTID[self.category]
        elif self.service in SERVICE_FILTER:
            self.event_id, self.channel = SERVICE_FILTER[self.service]

        # Compile through pySigma-backend-sqlite.
        # Source: https://github.com/SigmaHQ/pySigma-backend-sqlite
        try:
            collection  = SigmaCollection.from_yaml(open(path, encoding="utf-8").read())
            backend     = sqliteBackend()
            results     = backend.convert(collection)
            # backend.convert returns a list of SQL strings (one per rule).
            if not results:
                raise ValueError("backend returned no queries")
            self.raw_sql: str = results[0].replace("<TABLE_NAME>", "logs")
            self.ok = True
        except Exception as exc:
            logger.warning("[engine] rule %s failed to compile: %s", path.name, exc)
            self.raw_sql = ""
            self.ok = False

    def build_query(self) -> tuple[str, list]:
        """
        Wrap the pySigma-generated SELECT with:
          - user isolation  (user_id = ?)
          - time window       (received_at >= ?)
          - EventID filter    (if applicable)
        Returns (sql, []) - parameters injected per-call in run_poll().
        """
        inner = self.raw_sql  # SELECT * FROM logs WHERE <conditions>

        where_extra = []
        if self.event_id is not None:
            where_extra.append(f"l.EventID = {self.event_id}")
        if self.channel is not None:
            where_extra.append(f"l.Channel = '{self.channel}'")
        where_extra += ["l.user_id = ?", "l.received_at >= ?"]

        extra_clause = " AND ".join(where_extra)
        sql = f"SELECT l.id, l.agent_id FROM ({inner}) l WHERE {extra_clause}"
        return sql, []


def _load_rules() -> list[CompiledRule]:
    rules = []
    for yml in sorted(RULES_DIR.glob("*.yml")):
        r = CompiledRule(yml)
        if r.ok:
            logger.info("[engine] loaded rule '%s' (%s)", r.title, r.rule_id)
        rules.append(r)
    ok = sum(1 for r in rules if r.ok)
    logger.info("[engine] %d/%d rules compiled successfully", ok, len(rules))
    return [r for r in rules if r.ok]


def _get_agents(conn: sqlite3.Connection) -> list[tuple[int, int]]:
    """Return list of (user_id, agent_id) for all enrolled agents."""
    rows = conn.execute("SELECT user_id, id FROM agents").fetchall()
    return [(r[0], r[1]) for r in rows]


def _poll_once(rules: list[CompiledRule]) -> None:
    """One 30-second evaluation pass across all users and all rules."""
    if not rules:
        return

    window_start = (
        datetime.now(timezone.utc) - timedelta(seconds=POLL_SECS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        agents = _get_agents(conn)
        if not agents:
            return
            
        # Fetch enabled status for all rules from the DB
        enabled_rules_db = {row[0]: row[1] for row in conn.execute("SELECT rule_id, enabled FROM rules").fetchall()}

        for rule in rules:
            # Skip if rule is explicitly disabled in the database
            if enabled_rules_db.get(rule.rule_id, 1) == 0:
                continue
                
            sql_tmpl, _ = rule.build_query()
            for user_id, agent_id in agents:
                try:
                    rows = conn.execute(
                        sql_tmpl, (user_id, window_start)
                    ).fetchall()
                except Exception as exc:
                    logger.warning(
                        "[engine] rule '%s' query error (user=%d): %s",
                        rule.title, user_id, exc,
                    )
                    continue

                if not rows:
                    continue

                # Filter to only this agent's events.
                hit_ids = [r[0] for r in rows if r[1] == agent_id]
                if not hit_ids:
                    continue

                logger.warning(
                    "[ALERT] rule='%s' user=%d agent=%d events=%s",
                    rule.title, user_id, agent_id, hit_ids,
                )
                conn.execute(
                    """
                    INSERT INTO alerts
                        (user_id, agent_id, rule_id, rule_title, rule_level,
                         technique, matching_event_ids, raw_sql)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        user_id,
                        agent_id,
                        rule.rule_id,
                        rule.title,
                        rule.level,
                        rule.technique,
                        json.dumps(hit_ids),
                        rule.raw_sql,
                    ),
                )
                now_ts = int(datetime.now(timezone.utc).timestamp())
                conn.execute(
                    "UPDATE rules SET hit_count = hit_count + 1, last_fired_at = ? WHERE rule_id = ?",
                    (now_ts, rule.rule_id)
                )
        conn.commit()
    finally:
        conn.close()


async def engine_loop() -> None:
    """
    Async loop: compile rules once at startup, then poll every 30 seconds.
    Designed to run as a FastAPI lifespan background task.
    """
    logger.info("[engine] starting - hot-reload enabled from %s", RULES_DIR)

    while True:
        try:
            # FIX: Ghost Rule flaw - hot reload rules on every pass
            rules = _load_rules()
            _poll_once(rules)
        except Exception as exc:
            logger.error("[engine] poll error: %s", exc)
        await asyncio.sleep(POLL_SECS)
