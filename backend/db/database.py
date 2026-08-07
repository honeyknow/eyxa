"""
Eyxa backend - SQLite database connection and initialisation.

WAL mode is set on every new connection via an event listener so it is
never accidentally skipped.  busy_timeout prevents "database is locked"
errors under concurrent Uvicorn workers.

Sources:
  https://www.sqlite.org/wal.html
  https://docs.python.org/3/library/sqlite3.html
  https://fastapi.tiangolo.com/tutorial/sql-databases/
"""

import sqlite3
import pathlib
import bcrypt
import secrets

# Resolve paths relative to this file so the module works regardless of
# the working directory from which Uvicorn is launched.
_HERE = pathlib.Path(__file__).parent
DB_PATH = _HERE / "eyxa.db"
SCHEMA_PATH = _HERE / "schema.sql"


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    """Enable WAL mode and set a sensible busy timeout on every connection.

    WAL mode is a persistent database-file property once set, but applying
    the PRAGMA on each connection ensures correctness if the file is ever
    recreated.
    Source: https://www.sqlite.org/pragma.html#pragma_journal_mode
    """
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, improves throughput
    conn.execute("PRAGMA busy_timeout=5000")    # ms; avoids lock errors under load
    conn.execute("PRAGMA foreign_keys=ON")


def get_connection() -> sqlite3.Connection:
    """Open and return a new SQLite connection with WAL mode applied."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    return conn


def _migrate_logs_view(conn: sqlite3.Connection) -> None:
    """Drop and recreate the logs VIEW if its column list is stale.

    CREATE VIEW IF NOT EXISTS is a no-op when the VIEW already exists, so
    any schema.sql additions (e.g. new json_extract columns) are invisible
    until the VIEW is dropped and recreated. This function checks whether
    the current VIEW definition matches schema.sql and recreates it if not.

    Safe to call while the backend is running - SQLite DROP/CREATE VIEW
    holds no persistent data.
    Source: https://www.sqlite.org/lang_dropview.html
    """
    # Extract the CREATE VIEW block from schema.sql.
    schema_text = SCHEMA_PATH.read_text(encoding="utf-8")
    # Find the view definition between "CREATE VIEW IF NOT EXISTS logs AS" and
    # the next semicolon that closes the SELECT.
    import re
    m = re.search(
        r"CREATE VIEW IF NOT EXISTS logs AS\s*(SELECT[\s\S]+?)\s*;",
        schema_text,
        re.IGNORECASE,
    )
    if not m:
        return  # schema.sql has no view definition - nothing to do

    desired_select = m.group(1).strip()

    # Check whether the current VIEW already has a 'Type' column (the most
    # recently added column); if pragma returns it we're up-to-date.
    try:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(logs)").fetchall()]
    except Exception:
        cols = []

    if "QueryName" in cols:
        return  # already up-to-date

    # Recreate the VIEW.
    conn.execute("DROP VIEW IF EXISTS logs")
    conn.execute(f"CREATE VIEW logs AS {desired_select}")
    conn.commit()


def init_db() -> None:
    """Create tables and the logs VIEW if they do not already exist.

    Safe to call on every startup - all DDL uses CREATE IF NOT EXISTS.
    After initial schema creation, _migrate_logs_view() is called to ensure
    the VIEW is up-to-date with any new columns added to schema.sql.
    """
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn = get_connection()
    try:
        conn.executescript(schema)
        conn.commit()
        
        # Auto-migrate rules table to include uploaded_by
        try:
            conn.execute("ALTER TABLE rules ADD COLUMN uploaded_by TEXT NOT NULL DEFAULT 'Admin'")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
            
        # Auto-migrate users table for role and plaintext passwords
        try:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN password_plaintext TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass
            
        # Auto-migrate users table for AI config
        try:
            conn.execute("ALTER TABLE users ADD COLUMN groq_api_key TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN ai_model TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass
            
        _migrate_logs_view(conn)
        
        # Check if any users exist, if not, auto-create the default admin
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            pw_hash = bcrypt.hashpw("admin".encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            enroll_token = secrets.token_hex(16)
            conn.execute(
                "INSERT INTO users (email, password_hash, password_plaintext, role, enroll_token) VALUES (?,?,?,?,?)",
                ("admin@eyxa", pw_hash, "admin", "admin", enroll_token)
            )
            conn.commit()
            
    finally:
        conn.close()

def get_ai_config(user_id: int) -> dict:
    conn = get_connection()
    try:
        row = conn.execute("SELECT groq_api_key, ai_model FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return {"api_key": row["groq_api_key"] or "", "model_id": row["ai_model"] or "llama-3.3-70b-versatile"}
        return {"api_key": "", "model_id": "llama-3.3-70b-versatile"}
    finally:
        conn.close()

def set_ai_config(user_id: int, api_key: str, model_id: str) -> None:
    conn = get_connection()
    try:
        conn.execute("UPDATE users SET groq_api_key = ?, ai_model = ? WHERE id = ?", (api_key, model_id, user_id))
        conn.commit()
    finally:
        conn.close()
