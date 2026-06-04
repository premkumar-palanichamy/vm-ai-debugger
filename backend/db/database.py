"""SQLite persistence for VM investigation history."""
import os, sqlite3, json, uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DB_PATH", "vm_debugger.db"))

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                site_name TEXT,
                target_host TEXT,
                scan_mode TEXT DEFAULT 'full',
                status TEXT DEFAULT 'running',
                failure_category TEXT,
                severity TEXT,
                confidence INTEGER,
                root_cause TEXT,
                summary TEXT,
                evidence TEXT,
                analysis TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                helpful INTEGER,
                comment TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES investigations(id)
            );
        """)

def save_investigation(site_name="", target_host="", scan_mode="full",
):
    inv_id = str(uuid.uuid4())
    # Support both old (namespace) and new (site_name) calling convention
    resolved_site = site_name or namespace or "vm"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO investigations (id, site_name, target_host, scan_mode, status, created_at) VALUES (?,?,?,?,?,?)",
            (inv_id, resolved_site, target_host or "", scan_mode, "running",
             datetime.now(timezone.utc).isoformat())
        )
    return inv_id

def update_investigation(inv_id, result):
    analysis = result.get("analysis", {})
    with get_conn() as conn:
        conn.execute("""
            UPDATE investigations SET
                status=?, failure_category=?, severity=?, confidence=?,
                root_cause=?, summary=?, evidence=?, analysis=?, completed_at=?
            WHERE id=?
        """, (
            "completed",
            analysis.get("failure_category"),
            analysis.get("severity"),
            analysis.get("confidence"),
            analysis.get("root_cause"),
            analysis.get("summary"),
            json.dumps(result.get("evidence", {}), default=str),
            json.dumps(analysis, default=str),
            datetime.now(timezone.utc).isoformat(),
            inv_id,
        ))

def mark_investigation_error(inv_id, error):
    with get_conn() as conn:
        conn.execute(
            "UPDATE investigations SET status=?, root_cause=?, completed_at=? WHERE id=?",
            ("error", error[:500], datetime.now(timezone.utc).isoformat(), inv_id)
        )

def get_investigation(inv_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        for field in ("evidence", "analysis"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d

def list_investigations(namespace=None, limit=50):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, site_name, target_host, scan_mode, status, failure_category, severity, confidence, root_cause, summary, created_at, completed_at FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

def save_feedback(investigation_id, helpful, comment=None):
    fb_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO feedback (id, investigation_id, helpful, comment, created_at) VALUES (?,?,?,?,?)",
            (fb_id, investigation_id, int(helpful), comment,
             datetime.now(timezone.utc).isoformat())
        )
    return fb_id
