"""SQLite persistence: scan history + per-domain results (enables change detection)."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DB = Path(os.environ.get("BUILDWITH_DB_PATH", Path(__file__).parent / "data" / "scans.db"))


@contextmanager
def db():
    DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, created_at REAL, total INTEGER, status TEXT);
        CREATE TABLE IF NOT EXISTS results(scan_id TEXT, domain TEXT, scanned_at REAL, data TEXT);
        CREATE INDEX IF NOT EXISTS ix_results_domain ON results(domain, scanned_at);
        CREATE INDEX IF NOT EXISTS ix_results_scan ON results(scan_id);
        """)
        # a server restart leaves unfinished scans behind
        c.execute("UPDATE scans SET status='interrupted' WHERE status='running'")


def create_scan(scan_id, total):
    with db() as c:
        c.execute("INSERT INTO scans VALUES (?,?,?,?)", (scan_id, time.time(), total, "running"))


def finish_scan(scan_id):
    with db() as c:
        c.execute("UPDATE scans SET status='done' WHERE id=?", (scan_id,))


def previous_result(domain, scan_id):
    """Latest earlier successful result for this domain (from another scan)."""
    with db() as c:
        rows = c.execute("SELECT data, scanned_at FROM results WHERE domain=? AND scan_id!=? "
                         "ORDER BY scanned_at DESC LIMIT 5", (domain, scan_id)).fetchall()
    for r in rows:
        data = json.loads(r["data"])
        if data.get("ok"):
            return data, r["scanned_at"]
    return None, None


def add_result(scan_id, result):
    with db() as c:
        c.execute("INSERT INTO results VALUES (?,?,?,?)",
                  (scan_id, result["domain"], time.time(), json.dumps(result)))


def list_scans(limit=50):
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, created_at, total, status FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))]


def get_scan(scan_id):
    with db() as c:
        s = c.execute("SELECT id, created_at, total, status FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not s:
            return None
        rows = c.execute("SELECT data FROM results WHERE scan_id=? ORDER BY rowid", (scan_id,)).fetchall()
    scan = dict(s)
    scan["results"] = [json.loads(r["data"]) for r in rows]
    scan["done"] = len(scan["results"])
    return scan
