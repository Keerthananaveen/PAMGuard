"""Local SIEM-style event export, ingestion, and search for the PAMGuard lab."""
import json
from datetime import datetime, timezone
from pathlib import Path

from app.database import get_connection


def ingest_incidents(incidents, source="local-analyzer"):
    """Persist normalized incident events idempotently in SQLite."""
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS siem_events (
        event_key TEXT PRIMARY KEY, source TEXT NOT NULL,
        event_time TEXT, severity TEXT, event_type TEXT,
        username TEXT, hostname TEXT, source_ip TEXT,
        payload_json TEXT NOT NULL, ingested_at TEXT NOT NULL)""")
    inserted = 0
    for item in incidents:
        event_key = str(item.get("incident_id") or "")
        if not event_key:
            continue
        cur = conn.execute("""INSERT OR IGNORE INTO siem_events
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
          (event_key, source, item.get("event_timestamp"), item.get("severity"),
           item.get("incident_type"), item.get("username"), item.get("hostname"),
           item.get("source_ip"), json.dumps(item, sort_keys=True),
           datetime.now(timezone.utc).isoformat()))
        inserted += cur.rowcount
    conn.commit()
    conn.close()
    return inserted


def search_events(text_query=None, severity=None, limit=100):
    """Search the local event table with bounded, parameterized filters."""
    limit = max(1, min(int(limit), 500))
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS siem_events (
        event_key TEXT PRIMARY KEY, source TEXT NOT NULL, event_time TEXT,
        severity TEXT, event_type TEXT, username TEXT, hostname TEXT,
        source_ip TEXT, payload_json TEXT NOT NULL, ingested_at TEXT NOT NULL)""")
    clauses, params = [], []
    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())
    if text_query:
        clauses.append("(event_key LIKE ? OR event_type LIKE ? OR username LIKE ? OR hostname LIKE ? OR source_ip LIKE ?)")
        params.extend([f"%{text_query}%"] * 5)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    rows = conn.execute("SELECT payload_json FROM siem_events" + where + " ORDER BY ingested_at DESC LIMIT ?", (*params, limit)).fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]


def export_events(path="reports/siem/events.json"):
    events = search_events(limit=500)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"format": "PAMGuard-local-events-v1", "events": events}, indent=2), encoding="utf-8")
    return str(target)
