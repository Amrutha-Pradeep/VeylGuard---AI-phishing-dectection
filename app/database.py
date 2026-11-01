import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    """Get a database connection for the current request."""
    if "db" not in g:
        database_path = current_app.config["DATABASE"]
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(database_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    """Create the scan history table and apply any pending column migrations."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL DEFAULT (
                                strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')
                            ),
            sender          TEXT    NOT NULL,
            subject         TEXT    NOT NULL,
            score           INTEGER NOT NULL,
            rule_score      INTEGER,
            ai_contribution INTEGER,
            category        TEXT    NOT NULL,
            findings        TEXT    NOT NULL,
            ai_verdict      TEXT,
            ai_confidence   INTEGER
        )
    """)

    # Graceful migrations: add columns introduced after initial release
    existing_cols = {
        row[1]
        for row in db.execute("PRAGMA table_info(scan_history)").fetchall()
    }
    migrations = [
        ("rule_score",      "ALTER TABLE scan_history ADD COLUMN rule_score INTEGER"),
        ("ai_contribution", "ALTER TABLE scan_history ADD COLUMN ai_contribution INTEGER"),
    ]
    for col_name, sql in migrations:
        if col_name not in existing_cols:
            db.execute(sql)

    db.commit()


def close_db(error=None):
    """Close the database connection after a request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def save_scan(sender, subject, score, category, findings,
              rule_score=None, ai_contribution=None,
              ai_verdict=None, ai_confidence=None):
    """Persist a completed scan; the full email body is never stored."""
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO scan_history
            (sender, subject, score, rule_score, ai_contribution,
             category, findings, ai_verdict, ai_confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (sender, subject, score, rule_score, ai_contribution,
         category, findings, ai_verdict, ai_confidence),
    )
    db.commit()
    return cursor.lastrowid


def delete_scan(scan_id):
    """Delete one scan; returns True if the row existed."""
    db = get_db()
    cursor = db.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
    db.commit()
    return cursor.rowcount > 0


def clear_history():
    """Delete every saved scan."""
    db = get_db()
    db.execute("DELETE FROM scan_history")
    db.commit()
