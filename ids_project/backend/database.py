"""
database.py
SQLite persistence layer for the IDS: users, alerts, feedback/training
snapshots, and runtime configuration. Kept dependency-free (stdlib sqlite3)
so the storage layer has no extra install requirements.
"""
import sqlite3
import json
import threading
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "ids_data.db"

_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def db_cursor():
    with _lock:
        conn = get_conn()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        finally:
            conn.close()


def init_db():
    with db_cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            threat_score REAL NOT NULL,
            source_ip TEXT,
            source_mac TEXT,
            gateway_ip TEXT,
            old_mac TEXT,
            new_mac TEXT,
            description TEXT,
            features_json TEXT,
            shap_json TEXT,
            detection_stage TEXT,
            feedback_label TEXT DEFAULT NULL,
            pcap_path TEXT
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback_dataset (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            features_json TEXT NOT NULL,
            label INTEGER NOT NULL, -- 1 = true positive (attack), 0 = false positive (benign)
            created_at REAL NOT NULL
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS mac_ip_state (
            ip TEXT PRIMARY KEY,
            mac TEXT NOT NULL,
            status TEXT DEFAULT 'legitimate',
            last_seen REAL NOT NULL,
            first_seen REAL NOT NULL,
            mac_change_count INTEGER DEFAULT 0
        )""")

        # sensible defaults
        defaults = {
            "interface": "eth0",
            "threshold_low": "0.4",
            "threshold_high": "0.7",
            "gratuitous_burst_count": "3",
            "gratuitous_burst_window_sec": "30",
            "whitelist_gateway_macs": json.dumps([]),
        }
        for k, v in defaults.items():
            cur.execute(
                "INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)", (k, v)
            )

        # default admin user: admin / admin123 (bcrypt hash generated at import time)
        cur.execute("SELECT COUNT(*) as c FROM users")
        if cur.fetchone()["c"] == 0:
            from auth import hash_password
            cur.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                ("admin", "admin@example.com", hash_password("admin123"), time.time()),
            )


def get_config():
    with db_cursor() as cur:
        cur.execute("SELECT key, value FROM config")
        rows = cur.fetchall()
    return {r["key"]: r["value"] for r in rows}


def set_config(key: str, value: str):
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )


def insert_alert(alert: dict) -> int:
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO alerts (timestamp, alert_type, severity, threat_score,
                source_ip, source_mac, gateway_ip, old_mac, new_mac, description,
                features_json, shap_json, detection_stage, pcap_path)
            VALUES (:timestamp, :alert_type, :severity, :threat_score, :source_ip,
                :source_mac, :gateway_ip, :old_mac, :new_mac, :description,
                :features_json, :shap_json, :detection_stage, :pcap_path)
        """, alert)
        return cur.lastrowid


def list_alerts(start_ts=None, end_ts=None, severity=None, limit=500):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if start_ts is not None:
        query += " AND timestamp >= ?"
        params.append(start_ts)
    if end_ts is not None:
        query += " AND timestamp <= ?"
        params.append(end_ts)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
    return rows


def get_alert(alert_id: int):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def set_feedback(alert_id: int, label: str):
    """label in {'true_positive', 'false_positive', 'ignore'}"""
    with db_cursor() as cur:
        cur.execute("UPDATE alerts SET feedback_label = ? WHERE id = ?", (label, alert_id))
        cur.execute("SELECT features_json FROM alerts WHERE id = ?", (alert_id,))
        row = cur.fetchone()
        if row and label in ("true_positive", "false_positive"):
            numeric_label = 1 if label == "true_positive" else 0
            cur.execute("""
                INSERT INTO feedback_dataset (alert_id, features_json, label, created_at)
                VALUES (?, ?, ?, ?)
            """, (alert_id, row["features_json"], numeric_label, time.time()))


def get_feedback_dataset():
    with db_cursor() as cur:
        cur.execute("SELECT features_json, label FROM feedback_dataset")
        rows = cur.fetchall()
    return [(json.loads(r["features_json"]), r["label"]) for r in rows]


def clear_training_data():
    with db_cursor() as cur:
        cur.execute("DELETE FROM feedback_dataset")


def clear_all_logs():
    with db_cursor() as cur:
        cur.execute("DELETE FROM alerts")
        cur.execute("DELETE FROM feedback_dataset")


def upsert_mac_ip(ip, mac, status, now):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM mac_ip_state WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row is None:
            cur.execute("""
                INSERT INTO mac_ip_state (ip, mac, status, last_seen, first_seen, mac_change_count)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (ip, mac, status, now, now))
        else:
            change_count = row["mac_change_count"]
            if row["mac"] != mac:
                change_count += 1
            cur.execute("""
                UPDATE mac_ip_state SET mac=?, status=?, last_seen=?, mac_change_count=?
                WHERE ip=?
            """, (mac, status, now, change_count, ip))


def get_mac_ip_table():
    with db_cursor() as cur:
        cur.execute("SELECT * FROM mac_ip_state ORDER BY last_seen DESC LIMIT 200")
        rows = [dict(r) for r in cur.fetchall()]
    return rows


def get_user_by_username(username: str):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    return dict(row) if row else None


def update_user(user_id: int, email=None, password_hash=None):
    with db_cursor() as cur:
        if email is not None:
            cur.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        if password_hash is not None:
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
