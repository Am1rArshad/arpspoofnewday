"""
database.py
SQLite persistence layer for the IDS: users, alerts, feedback/training
snapshots, and runtime configuration. Kept dependency-free (stdlib sqlite3)
so the storage layer has no extra install requirements.
"""
import sqlite3
import json
import socket
import threading
import time
from pathlib import Path
from contextlib import contextmanager

import psutil

DB_PATH = Path(__file__).parent / "ids_data.db"
ALERTS_PATH = Path(__file__).parent / "alerts.json"

_lock = threading.Lock()
_alerts_lock = threading.Lock()


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
        CREATE TABLE IF NOT EXISTS unknown_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            op_code TEXT,
            raw_json TEXT NOT NULL,
            features_json TEXT NOT NULL,
            reviewed_at REAL,
            analyst_decision TEXT,
            UNIQUE(timestamp, src_ip, src_mac, op_code)
        )""")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS active_learning_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unknown_packet_id INTEGER UNIQUE NOT NULL,
            timestamp REAL,
            src_ip TEXT, dst_ip TEXT, src_mac TEXT, dst_mac TEXT, op_code TEXT,
            ip_mac_binding_delta INTEGER, replies_last_60s INTEGER,
            seconds_since_ip_first_seen REAL, is_gratuitous INTEGER,
            unsolicited_reply_ratio REAL, request_rate REAL,
            distinct_mac_count INTEGER, distinct_target_ips INTEGER,
            packet_freq REAL, features_json TEXT NOT NULL,
            analyst_decision TEXT NOT NULL, label INTEGER,
            reviewed_at REAL NOT NULL, retrained_at REAL
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
            "interface": "ens33",
            "dashboard_interface": "ens37",
            "threshold_low": "0.4",
            "threshold_high": "0.7",
            "gratuitous_burst_count": "3",
            "gratuitous_burst_window_sec": "30",
            "whitelist_gateway_macs": json.dumps([]),
            "email_notifications_enabled": "false",
            "smtp_host": "",
            "smtp_port": "587",
            "smtp_username": "",
            "smtp_password": "",
            "smtp_use_tls": "true",
            "notification_email": "",
            "email_min_severity": "High",
            "ntfy_notifications_enabled": "false",
            "ntfy_server": "https://ntfy.sh",
            "ntfy_topic": "",
            "ntfy_token": "",
            "ntfy_min_severity": "High",
        }
        for k, v in defaults.items():
            cur.execute(
                "INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)", (k, v)
            )
        cur.execute("UPDATE config SET value = 'ens33' WHERE key = 'interface' AND value = 'eth0'")

        _migrate_alerts_to_json(cur)

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


def _read_alerts_unlocked():
    if not ALERTS_PATH.exists():
        return []
    try:
        with ALERTS_PATH.open(encoding="utf-8") as file:
            alerts = json.load(file)
        return alerts if isinstance(alerts, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write_alerts_unlocked(alerts):
    temporary_path = ALERTS_PATH.with_suffix(".json.tmp")
    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, separators=(",", ":"))
        file.flush()
    temporary_path.replace(ALERTS_PATH)


def _migrate_alerts_to_json(cur):
    if ALERTS_PATH.exists():
        return
    cur.execute("SELECT * FROM alerts ORDER BY timestamp ASC")
    alerts = [dict(row) for row in cur.fetchall()]
    with _alerts_lock:
        _write_alerts_unlocked(alerts)


def insert_alert(alert: dict) -> int:
    with _alerts_lock:
        alerts = _read_alerts_unlocked()
        alert = {**alert, "id": max((item.get("id", 0) for item in alerts), default=0) + 1}
        alerts.append(alert)
        _write_alerts_unlocked(alerts)
        return alert["id"]


def list_alerts(start_ts=None, end_ts=None, severity=None, limit=500):
    with _alerts_lock:
        alerts = _read_alerts_unlocked()
    if start_ts is not None:
        alerts = [alert for alert in alerts if alert.get("timestamp", 0) >= start_ts]
    if end_ts is not None:
        alerts = [alert for alert in alerts if alert.get("timestamp", 0) <= end_ts]
    if severity:
        alerts = [alert for alert in alerts if alert.get("severity") == severity]
    return sorted(alerts, key=lambda alert: alert.get("timestamp", 0), reverse=True)[:limit]


def get_alert(alert_id: int):
    with _alerts_lock:
        return next((alert for alert in _read_alerts_unlocked() if alert.get("id") == alert_id), None)


def set_feedback(alert_id: int, label: str):
    """label in {'true_positive', 'false_positive', 'ignore'}"""
    with _alerts_lock:
        alerts = _read_alerts_unlocked()
        alert = next((item for item in alerts if item.get("id") == alert_id), None)
        if alert is None:
            return False
        alert["feedback_label"] = label
        _write_alerts_unlocked(alerts)

    features_json = alert.get("features_json") or "{}"
    with db_cursor() as cur:
        if label in ("true_positive", "false_positive"):
            numeric_label = 1 if label == "true_positive" else 0
            cur.execute("""
                INSERT INTO feedback_dataset (alert_id, features_json, label, created_at)
                VALUES (?, ?, ?, ?)
            """, (alert_id, features_json, numeric_label, time.time()))
    return True


def get_feedback_dataset():
    with db_cursor() as cur:
        cur.execute("""SELECT features_json, label FROM feedback_dataset
                      UNION ALL
                      SELECT features_json, label FROM active_learning_feedback
                      WHERE label IS NOT NULL AND analyst_decision != 'IGNORE'""")
        rows = cur.fetchall()
    return [(json.loads(r["features_json"]), r["label"]) for r in rows]


def insert_unknown_packet(packet: dict) -> int:
    with db_cursor() as cur:
        cur.execute("""
            INSERT OR IGNORE INTO unknown_packets
            (timestamp, src_ip, dst_ip, src_mac, dst_mac, op_code, raw_json, features_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (packet["timestamp"], packet["src_ip"], packet["dst_ip"], packet["src_mac"],
              packet["dst_mac"], packet["op_code"], json.dumps(packet),
              json.dumps(packet["features"])))
        if cur.rowcount == 0:
            cur.execute("""SELECT id FROM unknown_packets
                          WHERE timestamp=? AND src_ip=? AND src_mac=? AND op_code=?""",
                        (packet["timestamp"], packet["src_ip"], packet["src_mac"], packet["op_code"]))
            return cur.fetchone()[0]
        return cur.lastrowid


def list_unknown_packets(limit=500):
    with db_cursor() as cur:
        cur.execute("""SELECT * FROM unknown_packets WHERE reviewed_at IS NULL
                      ORDER BY timestamp DESC LIMIT ?""", (limit,))
        rows = cur.fetchall()
    return [{**dict(row), "raw": json.loads(row["raw_json"]), "features": json.loads(row["features_json"])} for row in rows]


def get_unknown_packet(packet_id):
    with db_cursor() as cur:
        cur.execute("SELECT * FROM unknown_packets WHERE id = ?", (packet_id,))
        row = cur.fetchone()
    if not row:
        return None
    return {**dict(row), "raw": json.loads(row["raw_json"]), "features": json.loads(row["features_json"])}


def get_verified_packet_label(src_ip, dst_ip, src_mac, dst_mac, op_code):
    """Return the latest analyst label for this recurring ARP signature."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT label FROM active_learning_feedback
            WHERE src_ip = ? AND dst_ip = ? AND src_mac = ? AND dst_mac = ?
              AND op_code = ? AND label IS NOT NULL
            ORDER BY reviewed_at DESC LIMIT 1
        """, (src_ip, dst_ip, src_mac, dst_mac, op_code))
        row = cur.fetchone()
    return None if row is None else int(row["label"])


def submit_unknown_feedback(packet_id: int, decision: str, features: dict, label: int | None):
    now = time.time()
    packet = get_unknown_packet(packet_id)
    if not packet or packet["reviewed_at"] is not None:
        return False
    with db_cursor() as cur:
        cur.execute("UPDATE unknown_packets SET reviewed_at=?, analyst_decision=? WHERE id=?", (now, decision, packet_id))
        if label is None:
            return True
        cur.execute("""
            INSERT INTO active_learning_feedback
            (unknown_packet_id, timestamp, src_ip, dst_ip, src_mac, dst_mac, op_code,
             ip_mac_binding_delta, replies_last_60s, seconds_since_ip_first_seen,
             is_gratuitous, unsolicited_reply_ratio, request_rate, distinct_mac_count,
             distinct_target_ips, packet_freq, features_json, analyst_decision, label, reviewed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (packet_id, packet["timestamp"], packet["src_ip"], packet["dst_ip"], packet["src_mac"],
              packet["dst_mac"], packet["op_code"], features.get("ip_mac_binding_delta", 0),
              features.get("replies_last_60s", 0), features.get("seconds_since_ip_first_seen", 0),
              features.get("is_gratuitous", 0), features.get("unsolicited_reply_ratio", 0),
              features.get("requests_last_60s", 0), features.get("unique_macs_for_ip_seen", 0),
              features.get("distinct_target_ips", 0), features.get("packet_freq", 0),
              json.dumps(features), decision, label, now))
    return True


def pending_feedback_count():
    with db_cursor() as cur:
        cur.execute("""SELECT COUNT(*) FROM active_learning_feedback
                      WHERE label IS NOT NULL AND analyst_decision != 'IGNORE' AND retrained_at IS NULL""")
        return cur.fetchone()[0]


def mark_feedback_retrained():
    with db_cursor() as cur:
        cur.execute("""UPDATE active_learning_feedback SET retrained_at=?
                      WHERE label IS NOT NULL AND analyst_decision != 'IGNORE' AND retrained_at IS NULL""", (time.time(),))


def clear_training_data():
    with db_cursor() as cur:
        cur.execute("DELETE FROM feedback_dataset")


def clear_all_logs():
    with _alerts_lock:
        _write_alerts_unlocked([])
    with db_cursor() as cur:
        cur.execute("DELETE FROM feedback_dataset")


def clear_alert_logs():
    with _alerts_lock:
        _write_alerts_unlocked([])


def clear_unknown_queue():
    with db_cursor() as cur:
        cur.execute("DELETE FROM unknown_packets WHERE reviewed_at IS NULL")


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


def get_local_network_addresses():
    """Return the host's current IPv4 and MAC addresses."""
    local_ips = set()
    local_macs = set()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if address.family == socket.AF_INET:
                local_ips.add(address.address)
            elif address.family == psutil.AF_LINK:
                local_macs.add(address.address.lower())
    return local_ips, local_macs


def is_local_network_address(ip, mac):
    local_ips, local_macs = get_local_network_addresses()
    return ip in local_ips or (mac or "").lower() in local_macs


def get_mac_ip_table():
    local_ips, local_macs = get_local_network_addresses()

    with db_cursor() as cur:
        cur.execute("SELECT * FROM mac_ip_state ORDER BY last_seen DESC LIMIT 200")
        rows = [
            dict(row)
            for row in cur.fetchall()
            if row["ip"] not in local_ips
            and (row["mac"] or "").lower() not in local_macs
        ]
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
