"""
main.py
FastAPI server tying together the sniffer, hybrid detection engine, SQLite
storage, authentication, and real-time WebSocket delivery to the React
dashboard.

Run (Linux, needs raw-socket privileges for the sniffer):
    sudo uvicorn main:app --host 0.0.0.0 --port 8000
"""
import asyncio
import csv
import io
import json
import logging
import smtplib
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from typing import Optional

import psutil
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

import database
import auth
from sniffer import Sniffer, list_interfaces

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ids.main")

app = FastAPI(title="ARP Spoofing / LAN MITM Intrusion Detection System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your dashboard's origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


metrics_manager = ConnectionManager()
alerts_manager = ConnectionManager()

sniffer: Optional[Sniffer] = None
main_loop: Optional[asyncio.AbstractEventLoop] = None


def handle_new_alert(alert_payload: dict):
    """Called from the sniffer's background thread. Persists the alert and
    schedules a broadcast on the asyncio event loop."""
    record = {
        "timestamp": alert_payload["timestamp"],
        "alert_type": alert_payload["alert_type"],
        "severity": alert_payload["severity"],
        "threat_score": alert_payload["threat_score"],
        "source_ip": alert_payload["source_ip"],
        "source_mac": alert_payload["source_mac"],
        "gateway_ip": alert_payload.get("gateway_ip"),
        "old_mac": alert_payload.get("old_mac"),
        "new_mac": alert_payload.get("new_mac"),
        "description": alert_payload["description"],
        "features_json": json.dumps(alert_payload["features"]),
        "shap_json": json.dumps(alert_payload["shap"]),
        "detection_stage": alert_payload["detection_stage"],
        "pcap_path": None,
    }
    alert_id = database.insert_alert(record)
    record["id"] = alert_id

    if main_loop:
        asyncio.run_coroutine_threadsafe(alerts_manager.broadcast(record), main_loop)
    send_alert_email(alert_payload)
    send_ntfy_notification(alert_payload)


SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


def _email_config():
    config = database.get_config()
    config["email_notifications_enabled"] = config.get("email_notifications_enabled", "false").lower() == "true"
    config["smtp_use_tls"] = config.get("smtp_use_tls", "true").lower() == "true"
    return config


def _send_email(subject: str, body: str, config: dict):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config["smtp_username"] or config["notification_email"]
    message["To"] = config["notification_email"]
    message.set_content(body)

    smtp_port = int(config.get("smtp_port") or 587)
    if config["smtp_use_tls"]:
        with smtplib.SMTP(config["smtp_host"], smtp_port, timeout=15) as server:
            server.starttls()
            if config.get("smtp_username"):
                server.login(config["smtp_username"], config.get("smtp_password", ""))
            server.send_message(message)
    else:
        with smtplib.SMTP_SSL(config["smtp_host"], smtp_port, timeout=15) as server:
            if config.get("smtp_username"):
                server.login(config["smtp_username"], config.get("smtp_password", ""))
            server.send_message(message)


def send_alert_email(alert_payload: dict):
    config = _email_config()
    minimum = config.get("email_min_severity", "High")
    if (
        not config["email_notifications_enabled"]
        or not config.get("smtp_host")
        or not config.get("notification_email")
        or SEVERITY_RANK.get(alert_payload.get("severity"), 0) < SEVERITY_RANK.get(minimum, 3)
    ):
        return

    body = (
        f"Severity: {alert_payload['severity']}\n"
        f"Alert type: {alert_payload['alert_type']}\n"
        f"Source IP: {alert_payload['source_ip']}\n"
        f"Source MAC: {alert_payload['source_mac']}\n\n"
        f"{alert_payload['description']}\n"
    )
    threading.Thread(
        target=_send_email_safely,
        args=(f"IDS {alert_payload['severity']} alert: {alert_payload['alert_type']}", body, config),
        daemon=True,
    ).start()


def _send_email_safely(subject: str, body: str, config: dict):
    try:
        _send_email(subject, body, config)
    except Exception:
        logger.exception("Unable to send IDS alert email")


def _send_ntfy(config: dict, title: str, body: str, priority: str):
    server = config.get("ntfy_server", "https://ntfy.sh").rstrip("/")
    topic = config.get("ntfy_topic", "").strip()
    request = urllib.request.Request(
        f"{server}/{topic}",
        data=body.encode("utf-8"),
        headers={
            "Title": title,
            "Priority": priority,
            "Tags": "rotating_light,shield",
            **({"Authorization": f"Bearer {config['ntfy_token']}"} if config.get("ntfy_token") else {}),
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        if response.status >= 300:
            raise RuntimeError(f"ntfy returned HTTP {response.status}")


def send_ntfy_notification(alert_payload: dict):
    config = _email_config()
    config["ntfy_notifications_enabled"] = config.get("ntfy_notifications_enabled", "false").lower() == "true"
    minimum = config.get("ntfy_min_severity", "High")
    if (
        not config["ntfy_notifications_enabled"]
        or not config.get("ntfy_topic")
        or SEVERITY_RANK.get(alert_payload.get("severity"), 0) < SEVERITY_RANK.get(minimum, 3)
    ):
        return

    priority = {"High": "urgent", "Medium": "high", "Low": "default"}.get(alert_payload["severity"], "default")
    body = (
        f"Severity: {alert_payload['severity']}\n"
        f"Alert type: {alert_payload['alert_type']}\n"
        f"Source: {alert_payload['source_ip']} ({alert_payload['source_mac']})\n\n"
        f"{alert_payload['description']}"
    )
    threading.Thread(
        target=_send_ntfy_safely,
        args=(config, f"IDS {alert_payload['severity']} alert", body, priority),
        daemon=True,
    ).start()


def _send_ntfy_safely(config: dict, title: str, body: str, priority: str):
    try:
        _send_ntfy(config, title, body, priority)
    except Exception:
        logger.exception("Unable to send ntfy notification")


def handle_state_update(ip, mac, status):
    pass  # mac/ip table is pulled on demand by the metrics loop; hook kept for extension


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup():
    global sniffer, main_loop
    database.init_db()
    main_loop = asyncio.get_event_loop()
    sniffer = Sniffer(on_alert=handle_new_alert, on_state_update=handle_state_update)
    sniffer.start()
    asyncio.create_task(metrics_broadcast_loop())


@app.on_event("shutdown")
async def shutdown():
    if sniffer:
        sniffer.stop()


async def metrics_broadcast_loop():
    """Streams system + traffic metrics to /ws/metrics clients every second."""
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            disk_io = psutil.disk_io_counters()
            traffic = sniffer.get_metrics() if sniffer else {}
            payload = {
                "timestamp": time.time(),
                "cpu_percent": cpu,
                "ram_percent": mem,
                "disk_read_bytes": disk_io.read_bytes if disk_io else 0,
                "disk_write_bytes": disk_io.write_bytes if disk_io else 0,
                "packets_per_sec": traffic.get("packets_per_sec", 0),
                "bandwidth_bytes_per_sec": traffic.get("bandwidth_bytes_per_sec", 0),
                "sniffer_running": traffic.get("running", False),
                "arp_mac_table": database.get_mac_ip_table()[:50],
            }
            await metrics_manager.broadcast(payload)
        except Exception:
            logger.exception("metrics loop error")
        await asyncio.sleep(1)


# ---------------------------------------------------------------------------
# WebSocket endpoints
# ---------------------------------------------------------------------------
@app.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket):
    await metrics_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keepalive / ignore client pings
    except WebSocketDisconnect:
        metrics_manager.disconnect(websocket)


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await alerts_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        alerts_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = auth.create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer", "username": user["username"], "email": user["email"]}


@app.get("/api/auth/me")
async def me(current_user=Depends(auth.get_current_user)):
    return {"username": current_user["username"], "email": current_user["email"]}


class UpdateAccountRequest(BaseModel):
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


@app.put("/api/auth/account")
async def update_account(req: UpdateAccountRequest, current_user=Depends(auth.get_current_user)):
    if req.new_password:
        if not req.current_password or not auth.verify_password(req.current_password, current_user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        database.update_user(current_user["id"], password_hash=auth.hash_password(req.new_password))
    if req.email:
        database.update_user(current_user["id"], email=req.email)
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# Config routes
# ---------------------------------------------------------------------------
@app.get("/api/config")
async def get_config(current_user=Depends(auth.get_current_user)):
    config = database.get_config()
    config["available_interfaces"] = list_interfaces()
    config["available_dashboard_interfaces"] = list_interfaces()
    config["whitelist_gateway_macs"] = json.loads(config.get("whitelist_gateway_macs", "[]"))
    config["email_notifications_enabled"] = config.get("email_notifications_enabled", "false").lower() == "true"
    config["smtp_use_tls"] = config.get("smtp_use_tls", "true").lower() == "true"
    config["smtp_password_configured"] = bool(config.get("smtp_password"))
    config.pop("smtp_password", None)
    config["ntfy_token_configured"] = bool(config.get("ntfy_token"))
    config.pop("ntfy_token", None)
    return config


class ConfigUpdateRequest(BaseModel):
    interface: Optional[str] = None
    dashboard_interface: Optional[str] = None
    threshold_low: Optional[float] = None
    threshold_high: Optional[float] = None
    gratuitous_burst_count: Optional[int] = None
    whitelist_gateway_macs: Optional[list[str]] = None
    email_notifications_enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    notification_email: Optional[str] = None
    email_min_severity: Optional[str] = None
    ntfy_notifications_enabled: Optional[bool] = None
    ntfy_server: Optional[str] = None
    ntfy_topic: Optional[str] = None
    ntfy_token: Optional[str] = None
    ntfy_min_severity: Optional[str] = None


@app.put("/api/config")
async def update_config(req: ConfigUpdateRequest, current_user=Depends(auth.get_current_user)):
    if req.interface is not None:
        database.set_config("interface", req.interface)
    if req.dashboard_interface is not None:
        database.set_config("dashboard_interface", req.dashboard_interface)
    if req.threshold_low is not None:
        database.set_config("threshold_low", req.threshold_low)
    if req.threshold_high is not None:
        database.set_config("threshold_high", req.threshold_high)
    if req.gratuitous_burst_count is not None:
        database.set_config("gratuitous_burst_count", req.gratuitous_burst_count)
    if req.whitelist_gateway_macs is not None:
        database.set_config("whitelist_gateway_macs", json.dumps(req.whitelist_gateway_macs))
    for key in (
        "email_notifications_enabled", "smtp_host", "smtp_port", "smtp_username",
        "smtp_use_tls", "notification_email", "email_min_severity",
        "ntfy_notifications_enabled", "ntfy_server", "ntfy_topic", "ntfy_min_severity",
    ):
        value = getattr(req, key)
        if value is not None:
            database.set_config(key, str(value).lower() if isinstance(value, bool) else value)
    if req.smtp_password:
        database.set_config("smtp_password", req.smtp_password)
    if req.ntfy_token:
        database.set_config("ntfy_token", req.ntfy_token)
    if sniffer:
        sniffer.reload_config()
    return {"status": "updated"}


class EmailTestRequest(BaseModel):
    recipient: Optional[str] = None


@app.post("/api/config/test-email")
async def test_email(req: EmailTestRequest, current_user=Depends(auth.get_current_user)):
    config = _email_config()
    recipient = req.recipient or config.get("notification_email")
    if not config.get("smtp_host") or not recipient:
        raise HTTPException(status_code=400, detail="Configure an SMTP host and notification email first")
    config["notification_email"] = recipient
    try:
        _send_email("IDS test notification", "This is a test email from your ARP IDS dashboard.", config)
    except Exception as exc:
        logger.exception("Unable to send test email")
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}") from exc
    return {"status": "sent"}


class NtfyTestRequest(BaseModel):
    server: Optional[str] = None
    topic: Optional[str] = None
    token: Optional[str] = None


@app.post("/api/config/test-ntfy")
async def test_ntfy(req: NtfyTestRequest, current_user=Depends(auth.get_current_user)):
    config = _email_config()
    config["ntfy_server"] = req.server or config.get("ntfy_server", "https://ntfy.sh")
    config["ntfy_topic"] = req.topic or config.get("ntfy_topic", "")
    if req.token:
        config["ntfy_token"] = req.token
    if not config["ntfy_topic"]:
        raise HTTPException(status_code=400, detail="Configure an ntfy topic first")
    try:
        _send_ntfy(config, "IDS test notification", "This is a test notification from your ARP IDS dashboard.", "default")
    except (urllib.error.URLError, OSError, RuntimeError) as exc:
        logger.exception("Unable to send ntfy test notification")
        raise HTTPException(status_code=502, detail=f"ntfy delivery failed: {exc}") from exc
    return {"status": "sent"}


# ---------------------------------------------------------------------------
# Alerts routes
# ---------------------------------------------------------------------------
@app.get("/api/alerts")
async def get_alerts(
    start: Optional[float] = None,
    end: Optional[float] = None,
    severity: Optional[str] = None,
    limit: int = 500,
    current_user=Depends(auth.get_current_user),
):
    return database.list_alerts(start_ts=start, end_ts=end, severity=severity, limit=limit)


@app.get("/api/alerts/{alert_id}")
async def get_alert_detail(alert_id: int, current_user=Depends(auth.get_current_user)):
    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["features"] = json.loads(alert.pop("features_json") or "{}")
    alert["shap"] = json.loads(alert.pop("shap_json") or "[]")
    return alert


class FeedbackRequest(BaseModel):
    label: str  # 'true_positive' | 'false_positive' | 'ignore'


@app.post("/api/alerts/{alert_id}/feedback")
async def submit_feedback(alert_id: int, req: FeedbackRequest, current_user=Depends(auth.get_current_user)):
    if req.label not in ("true_positive", "false_positive", "ignore"):
        raise HTTPException(status_code=400, detail="Invalid label")
    database.set_feedback(alert_id, req.label)
    return {"status": "ok"}


@app.delete("/api/alerts")
async def clear_logs(current_user=Depends(auth.get_current_user)):
    database.clear_all_logs()
    return {"status": "cleared"}


@app.get("/api/alerts/export/{fmt}")
async def export_alerts(
    fmt: str,
    start: Optional[float] = None,
    end: Optional[float] = None,
    current_user=Depends(auth.get_current_user),
):
    alerts = database.list_alerts(start_ts=start, end_ts=end, limit=100000)
    if fmt == "json":
        return StreamingResponse(
            io.BytesIO(json.dumps(alerts, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=alerts_export.json"},
        )
    elif fmt == "csv":
        buf = io.StringIO()
        if alerts:
            writer = csv.DictWriter(buf, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
        )
    raise HTTPException(status_code=400, detail="format must be 'csv' or 'json'")


# ---------------------------------------------------------------------------
# Model retraining routes
# ---------------------------------------------------------------------------
@app.post("/api/model/retrain")
async def retrain_model(current_user=Depends(auth.get_current_user)):
    if not sniffer:
        raise HTTPException(status_code=503, detail="Sniffer not initialized")
    started = sniffer.ml_engine.retrain_from_feedback_async()
    if not started:
        raise HTTPException(status_code=409, detail="Retraining already in progress")
    return {"status": "retraining_started"}


@app.get("/api/model/status")
async def model_status(current_user=Depends(auth.get_current_user)):
    if not sniffer:
        raise HTTPException(status_code=503, detail="Sniffer not initialized")
    return sniffer.ml_engine.status()


@app.delete("/api/model/training-data")
async def delete_model_training_data(current_user=Depends(auth.get_current_user)):
    if not sniffer:
        raise HTTPException(status_code=503, detail="Sniffer not initialized")
    if not sniffer.ml_engine.clear_training_data():
        raise HTTPException(status_code=409, detail="Cannot delete training data while retraining")
    return {"status": "training_data_deleted"}


@app.get("/api/network/arp-table")
async def arp_table(current_user=Depends(auth.get_current_user)):
    return database.get_mac_ip_table()


@app.get("/api/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
