"""
sniffer.py
Scapy packet capture loop that runs in a background thread. Requires raw
socket permissions (run the backend as root, or grant the interpreter
CAP_NET_RAW / CAP_NET_ADMIN via setcap on Linux):

    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

Each captured ARP packet is fed through features.py -> engine.RuleEngine
-> engine.MLEngine, and any resulting alert is handed to an `on_alert`
callback so main.py can broadcast it over the /ws/alerts WebSocket and
persist it to SQLite.
"""
import threading
import time
import logging

from scapy.all import sniff, ARP, Ether, conf

import database
from features import ArpStateTracker
from engine import RuleEngine, MLEngine

logger = logging.getLogger("ids.sniffer")


class Sniffer:
    def __init__(self, on_alert, on_state_update=None):
        """
        on_alert(alert_dict) -> called whenever a new alert is generated.
        on_state_update(ip, mac, status) -> called on every ARP packet so the
            live ARP/MAC table in the UI can be refreshed.
        """
        self.on_alert = on_alert
        self.on_state_update = on_state_update
        self.tracker = ArpStateTracker()

        config = database.get_config()
        self.rule_engine = RuleEngine(config)
        self.ml_engine = MLEngine()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.interface = self._resolve_interface(config.get("interface"))
        self.running = False
        self.packets_processed = 0

    @staticmethod
    def _resolve_interface(interface):
        if interface and interface in conf.ifaces:
            return interface
        if interface:
            logger.warning("Configured interface %r is unavailable; using %s", interface, conf.iface)
        return str(conf.iface)

    # ------------------------------------------------------------------
    def reload_config(self):
        config = database.get_config()
        self.rule_engine.reload_config(config)
        new_interface = self._resolve_interface(config.get("interface"))
        if new_interface != self.interface:
            self.interface = new_interface
            self.restart()
        elif not self._thread or not self._thread.is_alive():
            self.start()

    # ------------------------------------------------------------------
    def _handle_packet(self, pkt):
        try:
            size = len(pkt)
            self.tracker.record_traffic(size)

            if not pkt.haslayer(ARP):
                return

            self.packets_processed += 1
            extracted = self.tracker.extract(pkt)
            if extracted is None:
                return

            feature_dict = extracted["features"]
            meta = extracted["meta"]

            # Stage 1: rule engine (high recall baseline)
            rule_result = self.rule_engine.evaluate(feature_dict, meta)
            self.ml_engine.append_bootstrap_sample(feature_dict, rule_result is not None)
            self.ml_engine.maybe_bootstrap()

            status = "suspicious" if rule_result else "legitimate"

            alert_payload = None
            if rule_result:
                alert_payload = {
                    "timestamp": meta["timestamp"],
                    "alert_type": rule_result["alert_type"],
                    "severity": rule_result["severity"],
                    "threat_score": 1.0 if rule_result["severity"] == "High" else 0.6,
                    "source_ip": meta["source_ip"],
                    "source_mac": meta["source_mac"],
                    "gateway_ip": None,
                    "old_mac": meta.get("prev_mac"),
                    "new_mac": meta["source_mac"],
                    "description": rule_result["reason"],
                    "features": feature_dict,
                    "shap": [],
                    "detection_stage": "rule_engine",
                }
            else:
                # Stage 2: ML scoring for anything the rules didn't already flag
                score = self.ml_engine.score(feature_dict)
                if score >= 0.4:  # Medium or High per spec thresholds
                    severity = self.ml_engine.categorize(score)
                    shap_expl = self.ml_engine.explain(feature_dict)
                    status = "suspicious"
                    alert_payload = {
                        "timestamp": meta["timestamp"],
                        "alert_type": "ML_ANOMALY",
                        "severity": severity,
                        "threat_score": score,
                        "source_ip": meta["source_ip"],
                        "source_mac": meta["source_mac"],
                        "gateway_ip": None,
                        "old_mac": meta.get("prev_mac"),
                        "new_mac": meta["source_mac"],
                        "description": (
                            f"ML model flagged traffic from {meta['source_ip']} "
                            f"({meta['source_mac']}) with threat score {score:.2f}"
                        ),
                        "features": feature_dict,
                        "shap": shap_expl,
                        "detection_stage": "ml_engine",
                    }

            database.upsert_mac_ip(meta["source_ip"], meta["source_mac"], status, meta["timestamp"])
            if self.on_state_update:
                self.on_state_update(meta["source_ip"], meta["source_mac"], status)

            if alert_payload:
                self.on_alert(alert_payload)

        except Exception:
            logger.exception("Error processing packet")

    # ------------------------------------------------------------------
    def _run(self):
        self.running = True
        logger.info("Sniffer starting on interface=%s", self.interface or "default")
        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda p: self._stop_event.is_set(),
                )
        except PermissionError:
            logger.error(
                "Permission denied opening raw socket. Run as root or grant "
                "CAP_NET_RAW/CAP_NET_ADMIN to the python interpreter."
            )
        except Exception:
            logger.exception("Sniffer crashed")
        finally:
            self.running = False
            logger.info("Sniffer stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def restart(self):
        self.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self.start()

    def get_metrics(self):
        stats = self.tracker.get_traffic_stats()
        stats["running"] = self.running
        stats["packets_processed_total"] = self.packets_processed
        return stats


def list_interfaces():
    """Returns available network interface names for the config UI."""
    try:
        return list(conf.ifaces.data.keys()) if hasattr(conf, "ifaces") else []
    except Exception:
        return []
