"""
features.py
Converts raw Scapy ARP packets into numerical feature vectors used by both
the rule engine (engine.py) and the XGBoost scorer. Maintains rolling,
in-memory state of ARP requests/replies and IP<->MAC bindings so features
can be computed per-packet without re-scanning history.
"""
import time
import threading
from collections import defaultdict, deque

import pandas as pd
from scapy.all import ARP, Ether

# Feature vector column order -- used consistently by engine.py for training/inference
FEATURE_COLUMNS = [
    "opcode",
    "is_gratuitous",
    "gratuitous_burst_count_30s",
    "unsolicited_reply_ratio",
    "ip_mac_churn_rate",
    "ip_mac_binding_delta",
    "requests_last_60s",
    "replies_last_60s",
    "unique_macs_for_ip_seen",
    "seconds_since_ip_first_seen",
]


class ArpStateTracker:
    """Thread-safe rolling state of ARP traffic used for feature engineering."""

    def __init__(self, churn_window_sec=300, burst_window_sec=30):
        self.lock = threading.Lock()
        self.churn_window_sec = churn_window_sec
        self.burst_window_sec = burst_window_sec

        # ip -> current mac
        self.ip_to_mac = {}
        # ip -> deque of (timestamp, mac) for churn tracking
        self.ip_mac_history = defaultdict(lambda: deque(maxlen=200))
        # source_mac -> deque of gratuitous reply timestamps
        self.gratuitous_replies = defaultdict(lambda: deque(maxlen=500))
        # source_mac -> deque of request timestamps
        self.requests = defaultdict(lambda: deque(maxlen=500))
        # source_mac -> deque of reply timestamps
        self.replies = defaultdict(lambda: deque(maxlen=500))
        # source_mac -> deque of unsolicited reply timestamps (subset of replies)
        self.unsolicited_replies = defaultdict(lambda: deque(maxlen=500))
        # ip -> first_seen timestamp
        self.ip_first_seen = {}
        # pending request senders we've seen recently (ip -> timestamp) to judge "unsolicited"
        self.pending_requests_for_ip = {}

        # traffic counters for the metrics websocket
        self.packet_count_window = deque(maxlen=5000)  # timestamps of all packets seen
        self.byte_count_window = deque(maxlen=5000)     # (timestamp, size)

    def _prune(self, dq: deque, now: float, window: float):
        while dq and now - dq[0] > window:
            dq.popleft()

    def record_traffic(self, size_bytes: float):
        now = time.time()
        self.packet_count_window.append(now)
        self.byte_count_window.append((now, size_bytes))

    def get_traffic_stats(self):
        now = time.time()
        with self.lock:
            self._prune(self.packet_count_window, now, 1.0)
            while self.byte_count_window and now - self.byte_count_window[0][0] > 1.0:
                self.byte_count_window.popleft()
            pps = len(self.packet_count_window)
            bps = sum(sz for _, sz in self.byte_count_window)
        return {"packets_per_sec": pps, "bandwidth_bytes_per_sec": bps}

    def extract(self, pkt) -> dict:
        """Extract a feature dict + contextual metadata for a single ARP packet."""
        if not pkt.haslayer(ARP):
            return None
        arp = pkt[ARP]
        now = time.time()
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        opcode = int(arp.op)  # 1 = who-has (request), 2 = is-at (reply)

        eth_dst = pkt[Ether].dst if pkt.haslayer(Ether) else "ff:ff:ff:ff:ff:ff"
        is_broadcast = eth_dst.lower() == "ff:ff:ff:ff:ff:ff"
        # Gratuitous ARP: sender IP == target IP (announcing own binding), typically a reply
        is_gratuitous = (src_ip == dst_ip) or (opcode == 2 and is_broadcast)

        with self.lock:
            if src_ip not in self.ip_first_seen:
                self.ip_first_seen[src_ip] = now

            if opcode == 1:
                self.requests[src_mac].append(now)
                self.pending_requests_for_ip[dst_ip] = now
            else:
                self.replies[src_mac].append(now)
                if is_gratuitous:
                    self.gratuitous_replies[src_mac].append(now)
                # unsolicited: this reply claims a binding (src_ip -> src_mac) that
                # nobody recently asked "who has src_ip?" about
                had_pending = src_ip in self.pending_requests_for_ip and \
                    (now - self.pending_requests_for_ip.get(src_ip, 0)) < 5
                if not had_pending:
                    self.unsolicited_replies[src_mac].append(now)

            self._prune(self.requests[src_mac], now, 60)
            self._prune(self.replies[src_mac], now, 60)
            self._prune(self.unsolicited_replies[src_mac], now, 60)
            self._prune(self.gratuitous_replies[src_mac], now, self.burst_window_sec)

            requests_last_60s = len(self.requests[src_mac])
            replies_last_60s = len(self.replies[src_mac])
            gratuitous_burst_count_30s = len(self.gratuitous_replies[src_mac])

            total_replies = max(replies_last_60s, 1)
            unsolicited_reply_ratio = min(1.0, len(self.unsolicited_replies[src_mac]) / total_replies)

            # IP <-> MAC binding delta / churn
            prev_mac = self.ip_to_mac.get(src_ip)
            ip_mac_binding_delta = 1 if (prev_mac is not None and prev_mac != src_mac) else 0
            self.ip_mac_history[src_ip].append((now, src_mac))
            self._prune_pairs(self.ip_mac_history[src_ip], now, self.churn_window_sec)
            unique_macs = len(set(m for _, m in self.ip_mac_history[src_ip]))
            span = max(now - self.ip_mac_history[src_ip][0][0], 1.0)
            ip_mac_churn_rate = unique_macs / span * 60  # unique macs per minute

            self.ip_to_mac[src_ip] = src_mac
            seconds_since_ip_first_seen = now - self.ip_first_seen[src_ip]

        features = {
            "opcode": opcode,
            "is_gratuitous": int(is_gratuitous),
            "gratuitous_burst_count_30s": gratuitous_burst_count_30s,
            "unsolicited_reply_ratio": round(unsolicited_reply_ratio, 4),
            "ip_mac_churn_rate": round(ip_mac_churn_rate, 4),
            "ip_mac_binding_delta": ip_mac_binding_delta,
            "requests_last_60s": requests_last_60s,
            "replies_last_60s": replies_last_60s,
            "unique_macs_for_ip_seen": unique_macs,
            "seconds_since_ip_first_seen": round(seconds_since_ip_first_seen, 2),
        }

        meta = {
            "timestamp": now,
            "source_ip": src_ip,
            "source_mac": src_mac,
            "dest_ip": dst_ip,
            "opcode": opcode,
            "is_gratuitous": is_gratuitous,
            "prev_mac": prev_mac,
        }
        return {"features": features, "meta": meta}

    @staticmethod
    def _prune_pairs(dq: deque, now: float, window: float):
        while dq and now - dq[0][0] > window:
            dq.popleft()


def features_to_dataframe(feature_dicts: list) -> pd.DataFrame:
    """Convert a list of feature dicts into an ordered DataFrame for the model."""
    df = pd.DataFrame(feature_dicts)
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[FEATURE_COLUMNS]
