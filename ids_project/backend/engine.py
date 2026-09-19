"""
engine.py
Hybrid detection engine:
  Stage 1 - RuleEngine: high-recall, deterministic thresholds over the
            features produced by features.py (gratuitous ARP bursts,
            unsolicited replies, IP/MAC churn).
  Stage 2 - MLEngine: XGBoost classifier that scores every flow 0.0-1.0.
            Supports a cold-start bootstrap (auto-labels using rule engine
            output when no human feedback exists yet) and asynchronous
            retraining from accumulated human feedback (active learning).
"""
import json
import time
import threading
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split

import database
from features import FEATURE_COLUMNS, features_to_dataframe

MODEL_PATH = Path(__file__).parent / "model.json"
BOOTSTRAP_BUFFER_PATH = Path(__file__).parent / "bootstrap_buffer.jsonl"


class RuleEngine:
    """Stage 1: deterministic, high-recall rule checks."""

    def __init__(self, config: dict):
        self.reload_config(config)

    def reload_config(self, config: dict):
        self.gratuitous_burst_threshold = int(config.get("gratuitous_burst_count", 3))
        self.whitelist = set(json.loads(config.get("whitelist_gateway_macs", "[]")))

    def evaluate(self, features: dict, meta: dict):
        """Returns (matched: bool, alert_type: str, severity: str, reason: str) or None."""
        if meta["source_mac"] in self.whitelist:
            return None

        # High severity: gratuitous / unsolicited ARP reply flood -> classic MITM/poisoning
        if features["gratuitous_burst_count_30s"] > self.gratuitous_burst_threshold:
            return {
                "matched": True,
                "alert_type": "UNSOLICITED_ARP",
                "severity": "High",
                "reason": (
                    f"Excessive unsolicited ARP replies from {meta['source_ip']} "
                    f"({meta['source_mac']}). Count: {features['gratuitous_burst_count_30s']}"
                ),
            }

        # Medium severity: IP now bound to a different MAC than previously observed (churn)
        if features["ip_mac_binding_delta"] == 1:
            return {
                "matched": True,
                "alert_type": "MAC_CHURN",
                "severity": "Medium",
                "reason": (
                    f"Rapid MAC address change detected for IP {meta['source_ip']}. "
                    f"Old MAC: {meta.get('prev_mac')}, New MAC: {meta['source_mac']}"
                ),
            }

        # Low severity: ARP scanning reconnaissance pattern (many requests, low reply ratio)
        if features["requests_last_60s"] > 20 and features["opcode"] == 1:
            return {
                "matched": True,
                "alert_type": "ARP_SCAN",
                "severity": "Low",
                "reason": (
                    f"Possible ARP scanning from {meta['source_mac']}: "
                    f"{features['requests_last_60s']} requests in the last 60s"
                ),
            }

        return None


class MLEngine:
    """Stage 2: XGBoost threat scorer with bootstrap + active-learning retrain."""

    def __init__(self, config=None):
        self.lock = threading.Lock()
        self.model: xgb.XGBClassifier | None = None
        self.is_retraining = False
        self.last_trained_at = None
        self.training_samples = 0
        self.threshold_low = 0.4
        self.threshold_high = 0.7
        self.reload_config(config or {})
        self._load_model()

    def reload_config(self, config: dict):
        self.threshold_low = float(config.get("threshold_low", 0.4))
        self.threshold_high = float(config.get("threshold_high", 0.7))

    # ---------- persistence ----------
    def _load_model(self):
        if MODEL_PATH.exists():
            try:
                model = xgb.XGBClassifier()
                model.load_model(str(MODEL_PATH))
                self.model = model
            except Exception:
                self.model = None

    def _save_model(self):
        if self.model is not None:
            self.model.save_model(str(MODEL_PATH))

    def clear_training_data(self):
        with self.lock:
            if self.is_retraining:
                return False
            self.model = None
            self.last_trained_at = None
            self.training_samples = 0
            MODEL_PATH.unlink(missing_ok=True)
            BOOTSTRAP_BUFFER_PATH.unlink(missing_ok=True)
        database.clear_training_data()
        return True

    # ---------- bootstrap ----------
    def append_bootstrap_sample(self, feature_dict: dict, rule_matched: bool):
        """Cold-start: log rule-engine verdicts as weak labels until we have
        enough data (or human feedback) to train a real model."""
        record = {**feature_dict, "label": int(rule_matched)}
        with open(BOOTSTRAP_BUFFER_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")

    def _load_bootstrap_samples(self):
        if not BOOTSTRAP_BUFFER_PATH.exists():
            return pd.DataFrame(columns=FEATURE_COLUMNS + ["label"])
        rows = []
        with open(BOOTSTRAP_BUFFER_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return pd.DataFrame(rows)

    def maybe_bootstrap(self, min_samples=200):
        """Train an initial model purely from rule-engine auto-labels once
        enough packets have been observed, so scoring works before any
        human feedback exists."""
        if self.model is not None:
            return
        df = self._load_bootstrap_samples()
        if len(df) < min_samples:
            return
        if df["label"].nunique() < 2:
            return  # need both classes to train
        self._train_from_dataframe(df)

    # ---------- scoring ----------
    def score(self, feature_dict: dict) -> float:
        if self.model is None:
            return 0.0
        df = features_to_dataframe([feature_dict])
        proba = self.model.predict_proba(df)[0][1]
        return float(proba)

    def explain(self, feature_dict: dict, top_n=5):
        """Return top contributing features (SHAP-style) for a scored alert."""
        if self.model is None:
            return []
        try:
            import shap
            df = features_to_dataframe([feature_dict])
            explainer = shap.TreeExplainer(self.model)
            shap_values = explainer.shap_values(df)
            values = shap_values[0] if isinstance(shap_values, list) else shap_values[0]
            contributions = sorted(
                zip(FEATURE_COLUMNS, values), key=lambda x: abs(x[1]), reverse=True
            )[:top_n]
            return [{"feature": f, "impact": round(float(v), 4)} for f, v in contributions]
        except Exception:
            # Fall back to XGBoost's built-in feature importance if SHAP fails
            try:
                importances = self.model.feature_importances_
                contributions = sorted(
                    zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True
                )[:top_n]
                return [{"feature": f, "impact": round(float(v), 4)} for f, v in contributions]
            except Exception:
                return []

    def categorize(self, score: float) -> str:
        if score < self.threshold_low:
            return "Low"
        elif score < self.threshold_high:
            return "Medium"
        return "High"

    # ---------- training / retraining ----------
    def _train_from_dataframe(self, df: pd.DataFrame):
        X = df[FEATURE_COLUMNS]
        y = df["label"]
        if y.nunique() < 2:
            return False
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            eval_metric="logloss",
            use_label_encoder=False,
        )
        model.fit(X_train, y_train)
        with self.lock:
            self.model = model
            self.last_trained_at = time.time()
            self.training_samples = len(df)
        self._save_model()
        return True

    def retrain_from_feedback_async(self, on_complete=None):
        """Trigger a background retrain using accumulated human feedback
        (True Positive / False Positive labels) without blocking the server
        or requiring a restart."""
        if self.is_retraining:
            return False

        def _worker():
            self.is_retraining = True
            try:
                feedback = database.get_feedback_dataset()
                bootstrap_df = self._load_bootstrap_samples()

                rows = [{**f, "label": l} for f, l in feedback]
                feedback_df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=FEATURE_COLUMNS + ["label"])

                combined = pd.concat([bootstrap_df, feedback_df], ignore_index=True) \
                    if not bootstrap_df.empty else feedback_df

                if combined.empty or combined["label"].nunique() < 2:
                    return
                self._train_from_dataframe(combined)
            finally:
                self.is_retraining = False
                if on_complete:
                    on_complete()

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def status(self):
        bootstrap = self._load_bootstrap_samples()
        feedback = database.get_feedback_dataset()
        return {
            "model_loaded": self.model is not None,
            "is_retraining": self.is_retraining,
            "last_trained_at": self.last_trained_at,
            "training_samples": self.training_samples,
            "bootstrap_samples": len(bootstrap),
            "bootstrap_positive_samples": int((bootstrap["label"] == 1).sum()) if not bootstrap.empty else 0,
            "bootstrap_negative_samples": int((bootstrap["label"] == 0).sum()) if not bootstrap.empty else 0,
            "feedback_samples": len(feedback),
            "model_file_exists": MODEL_PATH.exists(),
            "model_file_size_bytes": MODEL_PATH.stat().st_size if MODEL_PATH.exists() else 0,
            "feature_count": len(FEATURE_COLUMNS),
            "threshold_low": self.threshold_low,
            "threshold_high": self.threshold_high,
        }
