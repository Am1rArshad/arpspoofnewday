import React from "react";
import { X } from "lucide-react";

const severityColor = {
  High: "text-red-400 bg-red-500/10 border-red-500/30",
  Medium: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  Low: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
};

export default function AlertModal({ alert, onClose, onFeedback }) {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-start mb-4">
          <div>
            <span className={`text-xs px-2 py-1 rounded-full border ${severityColor[alert.severity] || ""}`}>
              {alert.severity} Severity
            </span>
            <h2 className="text-lg font-semibold mt-2">{alert.alert_type}</h2>
            <p className="text-slate-400 text-sm">{new Date(alert.timestamp * 1000).toLocaleString()}</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X size={20} />
          </button>
        </div>

        <p className="text-sm text-slate-300 mb-4">{alert.description}</p>

        <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
          <div className="bg-slate-800/50 rounded-lg p-3">
            <p className="text-slate-500 text-xs">Source IP</p>
            <p className="font-mono">{alert.source_ip}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-3">
            <p className="text-slate-500 text-xs">Source MAC</p>
            <p className="font-mono">{alert.source_mac}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-3">
            <p className="text-slate-500 text-xs">Threat Score</p>
            <p className="font-mono">{Number(alert.threat_score).toFixed(3)}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg p-3">
            <p className="text-slate-500 text-xs">Detection Stage</p>
            <p className="font-mono">{alert.detection_stage}</p>
          </div>
        </div>

        {alert.features && (
          <div className="mb-4">
            <h3 className="text-sm font-medium text-slate-300 mb-2">Raw ARP / Feature Parameters</h3>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-950 rounded-lg p-3">
              {Object.entries(alert.features).map(([k, v]) => (
                <div key={k} className="flex justify-between border-b border-slate-800/60 py-1">
                  <span className="text-slate-500">{k}</span>
                  <span>{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {alert.shap && alert.shap.length > 0 && (
          <div className="mb-4">
            <h3 className="text-sm font-medium text-slate-300 mb-2">Top Contributing Features (SHAP)</h3>
            <div className="space-y-1">
              {alert.shap.map((s) => (
                <div key={s.feature} className="flex items-center gap-2 text-xs">
                  <span className="w-40 truncate text-slate-400">{s.feature}</span>
                  <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${s.impact >= 0 ? "bg-red-500" : "bg-blue-500"}`}
                      style={{ width: `${Math.min(100, Math.abs(s.impact) * 100)}%` }}
                    />
                  </div>
                  <span className="w-14 text-right font-mono">{s.impact.toFixed(3)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="flex gap-2 pt-2 border-t border-slate-800">
          <button
            onClick={() => onFeedback(alert.id, "true_positive")}
            className="flex-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg py-2 text-sm"
          >
            Mark True Positive
          </button>
          <button
            onClick={() => onFeedback(alert.id, "false_positive")}
            className="flex-1 bg-green-600/20 hover:bg-green-600/30 text-green-400 rounded-lg py-2 text-sm"
          >
            Mark False Positive
          </button>
          <button
            onClick={() => onFeedback(alert.id, "ignore")}
            className="flex-1 bg-slate-700/40 hover:bg-slate-700/60 text-slate-300 rounded-lg py-2 text-sm"
          >
            Ignore
          </button>
        </div>
      </div>
    </div>
  );
}
