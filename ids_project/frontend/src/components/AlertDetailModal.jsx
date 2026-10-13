import React from "react";
import { X } from "lucide-react";

const severityColor = {
  High: "text-red-400 bg-red-500/10 border-red-500/30",
  Medium: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  Low: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  UNKNOWN: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const featureOrder = [
  "opcode", "is_gratuitous", "gratuitous_burst_count_30s", "unsolicited_reply_ratio",
  "ip_mac_churn_rate", "ip_mac_binding_delta", "requests_last_60s", "replies_last_60s",
  "unique_macs_for_ip_seen", "seconds_since_ip_first_seen", "request_rate", "distinct_mac_count",
  "distinct_target_ips", "packet_freq",
];

export default function AlertDetailModal({ item, unknown = false, onClose, onFeedback }) {
  if (!item) return null;
  const severity = unknown ? "UNKNOWN" : item.severity;
  const sourceIp = unknown ? item.src_ip : item.source_ip;
  const sourceMac = unknown ? item.src_mac : item.source_mac;
  const features = unknown ? item.features : item.features;
  const title = unknown ? "UNKNOWN" : item.alert_type;
  const handleFeedback = (decision) => onFeedback(item, decision);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <span className={`inline-flex rounded-full border px-2 py-1 text-xs ${severityColor[severity] || ""}`}>{severity} Severity</span>
            <h2 className="mt-3 text-xl font-semibold">{title}</h2>
            <p className="text-sm text-slate-400">{new Date(item.timestamp * 1000).toLocaleString()}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close details" title="Close details" className="rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white"><X size={20} /></button>
        </div>
        <p className="mt-4 text-sm text-slate-300">{unknown ? `Unmatched ARP traffic from ${sourceIp} to ${item.dst_ip}.` : item.description}</p>

        <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-4">
          {[["Source IP", sourceIp], ["Source MAC", sourceMac], ["Threat Score", unknown ? "N/A" : Number(item.threat_score).toFixed(3)], ["Detection Stage", unknown ? "rule_engine" : item.detection_stage]].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-slate-800 bg-slate-800/50 p-3">
              <p className="text-xs text-slate-500">{label}</p>
              <p className="mt-1 truncate font-mono text-sm">{value || "-"}</p>
            </div>
          ))}
        </div>

        <div className="mt-6">
          <h3 className="mb-2 text-sm font-medium text-slate-300">Raw ARP / Feature Parameters</h3>
          <div className="grid grid-cols-1 gap-x-6 gap-y-1 rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs font-mono md:grid-cols-2">
            {featureOrder.map((key) => <div key={key} className="flex justify-between gap-4 border-b border-slate-800/60 py-2"><span className="text-slate-500">{key}</span><span>{features?.[key] ?? "-"}</span></div>)}
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-2 border-t border-slate-800 pt-4 md:grid-cols-3">
          <button onClick={() => handleFeedback(unknown ? "TP" : "true_positive")} className="rounded-lg bg-red-600 px-4 py-3 text-sm font-medium text-white hover:bg-red-500">Mark True Positive</button>
          <button onClick={() => handleFeedback(unknown ? "FP" : "false_positive")} className="rounded-lg bg-green-600 px-4 py-3 text-sm font-medium text-white hover:bg-green-500">Mark False Positive</button>
          <button onClick={() => handleFeedback(unknown ? "IGNORE" : "ignore")} className="rounded-lg bg-slate-700 px-4 py-3 text-sm font-medium text-white hover:bg-slate-600">Ignore</button>
        </div>
      </div>
    </div>
  );
}
