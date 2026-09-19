import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, Trash2, Download, Check, X as XIcon, EyeOff } from "lucide-react";
import { api } from "../api";
import { useWebSocket } from "../hooks/useWebSocket";
import AlertModal from "./AlertModal";

const severityStyles = {
  High: "border-l-4 border-red-500 bg-red-500/5",
  Medium: "border-l-4 border-orange-500 bg-orange-500/5",
  Low: "border-l-4 border-yellow-500 bg-yellow-500/5",
};

const severityBadge = {
  High: "bg-red-500 text-white",
  Medium: "bg-orange-500 text-white",
  Low: "bg-yellow-500 text-black",
};

export default function AlertCenter() {
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(null);
  const [selectedDetail, setSelectedDetail] = useState(null);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [confirmClear, setConfirmClear] = useState(false);

  const loadAlerts = useCallback(async () => {
    const params = {};
    if (dateFrom) params.start = new Date(dateFrom).getTime() / 1000;
    if (dateTo) params.end = new Date(dateTo).getTime() / 1000;
    if (severityFilter) params.severity = severityFilter;
    const data = await api.getAlerts(params);
    setAlerts(data);
  }, [dateFrom, dateTo, severityFilter]);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);

  const onNewAlert = useCallback((alert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, 500));
  }, []);
  useWebSocket("/ws/alerts", onNewAlert);

  const openDetail = async (alert) => {
    setSelected(alert);
    const detail = await api.getAlertDetail(alert.id);
    setSelectedDetail(detail);
  };

  const handleFeedback = async (id, label) => {
    await api.submitFeedback(id, label);
    setSelected(null);
    setSelectedDetail(null);
    loadAlerts();
  };

  const handleClear = async () => {
    await api.clearLogs();
    setConfirmClear(false);
    loadAlerts();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-lg font-semibold">Alert Center & Log Management</h2>
        <div className="flex items-center gap-2 flex-wrap">
          <input type="datetime-local" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-sm" />
          <span className="text-slate-500 text-sm">to</span>
          <input type="datetime-local" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-sm" />
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-sm">
            <option value="">All Severities</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <button onClick={loadAlerts} className="p-2 bg-slate-800 hover:bg-slate-700 rounded-lg">
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between flex-wrap gap-3 bg-slate-900 border border-slate-800 rounded-2xl p-4">
        <div className="flex items-center gap-2">
          <a href={api.exportUrl("csv", severityFilter ? { severity: severityFilter } : {})}
             className="flex items-center gap-1 text-sm bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg">
            <Download size={14} /> CSV
          </a>
          <a href={api.exportUrl("json", severityFilter ? { severity: severityFilter } : {})}
             className="flex items-center gap-1 text-sm bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg">
            <Download size={14} /> JSON
          </a>
          {!confirmClear ? (
            <button onClick={() => setConfirmClear(true)} className="flex items-center gap-1 text-sm bg-slate-800 hover:bg-red-600/30 text-red-400 px-3 py-2 rounded-lg">
              <Trash2 size={14} /> Clear All Logs
            </button>
          ) : (
            <div className="flex items-center gap-1 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-2 py-1">
              <span>Confirm clear?</span>
              <button onClick={handleClear} className="text-red-400 font-medium px-2">Yes</button>
              <button onClick={() => setConfirmClear(false)} className="text-slate-400 px-2">No</button>
            </div>
          )}
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-800/50">
            <tr className="text-left text-slate-400">
              <th className="py-2 px-4">Timestamp</th>
              <th className="py-2 px-4">Alert Type</th>
              <th className="py-2 px-4">Severity</th>
              <th className="py-2 px-4">Source IP</th>
              <th className="py-2 px-4">Source MAC</th>
              <th className="py-2 px-4">Description</th>
              <th className="py-2 px-4">Feedback</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 && (
              <tr><td colSpan={7} className="py-8 text-center text-slate-500">No alerts detected. Network is secure.</td></tr>
            )}
            {alerts.map((a) => (
              <tr
                key={a.id}
                onClick={() => openDetail(a)}
                className={`cursor-pointer hover:bg-slate-800/40 ${severityStyles[a.severity] || ""}`}
              >
                <td className="py-2 px-4 whitespace-nowrap">{new Date(a.timestamp * 1000).toLocaleString()}</td>
                <td className="py-2 px-4">{a.alert_type}</td>
                <td className="py-2 px-4">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${severityBadge[a.severity]}`}>{a.severity}</span>
                </td>
                <td className="py-2 px-4 font-mono">{a.source_ip}</td>
                <td className="py-2 px-4 font-mono">{a.source_mac}</td>
                <td className="py-2 px-4 truncate max-w-xs">{a.description}</td>
                <td className="py-2 px-4" onClick={(e) => e.stopPropagation()}>
                  <div className="flex gap-1">
                    <button title="True Positive" onClick={() => handleFeedback(a.id, "true_positive")}
                      className={`p-1 rounded ${a.feedback_label === "true_positive" ? "bg-red-600 text-white" : "bg-slate-800 text-red-400 hover:bg-red-600/30"}`}>
                      <Check size={14} />
                    </button>
                    <button title="False Positive" onClick={() => handleFeedback(a.id, "false_positive")}
                      className={`p-1 rounded ${a.feedback_label === "false_positive" ? "bg-green-600 text-white" : "bg-slate-800 text-green-400 hover:bg-green-600/30"}`}>
                      <XIcon size={14} />
                    </button>
                    <button title="Ignore" onClick={() => handleFeedback(a.id, "ignore")}
                      className={`p-1 rounded ${a.feedback_label === "ignore" ? "bg-slate-600 text-white" : "bg-slate-800 text-slate-400 hover:bg-slate-700"}`}>
                      <EyeOff size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <AlertModal
        alert={selectedDetail}
        onClose={() => { setSelected(null); setSelectedDetail(null); }}
        onFeedback={handleFeedback}
      />
    </div>
  );
}
