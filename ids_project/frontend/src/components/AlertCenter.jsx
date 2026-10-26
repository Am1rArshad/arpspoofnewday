import React, { useCallback, useEffect, useState } from "react";
import { Download, RefreshCw, Trash2 } from "lucide-react";
import { api } from "../api";
import { useWebSocket } from "../hooks/useWebSocket";
import AlertTable from "./AlertTable";
import AlertDetailModal from "./AlertDetailModal";

const tabs = [
  ["flagged", "Flagged Alerts"],
  ["review", "Analyst Review Queue", "UNKNOWN"],
  ["archived", "Archived Logs"],
];

export default function AlertCenter() {
  const [activeTab, setActiveTab] = useState("flagged");
  const [alerts, setAlerts] = useState([]);
  const [unknownPackets, setUnknownPackets] = useState([]);
  const [archived, setArchived] = useState([]);
  const [selected, setSelected] = useState(null);
  const [selectedUnknown, setSelectedUnknown] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState(null);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [confirmClear, setConfirmClear] = useState(false);
  const [rangeError, setRangeError] = useState("");

  const validateRange = (from, to) => {
    if (!from || !to) { setRangeError(""); return true; }
    const duration = new Date(to).getTime() - new Date(from).getTime();
    if (duration < 0 || duration > 90 * 24 * 60 * 60 * 1000) {
      setRangeError("Selected duration exceeds 3 months. Longer duration may cause short of storage.");
      return false;
    }
    setRangeError("");
    return true;
  };

  const loadAlerts = useCallback(async () => {
    if (!validateRange(dateFrom, dateTo)) return;
    const params = {};
    if (dateFrom) params.start = new Date(dateFrom).getTime() / 1000;
    if (dateTo) params.end = new Date(dateTo).getTime() / 1000;
    if (severityFilter) params.severity = severityFilter;
    setAlerts(await api.getAlerts(params));
  }, [dateFrom, dateTo, severityFilter]);

  const loadUnknownPackets = useCallback(async () => setUnknownPackets(await api.unknownPackets()), []);
  useEffect(() => { loadAlerts(); loadUnknownPackets(); }, [loadAlerts, loadUnknownPackets]);

  const onNewAlert = useCallback((event) => {
    if (event.type === "unknown") setUnknownPackets((prev) => [event, ...prev.filter((row) => row.id !== event.id)].slice(0, 500));
    else setAlerts((prev) => [event, ...prev].slice(0, 500));
  }, []);
  useWebSocket("/ws/alerts", onNewAlert);

  const openAlert = async (row, unknown = false) => {
    setSelected(row);
    setSelectedUnknown(unknown);
    setSelectedDetail(unknown ? row : await api.getAlertDetail(row.id));
  };

  const handleFeedback = async (row, decision, isUnknown = selectedUnknown) => {
    if (isUnknown) {
      await api.submitUnknownFeedback(row.id, decision);
      setUnknownPackets((prev) => prev.filter((packet) => packet.id !== row.id));
    } else {
      await api.submitFeedback(row.id, decision);
      setAlerts((prev) => prev.map((alert) => alert.id === row.id ? { ...alert, feedback_label: decision } : alert));
    }
    setSelected(null);
    setSelectedDetail(null);
  };

  const handleClearAll = async () => {
    await api.clearLogs(activeTab === "flagged" ? "flagged" : activeTab === "review" ? "unknown" : "archived");
    if (activeTab === "flagged") {
      setArchived((prev) => [...prev, ...alerts]);
      setAlerts([]);
    } else if (activeTab === "review") {
      setUnknownPackets([]);
    } else {
      setArchived([]);
    }
    setConfirmClear(false);
  };

  const exportRows = (rows) => {
    const payload = rows.map((row) => activeTab === "review" ? {
      timestamp: row.timestamp, alert_type: "UNKNOWN", severity: "UNKNOWN", source_ip: row.src_ip,
      source_mac: row.src_mac, description: `Unmatched ARP traffic to ${row.dst_ip}`, features: row.features,
    } : row);
    return payload;
  };

  const handleExport = (format) => {
    if (activeTab === "flagged") {
      const params = { ...(dateFrom ? { start: new Date(dateFrom).getTime() / 1000 } : {}), ...(dateTo ? { end: new Date(dateTo).getTime() / 1000 } : {}), ...(severityFilter ? { severity: severityFilter } : {}), type: "flagged" };
      window.open(api.exportUrl(format, params), "_blank");
      return;
    }
    const rows = exportRows(currentRows);
    const content = format === "json" ? JSON.stringify(rows, null, 2) : [
      Object.keys(rows[0] || {}).join(","),
      ...rows.map((row) => Object.values(row).map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")),
    ].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([content], { type: format === "json" ? "application/json" : "text/csv" }));
    link.download = `${activeTab === "review" ? "unknown-review-queue" : "archived-logs"}.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const currentRows = activeTab === "flagged" ? alerts : activeTab === "review" ? unknownPackets : archived;
  const clearConfirmation = activeTab === "flagged"
    ? "Are you sure you want to clear all Flagged Alerts?"
    : activeTab === "review"
      ? "Are you sure you want to clear all pending UNKNOWN review items?"
      : "Are you sure you want to clear all Archived Logs?";

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold">Alert Center &amp; Log Management</h2>
        <div className="mt-5 flex gap-6 overflow-x-auto border-b border-slate-800">
          {tabs.map(([id, label, badge]) => <button key={id} onClick={() => { setActiveTab(id); setConfirmClear(false); }} className={`theme-tab relative whitespace-nowrap px-1 pb-3 text-sm ${activeTab === id ? "theme-tab-active" : "theme-tab-inactive"}`}>
            {label}{badge && <span className="ml-2 rounded-full bg-blue-500/15 px-2 py-0.5 text-xs text-blue-300">{unknownPackets.length}</span>}
            {activeTab === id && <span className="absolute inset-x-0 -bottom-px h-0.5 bg-cyan-400" />}
          </button>)}
        </div>
      </header>

      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <input type="datetime-local" value={dateFrom} onChange={(event) => { setDateFrom(event.target.value); validateRange(event.target.value, dateTo); }} className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-2 text-sm" aria-label="Start date" />
          <span className="text-slate-500">to</span>
          <input type="datetime-local" value={dateTo} onChange={(event) => { setDateTo(event.target.value); validateRange(dateFrom, event.target.value); }} className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-2 text-sm" aria-label="End date" />
          <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-2 text-sm"><option value="">All Severities</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select>
          <button onClick={loadAlerts} title="Refresh logs" className="rounded-lg bg-slate-800 p-2 hover:bg-slate-700"><RefreshCw size={16} /></button>
          <div className="ml-auto flex gap-2"><button onClick={() => handleExport("csv")} disabled={Boolean(rangeError)} className="flex items-center gap-1 rounded-lg bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-50"><Download size={14} /> CSV</button><button onClick={() => handleExport("json")} disabled={Boolean(rangeError)} className="flex items-center gap-1 rounded-lg bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700 disabled:opacity-50"><Download size={14} /> JSON</button>
            {!confirmClear ? <button onClick={() => setConfirmClear(true)} className="flex items-center gap-1 rounded-lg bg-slate-800 px-3 py-2 text-sm text-red-400 hover:bg-red-600/30"><Trash2 size={14} /> Clear All Logs</button> : <div className="flex items-center gap-2 rounded-lg border border-red-500/30 px-2 text-sm"><span>{clearConfirmation}</span><button onClick={handleClearAll} className="text-red-400">Yes</button><button onClick={() => setConfirmClear(false)} className="text-slate-400">No</button></div>}
          </div>
        </div>
        {rangeError && <p className="mt-2 text-sm text-red-400" role="alert">{rangeError}</p>}
      </section>

      <section className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">
        <AlertTable rows={currentRows} unknown={activeTab === "review"} onRowClick={(row) => openAlert(row, activeTab === "review")} onFeedback={handleFeedback} emptyMessage={activeTab === "review" ? "No packets awaiting analyst review." : activeTab === "archived" ? "No archived logs." : "No alerts detected."} />
      </section>

      <AlertDetailModal item={selectedDetail} unknown={selectedUnknown} onClose={() => { setSelected(null); setSelectedDetail(null); }} onFeedback={handleFeedback} />
    </div>
  );
}
