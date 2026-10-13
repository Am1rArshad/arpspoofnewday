import React from "react";
import { Check, EyeOff, X as XIcon } from "lucide-react";

const severityStyles = {
  High: "border-l-4 border-red-500 bg-red-500/5",
  Medium: "border-l-4 border-orange-500 bg-orange-500/5",
  Low: "border-l-4 border-yellow-500 bg-yellow-500/5",
  UNKNOWN: "border-l-4 border-blue-500 bg-blue-500/5",
};

const severityBadges = {
  High: "bg-red-500 text-white",
  Medium: "bg-orange-500 text-white",
  Low: "bg-yellow-500 text-black",
  UNKNOWN: "bg-blue-500 text-white",
};

const formatTimestamp = (timestamp) => new Date(timestamp * 1000).toLocaleString([], {
  day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
});

export default function AlertTable({ rows, emptyMessage, onRowClick, onFeedback, unknown = false }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/50">
          <tr className="text-left text-slate-400">
            <th className="py-3 px-4">Timestamp</th>
            <th className="py-3 px-4">Alert Type</th>
            <th className="py-3 px-4">Severity</th>
            <th className="py-3 px-4">Source IP</th>
            <th className="py-3 px-4">Source MAC</th>
            <th className="py-3 px-4">Description</th>
            <th className="py-3 px-4">Feedback / Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && <tr><td colSpan={7} className="py-10 text-center text-slate-500">{emptyMessage}</td></tr>}
          {rows.map((row) => {
            const severity = unknown ? "UNKNOWN" : row.severity;
            return (
              <tr key={`${unknown ? "unknown" : "alert"}-${row.id}`} onClick={() => onRowClick(row)} className={`cursor-pointer border-t border-slate-800 hover:bg-slate-800/40 ${severityStyles[severity] || ""}`}>
                <td className="py-3 px-4 whitespace-nowrap">{formatTimestamp(row.timestamp)}</td>
                <td className="py-3 px-4 font-medium">{unknown ? "UNKNOWN" : row.alert_type}</td>
                <td className="py-3 px-4"><span className={`text-xs px-2 py-1 rounded-full ${severityBadges[severity] || "bg-slate-600 text-white"}`}>{severity}</span></td>
                <td className="py-3 px-4 font-mono">{unknown ? row.src_ip : row.source_ip}</td>
                <td className="py-3 px-4 font-mono">{unknown ? row.src_mac : row.source_mac}</td>
                <td className="py-3 px-4 max-w-sm truncate">{unknown ? `Unmatched ARP traffic to ${row.dst_ip}` : row.description}</td>
                <td className="py-3 px-4" onClick={(event) => event.stopPropagation()}>
                  <div className="flex gap-1">
                    <button title="True Positive" onClick={() => onFeedback(row, unknown ? "TP" : "true_positive", unknown)} className="p-1.5 rounded bg-slate-800 text-red-400 hover:bg-red-600/30"><Check size={15} /></button>
                    <button title="False Positive" onClick={() => onFeedback(row, unknown ? "FP" : "false_positive", unknown)} className="p-1.5 rounded bg-slate-800 text-green-400 hover:bg-green-600/30"><XIcon size={15} /></button>
                    <button title="Ignore" onClick={() => onFeedback(row, unknown ? "IGNORE" : "ignore", unknown)} className="p-1.5 rounded bg-slate-800 text-slate-400 hover:bg-slate-700"><EyeOff size={15} /></button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
