import React, { useState, useCallback } from "react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Cpu, MemoryStick, Activity, Wifi, ShieldCheck, ShieldAlert } from "lucide-react";
import { useWebSocket } from "../hooks/useWebSocket";

const MAX_POINTS = 60;

function Gauge({ label, value, icon: Icon, color }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex items-center gap-4">
      <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${color}`}>
        <Icon size={22} />
      </div>
      <div className="flex-1">
        <p className="text-xs text-slate-400">{label}</p>
        <p className="text-2xl font-semibold">{value}</p>
      </div>
      <div className="w-16 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-current transition-all"
          style={{ width: `${Math.min(100, parseFloat(value) || 0)}%` }}
        />
      </div>
    </div>
  );
}

function fmtBytes(bytes) {
  if (bytes < 1024) return `${bytes} B/s`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB/s`;
}

export default function NetworkOverview() {
  const [history, setHistory] = useState([]);
  const [latest, setLatest] = useState(null);
  const [arpTable, setArpTable] = useState([]);

  const onMessage = useCallback((data) => {
    setLatest(data);
    setArpTable(data.arp_mac_table || []);
    setHistory((prev) => {
      const point = {
        time: new Date(data.timestamp * 1000).toLocaleTimeString(),
        pps: data.packets_per_sec,
        bandwidth: Math.round(data.bandwidth_bytes_per_sec / 1024), // KB/s
      };
      const next = [...prev, point];
      return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next;
    });
  }, []);

  const { connected } = useWebSocket("/ws/metrics", onMessage);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Network Overview & System Performance</h2>
        <span className={`text-xs px-2 py-1 rounded-full ${connected ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}`}>
          {connected ? "Live" : "Disconnected"}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Gauge label="CPU Usage" value={`${(latest?.cpu_percent ?? 0).toFixed(0)}%`} icon={Cpu} color="bg-blue-500/10 text-blue-400" />
        <Gauge label="RAM Usage" value={`${(latest?.ram_percent ?? 0).toFixed(0)}%`} icon={MemoryStick} color="bg-purple-500/10 text-purple-400" />
        <Gauge label="Packets/sec" value={latest?.packets_per_sec ?? 0} icon={Activity} color="bg-amber-500/10 text-amber-400" />
        <Gauge label="Bandwidth" value={fmtBytes(latest?.bandwidth_bytes_per_sec ?? 0)} icon={Wifi} color="bg-cyan-500/10 text-cyan-400" />
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-2">Traffic (packets/sec & bandwidth KB/s)</h3>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={history}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="time" tick={{ fontSize: 10, fill: "#64748b" }} interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 10, fill: "#64748b" }} />
            <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
            <Line type="monotone" dataKey="pps" name="Packets/sec" stroke="#f59e0b" dot={false} strokeWidth={2} />
            <Line type="monotone" dataKey="bandwidth" name="Bandwidth (KB/s)" stroke="#22d3ee" dot={false} strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-3">Live ARP / MAC State Table</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-500 border-b border-slate-800">
                <th className="py-2 pr-4">IP Address</th>
                <th className="py-2 pr-4">MAC Address</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">MAC Changes</th>
                <th className="py-2 pr-4">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {arpTable.length === 0 && (
                <tr><td colSpan={5} className="py-6 text-center text-slate-500">No ARP activity captured yet</td></tr>
              )}
              {arpTable.map((row) => (
                <tr key={row.ip} className="border-b border-slate-800/60">
                  <td className="py-2 pr-4 font-mono">{row.ip}</td>
                  <td className="py-2 pr-4 font-mono">{row.mac}</td>
                  <td className="py-2 pr-4">
                    {row.status === "legitimate" ? (
                      <span className="inline-flex items-center gap-1 text-green-400"><ShieldCheck size={14} /> Legitimate</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-red-400"><ShieldAlert size={14} /> Suspicious</span>
                    )}
                  </td>
                  <td className="py-2 pr-4">{row.mac_change_count}</td>
                  <td className="py-2 pr-4 text-slate-400">{new Date(row.last_seen * 1000).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
