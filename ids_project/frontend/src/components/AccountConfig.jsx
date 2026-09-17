import React, { useEffect, useState } from "react";
import { LogOut, Save, Plus, Trash } from "lucide-react";
import { api } from "../api";

export default function AccountConfig({ user, onLogout }) {
  const [email, setEmail] = useState(user?.email || "");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [accountMsg, setAccountMsg] = useState("");

  const [config, setConfig] = useState(null);
  const [newMac, setNewMac] = useState("");
  const [configMsg, setConfigMsg] = useState("");

  useEffect(() => {
    api.getConfig().then(setConfig).catch(() => {});
  }, []);

  const saveAccount = async (e) => {
    e.preventDefault();
    setAccountMsg("");
    try {
      await api.updateAccount({
        email: email !== user?.email ? email : undefined,
        current_password: currentPassword || undefined,
        new_password: newPassword || undefined,
      });
      setAccountMsg("Account updated successfully.");
      setCurrentPassword("");
      setNewPassword("");
    } catch (err) {
      setAccountMsg(err.message || "Update failed");
    }
  };

  const saveConfig = async () => {
    setConfigMsg("");
    try {
      await api.updateConfig({
        interface: config.interface,
        threshold_low: parseFloat(config.threshold_low),
        threshold_high: parseFloat(config.threshold_high),
        gratuitous_burst_count: parseInt(config.gratuitous_burst_count, 10),
        whitelist_gateway_macs: config.whitelist_gateway_macs,
      });
      setConfigMsg("Configuration saved. Sniffer reloaded.");
    } catch (err) {
      setConfigMsg(err.message || "Save failed");
    }
  };

  const addMac = () => {
    if (!newMac.trim()) return;
    setConfig((c) => ({ ...c, whitelist_gateway_macs: [...c.whitelist_gateway_macs, newMac.trim()] }));
    setNewMac("");
  };

  const removeMac = (mac) => {
    setConfig((c) => ({ ...c, whitelist_gateway_macs: c.whitelist_gateway_macs.filter((m) => m !== mac) }));
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Account & Configuration</h2>
        <button onClick={onLogout} className="flex items-center gap-2 text-sm bg-slate-800 hover:bg-red-600/30 hover:text-red-400 px-3 py-2 rounded-lg">
          <LogOut size={14} /> Logout
        </button>
      </div>

      <form onSubmit={saveAccount} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
        <h3 className="text-sm font-medium text-slate-300">Account Settings</h3>
        <div>
          <label className="text-xs text-slate-500">Username</label>
          <input disabled value={user?.username || ""} className="w-full mt-1 bg-slate-800/50 border border-slate-700 rounded-lg px-3 py-2 text-slate-400" />
        </div>
        <div>
          <label className="text-xs text-slate-500">Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)}
            className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-slate-500">Current Password</label>
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
          </div>
          <div>
            <label className="text-xs text-slate-500">New Password</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)}
              className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
          </div>
        </div>
        {accountMsg && <p className="text-xs text-slate-400">{accountMsg}</p>}
        <button className="flex items-center gap-2 bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-medium">
          <Save size={14} /> Save Account
        </button>
      </form>

      {config && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
          <h3 className="text-sm font-medium text-slate-300">IDS Configuration</h3>

          <div>
            <label className="text-xs text-slate-500">Capture Interface (NIC / SPAN port)</label>
            <select
              value={config.interface || ""}
              onChange={(e) => setConfig({ ...config, interface: e.target.value })}
              className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2"
            >
              {(config.available_interfaces || []).length === 0 && <option value="">(none detected)</option>}
              {(config.available_interfaces || []).map((iface) => (
                <option key={iface} value={iface}>{iface}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-500">Low/Medium Threshold</label>
              <input type="number" step="0.05" value={config.threshold_low}
                onChange={(e) => setConfig({ ...config, threshold_low: e.target.value })}
                className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
            </div>
            <div>
              <label className="text-xs text-slate-500">Medium/High Threshold</label>
              <input type="number" step="0.05" value={config.threshold_high}
                onChange={(e) => setConfig({ ...config, threshold_high: e.target.value })}
                className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
            </div>
            <div>
              <label className="text-xs text-slate-500">Gratuitous ARP Burst Count</label>
              <input type="number" value={config.gratuitous_burst_count}
                onChange={(e) => setConfig({ ...config, gratuitous_burst_count: e.target.value })}
                className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
            </div>
          </div>

          <div>
            <label className="text-xs text-slate-500">Whitelisted Gateway MAC Addresses</label>
            <div className="flex gap-2 mt-1">
              <input
                value={newMac}
                onChange={(e) => setNewMac(e.target.value)}
                placeholder="aa:bb:cc:dd:ee:ff"
                className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 font-mono text-sm"
              />
              <button onClick={addMac} className="bg-slate-800 hover:bg-slate-700 px-3 rounded-lg">
                <Plus size={16} />
              </button>
            </div>
            <div className="flex flex-wrap gap-2 mt-2">
              {(config.whitelist_gateway_macs || []).map((mac) => (
                <span key={mac} className="flex items-center gap-1 text-xs font-mono bg-slate-800 px-2 py-1 rounded-lg">
                  {mac}
                  <button onClick={() => removeMac(mac)} className="text-slate-500 hover:text-red-400">
                    <Trash size={12} />
                  </button>
                </span>
              ))}
            </div>
          </div>

          {configMsg && <p className="text-xs text-slate-400">{configMsg}</p>}
          <button onClick={saveConfig} className="flex items-center gap-2 bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-medium">
            <Save size={14} /> Save Configuration
          </button>
        </div>
      )}
    </div>
  );
}
