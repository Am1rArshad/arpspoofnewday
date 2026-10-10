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
  const [smtpPassword, setSmtpPassword] = useState("");
  const [emailMsg, setEmailMsg] = useState("");
  const [ntfyToken, setNtfyToken] = useState("");
  const [ntfyMsg, setNtfyMsg] = useState("");
  const [activeSection, setActiveSection] = useState("account");

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
      const payload = {
        interface: config.interface,
        dashboard_interface: config.dashboard_interface,
        threshold_low: parseFloat(config.threshold_low),
        threshold_high: parseFloat(config.threshold_high),
        gratuitous_burst_count: parseInt(config.gratuitous_burst_count, 10),
        whitelist_gateway_macs: config.whitelist_gateway_macs,
        email_notifications_enabled: config.email_notifications_enabled,
        smtp_host: config.smtp_host,
        smtp_port: parseInt(config.smtp_port, 10),
        smtp_username: config.smtp_username,
        smtp_use_tls: config.smtp_use_tls,
        notification_email: config.notification_email,
        email_min_severity: config.email_min_severity,
      };
      if (smtpPassword) payload.smtp_password = smtpPassword;
      if (ntfyToken) payload.ntfy_token = ntfyToken;
      await api.updateConfig(payload);
      setSmtpPassword("");
      setNtfyToken("");
      setConfigMsg("Configuration saved. Restart the IDS to apply the dashboard interface.");
    } catch (err) {
      setConfigMsg(err.message || "Save failed");
    }
  };

  const sendTestNtfy = async () => {
    setNtfyMsg("");
    try {
      await api.testNtfy(config.ntfy_server, config.ntfy_topic, ntfyToken);
      setNtfyMsg("Test notification sent successfully.");
    } catch (err) {
      setNtfyMsg(err.message || "Test notification failed");
    }
  };

  const sendTestEmail = async () => {
    setEmailMsg("");
    try {
      await api.testEmail(config.notification_email);
      setEmailMsg("Test email sent successfully.");
    } catch (err) {
      setEmailMsg(err.message || "Test email failed");
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

      <div className="flex gap-1 border-b border-slate-800 overflow-x-auto">
        {[
          ["account", "Account Settings"],
          ["network", "IDS & Network Settings"],
          ["notifications", "Notifications & Email"],
        ].map(([section, label]) => (
          <button
            key={section}
            type="button"
            onClick={() => setActiveSection(section)}
            className={`whitespace-nowrap px-3 py-2 text-sm border-b-2 transition ${
              activeSection === section
                ? "border-red-500 text-white"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {activeSection === "account" && <form onSubmit={saveAccount} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
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
      </form>}

      {config && activeSection !== "account" && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
          {activeSection === "network" && <>
            <h3 className="text-sm font-medium text-slate-300">IDS & Network Settings</h3>

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

            <div>
            <label className="text-xs text-slate-500">Dashboard Interface (external access)</label>
            <select
              value={config.dashboard_interface || ""}
              onChange={(e) => setConfig({ ...config, dashboard_interface: e.target.value })}
              className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2"
            >
              {(config.available_dashboard_interfaces || []).length === 0 && <option value="">(none detected)</option>}
              {(config.available_dashboard_interfaces || []).map((iface) => (
                <option key={iface} value={iface}>{iface}</option>
              ))}
            </select>
            <p className="text-xs text-slate-500 mt-1">Restart the IDS after changing this interface.</p>
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
          </>}

          {activeSection === "notifications" && <>
          <h3 className="text-sm font-medium text-slate-300">Notifications & Email</h3>
          <div className="border-t border-slate-800 pt-4 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-slate-300">Email Notifications</h3>
                <p className="text-xs text-slate-500 mt-1">Receive new IDS alerts by email.</p>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={Boolean(config.email_notifications_enabled)}
                  onChange={(e) => setConfig({ ...config, email_notifications_enabled: e.target.checked })} />
                Enabled
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-500">SMTP Host</label>
                <input value={config.smtp_host || ""} onChange={(e) => setConfig({ ...config, smtp_host: e.target.value })}
                  placeholder="smtp.example.com" className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">SMTP Port</label>
                <input type="number" value={config.smtp_port || 587} onChange={(e) => setConfig({ ...config, smtp_port: e.target.value })}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">SMTP Username</label>
                <input value={config.smtp_username || ""} onChange={(e) => setConfig({ ...config, smtp_username: e.target.value })}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">SMTP Password</label>
                <input type="password" value={smtpPassword} onChange={(e) => setSmtpPassword(e.target.value)}
                  placeholder={config.smtp_password_configured ? "Saved password" : "Required for authenticated SMTP"}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">Notification Email</label>
                <input type="email" value={config.notification_email || ""} onChange={(e) => setConfig({ ...config, notification_email: e.target.value })}
                  placeholder="security@example.com" className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">Minimum Severity</label>
                <select value={config.email_min_severity || "High"} onChange={(e) => setConfig({ ...config, email_min_severity: e.target.value })}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2">
                  <option value="High">High</option>
                  <option value="Medium">Medium and High</option>
                  <option value="Low">All alerts</option>
                </select>
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={config.smtp_use_tls !== false}
                onChange={(e) => setConfig({ ...config, smtp_use_tls: e.target.checked })} />
              Use STARTTLS (disable only for SSL SMTP providers)
            </label>
            {emailMsg && <p className="text-xs text-slate-400">{emailMsg}</p>}
            <button onClick={sendTestEmail} type="button" className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg text-sm">
              Send Test Email
            </button>
          </div>

          <div className="border-t border-slate-800 pt-4 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-medium text-slate-300">ntfy Notifications</h3>
                <p className="text-xs text-slate-500 mt-1">Send push notifications through ntfy.sh or a self-hosted ntfy server.</p>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={Boolean(config.ntfy_notifications_enabled)}
                  onChange={(e) => setConfig({ ...config, ntfy_notifications_enabled: e.target.checked })} />
                Enabled
              </label>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-500">ntfy Server</label>
                <input value={config.ntfy_server || "https://ntfy.sh"} onChange={(e) => setConfig({ ...config, ntfy_server: e.target.value })}
                  placeholder="https://ntfy.sh" className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">Topic</label>
                <input value={config.ntfy_topic || ""} onChange={(e) => setConfig({ ...config, ntfy_topic: e.target.value })}
                  placeholder="my-unique-ids-topic" className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">Access Token (optional)</label>
                <input type="password" value={ntfyToken} onChange={(e) => setNtfyToken(e.target.value)}
                  placeholder={config.ntfy_token_configured ? "Saved token" : "Required for private topics"}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="text-xs text-slate-500">Minimum Severity</label>
                <select value={config.ntfy_min_severity || "High"} onChange={(e) => setConfig({ ...config, ntfy_min_severity: e.target.value })}
                  className="w-full mt-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2">
                  <option value="High">High</option>
                  <option value="Medium">Medium and High</option>
                  <option value="Low">All alerts</option>
                </select>
              </div>
            </div>
            {ntfyMsg && <p className="text-xs text-slate-400">{ntfyMsg}</p>}
            <button onClick={sendTestNtfy} type="button" className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg text-sm">
              Send Test Notification
            </button>
          </div>
            </>}

            {configMsg && <p className="text-xs text-slate-400">{configMsg}</p>}
            <button onClick={saveConfig} className="flex items-center gap-2 bg-red-600 hover:bg-red-500 px-4 py-2 rounded-lg text-sm font-medium">
              <Save size={14} /> Save Configuration
            </button>
        </div>
      )}
    </div>
  );
}
