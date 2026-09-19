import React, { useEffect, useState } from "react";
import { Shield, Activity, Bell, BrainCircuit, Settings } from "lucide-react";
import { api, getToken } from "./api";
import Login from "./components/Login";
import NetworkOverview from "./components/NetworkOverview";
import AlertCenter from "./components/AlertCenter";
import AccountConfig from "./components/AccountConfig";
import ModelControl from "./components/ModelControl";

const TABS = [
  { id: "overview", label: "Network Overview", icon: Activity },
  { id: "alerts", label: "Alert Center", icon: Bell },
  { id: "model", label: "Model Control", icon: BrainCircuit },
  { id: "account", label: "Account & Config", icon: Settings },
];

export default function App() {
  const [authed, setAuthed] = useState(false);
  const [user, setUser] = useState(null);
  const [tab, setTab] = useState("overview");
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    if (getToken()) {
      api.me().then((u) => { setUser(u); setAuthed(true); }).catch(() => setAuthed(false)).finally(() => setChecking(false));
    } else {
      setChecking(false);
    }
  }, []);

  const handleLoginSuccess = async () => {
    const u = await api.me();
    setUser(u);
    setAuthed(true);
  };

  const handleLogout = () => {
    api.logout();
    setAuthed(false);
    setUser(null);
  };

  if (checking) return null;
  if (!authed) return <Login onSuccess={handleLoginSuccess} />;

  return (
    <div className="min-h-screen flex">
      <aside className="w-64 bg-slate-900 border-r border-slate-800 p-4 flex flex-col">
        <div className="flex items-center gap-2 mb-8 px-2">
          <div className="w-9 h-9 rounded-lg bg-red-500/10 flex items-center justify-center">
            <Shield className="text-red-500" size={20} />
          </div>
          <div>
            <p className="font-semibold text-sm leading-tight">ARP Security Box</p>
            <p className="text-xs text-slate-500">LAN MITM Detection</p>
          </div>
        </div>

        <nav className="space-y-1 flex-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition ${
                tab === t.id ? "bg-red-600 text-white" : "text-slate-400 hover:bg-slate-800 hover:text-white"
              }`}
            >
              <t.icon size={16} />
              {t.label}
            </button>
          ))}
        </nav>

        <div className="text-xs text-slate-500 px-2">
          Signed in as <span className="text-slate-300">{user?.username}</span>
        </div>
      </aside>

      <main className="flex-1 p-6 overflow-y-auto">
        {tab === "overview" && <NetworkOverview />}
        {tab === "alerts" && <AlertCenter />}
        {tab === "model" && <ModelControl />}
        {tab === "account" && <AccountConfig user={user} onLogout={handleLogout} />}
      </main>
    </div>
  );
}
