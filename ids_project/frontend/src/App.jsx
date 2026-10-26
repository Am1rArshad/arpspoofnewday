import React, { useEffect, useState } from "react";
import { Activity, Bell, BrainCircuit, Settings, Sun, Moon, Loader2 } from "lucide-react";
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
  const isLandingRoute = window.location.pathname === "/";
  const isLoginRoute = window.location.pathname === "/login";
  const [authed, setAuthed] = useState(false);
  const [user, setUser] = useState(null);
  const [tab, setTab] = useState("overview");
  const [checking, setChecking] = useState(true);
  const [startupProgress, setStartupProgress] = useState(12);
  const [darkMode, setDarkMode] = useState(() => localStorage.getItem("arp-ids-theme") !== "light");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", darkMode);
    document.documentElement.classList.toggle("light-mode", !darkMode);
    document.body.classList.toggle("light-mode", !darkMode);
    localStorage.setItem("arp-ids-theme", darkMode ? "dark" : "light");
  }, [darkMode]);

  useEffect(() => {
    if (!checking) {
      setStartupProgress(100);
      return undefined;
    }

    const timer = window.setInterval(() => {
      setStartupProgress((progress) => Math.min(progress + 8, 88));
    }, 180);
    return () => window.clearInterval(timer);
  }, [checking]);

  useEffect(() => {
    if (isLandingRoute) {
      window.location.replace("/landing.html");
      return undefined;
    }
    if (isLoginRoute) {
      setChecking(false);
      return undefined;
    }
    if (getToken()) {
      api.me().then((u) => { setUser(u); setAuthed(true); }).catch(() => setAuthed(false)).finally(() => setChecking(false));
    } else {
      setChecking(false);
    }
  }, [isLandingRoute, isLoginRoute]);

  const handleLoginSuccess = async () => {
    const u = await api.me();
    setUser(u);
    setAuthed(true);
    window.history.replaceState({}, "", "/dashboard");
  };

  const handleLogout = () => {
    api.logout();
    setAuthed(false);
    setUser(null);
    window.history.replaceState({}, "", "/login");
  };

  if (isLandingRoute) return null;
  if (checking) {
    return (
      <div className="startup-overlay" role="status" aria-live="polite">
        <div className="startup-popup">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center">
              <Loader2 className="animate-spin text-cyan-400" size={21} />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-100">Starting ARP Security Box</p>
              <p className="text-xs text-slate-400">Loading modules and connecting to IDS</p>
            </div>
          </div>
          <div className="startup-progress-track" aria-hidden="true">
            <div className="startup-progress-bar" style={{ width: `${startupProgress}%` }} />
          </div>
          <p className="mt-2 text-right text-[11px] text-slate-500">{startupProgress}%</p>
        </div>
      </div>
    );
  }
  if (isLoginRoute || !authed) return <Login onSuccess={handleLoginSuccess} />;

  return (
    <div className={`min-h-screen flex ${darkMode ? "" : "light-mode"}`}>
      <aside className="w-64 bg-slate-900 border-r border-slate-800 p-4 flex flex-col">
        <div className="flex items-center gap-3 mb-8 px-2">
          <img src="/image/octopus.png" alt="ARP Security Box logo" className="h-12 w-12 object-contain" />
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
                tab === t.id ? "bg-cyan-400 text-slate-950" : "text-slate-400 hover:bg-slate-800 hover:text-white"
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

      <main className="relative flex-1 p-6 overflow-y-auto">
        <button
          type="button"
          onClick={() => setDarkMode((isDark) => !isDark)}
          aria-label={`Switch to ${darkMode ? "light" : "dark"} mode`}
          title={`Switch to ${darkMode ? "light" : "dark"} mode`}
          className="absolute top-5 right-6 flex h-9 w-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-900 text-slate-300 transition hover:border-cyan-400 hover:text-white light-mode:border-slate-300 light-mode:bg-white light-mode:text-slate-600 light-mode:hover:text-slate-900"
        >
          {darkMode ? <Sun size={17} /> : <Moon size={17} />}
        </button>
        {tab === "overview" && <NetworkOverview />}
        {tab === "alerts" && <AlertCenter />}
        {tab === "model" && <ModelControl />}
        {tab === "account" && <AccountConfig user={user} onLogout={handleLogout} />}
      </main>
    </div>
  );
}
