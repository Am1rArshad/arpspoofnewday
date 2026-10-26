import React, { useState } from "react";
import { api } from "../api";

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.login(username, password);
      onSuccess();
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-shell min-h-screen flex items-center justify-center px-4">
      <a href="/" className="login-home-link" aria-label="Return to landing page">
        <span aria-hidden="true">&#8592;</span> Back to Home
      </a>
      <form onSubmit={submit} className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-2xl p-8">
        <div className="flex flex-col items-center mb-6">
          <img src="/image/octopus.png" alt="ARP Security Box logo" className="h-[4.5rem] w-[4.5rem] object-contain mb-4" />
          <h1 className="text-xl font-semibold">ARP Security Box</h1>
          <p className="text-slate-400 text-sm">Real-time Threat Detection Dashboard</p>
        </div>

        {error && (
          <div className="mb-4 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
            {error}
          </div>
        )}

        <label className="text-xs uppercase tracking-wide text-slate-400">Username</label>
        <input
          className="w-full mt-1 mb-4 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-400"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />

        <label className="text-xs uppercase tracking-wide text-slate-400">Password</label>
        <input
          type="password"
          className="w-full mt-1 mb-6 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-400"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <button
          disabled={loading}
          className="w-full bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition rounded-lg py-2 font-semibold disabled:opacity-50"
        >
          {loading ? "Signing in..." : "Sign In"}
        </button>

        <p className="text-xs text-slate-500 mt-4 text-center">
          Default credentials: admin / admin123
        </p>
      </form>
    </div>
  );
}
