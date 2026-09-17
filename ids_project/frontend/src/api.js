const API_BASE = "/api";

function getToken() {
  return localStorage.getItem("ids_token");
}

export function setToken(token) {
  if (token) localStorage.setItem("ids_token", token);
  else localStorage.removeItem("ids_token");
}

async function request(path, options = {}) {
  const headers = options.headers || {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (options.body && !(options.body instanceof URLSearchParams)) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (res.status === 401) {
    setToken(null);
    window.location.reload();
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `Request failed: ${res.status}`);
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return res.json();
  return res;
}

export const api = {
  login: async (username, password) => {
    const body = new URLSearchParams();
    body.append("username", username.trim());
    body.append("password", password);
    const res = await fetch(`${API_BASE}/auth/login`, { method: "POST", body });
    if (!res.ok) {
      let message = "Login failed";
      try {
        const data = await res.json();
        message = data.detail || message;
      } catch {
        // Keep the generic message when the server does not return JSON.
      }
      throw new Error(message);
    }
    const data = await res.json();
    setToken(data.access_token);
    return data;
  },
  logout: () => setToken(null),
  me: () => request("/auth/me"),
  updateAccount: (payload) => request("/auth/account", { method: "PUT", body: JSON.stringify(payload) }),

  getConfig: () => request("/config"),
  updateConfig: (payload) => request("/config", { method: "PUT", body: JSON.stringify(payload) }),

  getAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/alerts${qs ? `?${qs}` : ""}`);
  },
  getAlertDetail: (id) => request(`/alerts/${id}`),
  submitFeedback: (id, label) => request(`/alerts/${id}/feedback`, { method: "POST", body: JSON.stringify({ label }) }),
  clearLogs: () => request("/alerts", { method: "DELETE" }),
  exportUrl: (fmt, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    const token = getToken();
    return `${API_BASE}/alerts/export/${fmt}${qs ? `?${qs}` : ""}`;
  },

  retrainModel: () => request("/model/retrain", { method: "POST" }),
  modelStatus: () => request("/model/status"),
  arpTable: () => request("/network/arp-table"),
};

export function wsUrl(path) {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.host;
  return `${proto}://${host}${path}`;
}

export { getToken };
