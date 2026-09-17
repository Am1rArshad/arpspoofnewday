# Automated ARP Spoofing / LAN MITM Detection System

Real-time Intrusion Detection System (IDS) for ARP Spoofing, MAC Poisoning,
and LAN Man-in-the-Middle attacks. Hybrid rule-based + XGBoost detection
engine, FastAPI + WebSocket backend, React/Tailwind dashboard.

## Architecture

```
backend/
  sniffer.py    -> Scapy packet capture (background thread, raw sockets)
  features.py   -> Layer 2/3 feature extraction (Pandas)
  engine.py     -> Rule engine (Stage 1) + XGBoost scorer (Stage 2) + retrain pipeline
  auth.py       -> bcrypt password hashing + JWT sessions
  database.py   -> SQLite persistence (alerts, feedback, config, ARP state)
  main.py       -> FastAPI app, /ws/metrics + /ws/alerts, REST API
frontend/
  React (Vite) + Tailwind CSS dashboard, 3 tabs, native WebSocket client
```

## Requirements

- **Linux (Ubuntu/Debian recommended)** — Scapy's raw-socket capture requires
  a Linux kernel network stack; it will not work on Windows/macOS sandboxes
  or inside most containers without `--net=host` and elevated capabilities.
- Python 3.10+
- Node.js 18+ (for the frontend)
- Root privileges, OR `CAP_NET_RAW`/`CAP_NET_ADMIN` capability on the Python
  interpreter, to open raw sockets for packet capture.

## Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Option A: run as root (simplest for a lab/demo environment)
sudo venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000

# Option B: grant capabilities instead of running the whole server as root
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python3)
uvicorn main:app --host 0.0.0.0 --port 8000
```

The first run creates `ids_data.db` (SQLite) with a default admin account:

- **username:** `admin`
- **password:** `admin123`

Change this immediately from the Account & Configuration tab.

Set the capture interface (e.g. `eth0`, or your mirrored/SPAN port NIC) either
by editing the `interface` row in the `config` table, or from the dashboard's
IDS Configuration panel after logging in — the sniffer reloads its config
automatically without a restart.

## Frontend Setup

```bash
cd frontend
npm install
npm run dev        # dev server on http://localhost:5173, proxies /api and /ws to :8000
# or
npm run build       # production build -> frontend/dist, serve with any static host / nginx
```

## Run Both Services

From the project root, run:

```bash
chmod +x run_ids.sh
./run_ids.sh
```

The script starts the backend on `http://localhost:8000` and the frontend on
`http://localhost:5173`. Running it again stops the previous services first;
press `Ctrl-C` to stop the current pair. Service logs are written to `.run/`.

## Notes on the Detection Pipeline

1. **Cold start**: with no trained model yet, every ARP packet's rule-engine
   verdict (matched / not matched) is logged to `backend/bootstrap_buffer.jsonl`.
   Once enough samples with both classes exist, `engine.MLEngine.maybe_bootstrap()`
   automatically trains an initial XGBoost model — no manual step required.
2. **Human-in-the-loop**: mark alerts True Positive / False Positive from the
   dashboard. These go into the `feedback_dataset` table.
3. **Retraining**: the "Retrain Model with Feedback" button triggers
   `POST /api/model/retrain`, which trains a fresh XGBoost model on the
   bootstrap buffer + accumulated feedback in a background thread — the
   server keeps serving requests and scoring traffic with the old model
   while retraining runs, then swaps in the new model atomically.
4. **Explainability**: each ML-flagged alert stores SHAP (or, if SHAP fails
   to load, XGBoost feature-importance as a fallback) top contributing
   features, shown in the alert's inspection modal.

## Security Notes

- Change `auth.SECRET_KEY` in `backend/auth.py` before any real deployment
  (ideally load it from an environment variable).
- Put the dashboard behind HTTPS. The project report describes fronting it
  with a Cloudflare Tunnel so the dashboard is reachable without opening any
  inbound port on the router — that is a deployment-time step outside this
  codebase (`cloudflared tunnel --url http://localhost:8000`).
- Whitelist your legitimate gateway MAC address(es) from the Configuration
  tab to avoid false positives when the router itself sends gratuitous ARPs.

