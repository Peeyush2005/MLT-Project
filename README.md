# Live Threat Simulation Platform

Fullstack SOC-style platform wrapping an existing trained XGBoost IOC classifier.

- Backend: FastAPI + SQLite + WebSocket stream
- Frontend: React + Tailwind dashboard
- Model: Existing joblib artifacts from the original notebook

## Required Artifacts

Place these files at repository root:

- malware_detector_model.pkl
- malware_detector_encoders.pkl
- malware_detector_features.pkl
- malware_detector_cat_cols.pkl
- metrics.json

Backend startup fails fast with explicit missing-file names if any are absent.

## Backend Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend endpoints:

- GET /api/health (no key)
- POST /api/keys
- GET /api/keys
- DELETE /api/keys/{key_id}
- GET /api/keys/{key_id}/usage
- POST /api/predict (requires X-API-Key)
- POST /api/predict/batch (requires X-API-Key)
- POST /api/predict/csv (requires X-API-Key)
- GET /api/model/info
- GET /api/model/feature-importance
- GET /api/stream/stats (requires X-API-Key)
- GET /api/simulate/scenarios (requires X-API-Key)
- POST /api/simulate/scenario (requires X-API-Key)
- WS /api/ws/stream?api_key=<raw_key>

## API Key and Rate Limiting

- Keys are generated as mw_live_sk_<token> and only shown once.
- Stored hashed in SQLite (SHA-256), never compared in raw form.
- Protected routes require X-API-Key.
- Revoked or invalid key returns 401.
- Per-key token bucket rate limiting returns 429 with Retry-After.
- Usage counters tracked per key: requests_total, requests_today, hourly usage series.

SQLite database:

- backend/data/app.db (auto-created)
- ignored via backend/.gitignore

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

The dashboard includes:

- Live Feed (default): live stream rows, scenario injector, mini chart, expandable event details
- Manual Analysis: form + side-by-side result panel with real probability bars
- Batch / CSV Upload: upload, per-row errors, annotated CSV download
- Model Insights: feature importances + model metrics
- Pipeline Walkthrough: 8-stage explanation and real inference call
- Developer Portal: key generation/list/revoke + per-key usage chart

## Stream URL and Auth

Frontend uses:

- WebSocket: ws://localhost:5173/api/ws/stream?api_key=<raw_key>

Vite proxies /api to backend (including websocket traffic).

## Tests

Run fast smoke tests:

```bash
cd backend
source .venv/bin/activate
pytest tests/test_smoke.py -q
```

Current smoke coverage:

- Predict contract + probability sum
- Unseen categorical fallback behavior
- Malformed numeric field returns 422
- API key lifecycle: create -> predict -> revoke -> 401
- Rate limit: 429 + Retry-After
- Route status checks (predict, batch, csv, model info, feature importance, health, keys, scenarios, stream stats)
- Golden regression records (expected labels)
- CSV 5-row case with 1 bad row

Pre-demo script (backend running):

```bash
cd backend
bash scripts/smoke_check.sh
```

Checks:

- /api/health
- create temporary key
- one /api/predict call using X-API-Key
- /api/stream/stats using X-API-Key

## Demo Walkthrough

1. Open Developer Portal and create a key.
2. Copy and set that key as active.
3. Open Live Feed and observe ambient events auto-arriving every ~1-3 seconds.
4. Inject a scenario (for example ransomware_burst).
5. Show injected rows highlighted in feed and updated live stats.
6. Open Manual Analysis and run a record to show probability bar fill.
7. Return to Developer Portal and show key usage chart updates.
