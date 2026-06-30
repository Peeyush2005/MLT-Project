# Live Threat Simulation Platform - Presentation Guide

## Slide 1 - Title

Title:
Live Threat Simulation Platform

Subtitle:
Real-time SOC Dashboard powered by existing XGBoost IOC Malware Classifier

Talk track:
- This project wraps an already-trained model in a realistic security operations experience.
- The goal was not to retrain ML, but to productize it: auth, rate limiting, live traffic simulation, scenario injection, and analyst workflows.

## Slide 2 - Problem and Goal

Title:
What problem are we solving?

Bullets:
- Raw model endpoints feel static and demo-poor.
- Security teams need continuous telemetry, not one-off form submits.
- Need realistic API key product behavior for external users.
- Need confidence, auditability, and stability under demo conditions.

Talk track:
- The old pattern is request/response only.
- The new system behaves like a SOC console: always-on event flow, inject-able attacks, and developer-facing key governance.

## Slide 3 - System Architecture

Title:
Architecture Overview

Bullets:
- Backend: FastAPI service with model wrapper + auth + streaming + simulation + audit.
- Data store: SQLite for API keys and per-hour usage aggregates.
- Frontend: React + Tailwind cyberpunk SOC dashboard with 6 views.
- Transport: REST for control/data, WebSocket for live event stream.

Talk track:
- The ML model remains unchanged.
- Everything around it is production wrapper and UX orchestration.

## Slide 4 - Model Contract (Unchanged)

Title:
Inference Contract Preserved

Bullets:
- Loads 4 model artifacts once at startup.
- Reindexes incoming record to saved feature order.
- Encodes categoricals with fallback for unseen values.
- Returns prediction, class index, confidence, and full probabilities.

Talk track:
- This is critical: we preserved notebook behavior exactly.
- We did not alter model architecture or training strategy.

Reference:
- [backend/app/inference.py](backend/app/inference.py)

## Slide 5 - Startup and Reliability

Title:
Fail-fast startup and service lifecycle

Bullets:
- Startup validates required artifacts and logs load status.
- Database initialized on app startup.
- Ambient stream generator starts automatically.
- Health endpoint stays public for status indicators.

Talk track:
- If artifacts are missing, startup fails loudly and clearly.
- This avoids silent misconfiguration during demo day.

Reference:
- [backend/app/main.py](backend/app/main.py)
- [backend/app/routes/health.py](backend/app/routes/health.py)

## Slide 6 - API Keys and Security Model

Title:
Real API Key Product Behavior

Bullets:
- Key creation returns raw key once.
- Raw keys are never stored; only SHA-256 hashes.
- Listing returns masked key form.
- Revocation disables access immediately.
- Protected endpoints require X-API-Key header.

Talk track:
- This follows common SaaS security patterns.
- After creation, users must save their key because backend cannot re-display it.

Reference:
- [backend/app/routes/keys.py](backend/app/routes/keys.py)
- [backend/app/auth.py](backend/app/auth.py)
- [backend/app/db.py](backend/app/db.py)

## Slide 7 - Rate Limiting and Usage Analytics

Title:
Per-key Traffic Controls + Insights

Bullets:
- Token-bucket limiter enforced per key.
- Rate exceed returns 429 with Retry-After.
- Usage counters track total and daily usage.
- Hourly aggregates power 24h usage charts.

Talk track:
- Limiting is enforced server-side.
- Same data powers operational analytics in the Developer Portal.

Reference:
- [backend/app/auth.py](backend/app/auth.py)
- [backend/app/db.py](backend/app/db.py)

## Slide 8 - Live Stream (Core Experience)

Title:
Always-on Simulated Traffic Stream

Bullets:
- Background task emits synthetic IOC events every 1-3 seconds.
- Records run through real predict_malware pipeline.
- Ring buffer holds recent events for instant client backfill.
- All connected clients receive events via WebSocket broadcast.

Talk track:
- The UI feels alive before any manual interaction.
- New clients do not connect to an empty screen.

Reference:
- [backend/app/stream.py](backend/app/stream.py)
- [backend/app/routes/streaming.py](backend/app/routes/streaming.py)

## Slide 9 - Scenario Injection

Title:
On-demand Attack Simulation

Bullets:
- Frontend fetches available scenarios dynamically.
- User triggers named scenario injection.
- Backend emits injected events into same live stream.
- Injected events are visibly distinct in UI.

Talk track:
- This supports storytelling: ransomware burst, C2 beaconing, phishing wave.
- Scenarios are concrete records mapped to real feature vocabularies.

Reference:
- [backend/app/scenarios.py](backend/app/scenarios.py)
- [backend/app/routes/streaming.py](backend/app/routes/streaming.py)

## Slide 10 - Prediction Workflows

Title:
Analysis Modes

Bullets:
- Single prediction endpoint for manual analysis.
- Batch prediction for up to 500 records.
- CSV upload with per-row error handling.
- Annotated CSV returned for downstream review.

Talk track:
- This supports both analyst triage and bulk ingestion operations.

Reference:
- [backend/app/routes/predict.py](backend/app/routes/predict.py)

## Slide 11 - Audit and Traceability

Title:
Structured Audit Logging

Bullets:
- Every prediction event emits JSONL log entry.
- Includes timestamp, key_id, input hash, prediction, confidence, latency, source.
- Source distinguishes manual, batch, csv, scenario, and ambient stream.

Talk track:
- This is vital for forensic traceability and post-demo analysis.

Reference:
- [backend/app/audit.py](backend/app/audit.py)
- [backend/predictions.jsonl](backend/predictions.jsonl)

## Slide 12 - Frontend UX Strategy

Title:
SOC Dashboard Design

Bullets:
- Persistent header and nav across all views.
- Live telemetry strip with API and stream stats.
- Dense panel layout inspired by SOC/NOC consoles.
- Neon visual language for verdict clarity.

Talk track:
- The interface emphasizes information density and continual motion.
- No dead zones, no static single form page.

Reference:
- [frontend/src/App.jsx](frontend/src/App.jsx)
- [frontend/src/index.css](frontend/src/index.css)

## Slide 13 - Six Views Walkthrough

Title:
User Journey Across Views

Bullets:
- Live Feed: real-time events, details, scenario injection, mini trend chart.
- Manual Analysis: form + side-by-side result panel.
- Batch/CSV: upload, summary, table, annotated export.
- Model Insights: feature importance and metrics.
- Pipeline Walkthrough: explainable stage-by-stage flow.
- Developer Portal: key management + usage chart.

Reference:
- [frontend/src/views/LiveFeed.jsx](frontend/src/views/LiveFeed.jsx)
- [frontend/src/views/ManualAnalysis.jsx](frontend/src/views/ManualAnalysis.jsx)
- [frontend/src/views/BatchUpload.jsx](frontend/src/views/BatchUpload.jsx)
- [frontend/src/views/ModelInsights.jsx](frontend/src/views/ModelInsights.jsx)
- [frontend/src/views/PipelineWalkthrough.jsx](frontend/src/views/PipelineWalkthrough.jsx)
- [frontend/src/views/DeveloperPortal.jsx](frontend/src/views/DeveloperPortal.jsx)

## Slide 14 - Critical Bug Fix Verification

Title:
Probability Bar Bug - Fixed

Bullets:
- Prior bug: bars showed 0 percent despite high confidence.
- Fix: UI width is bound directly to numeric probabilities.
- Uses all_probabilities payload from backend response contract.
- Verified in manual and stream detail rendering.

Talk track:
- This was a trust issue in model explainability.
- We fixed the binding at component level and reused it consistently.

Reference:
- [frontend/src/components/shared/ConfidenceBar.jsx](frontend/src/components/shared/ConfidenceBar.jsx)
- [frontend/src/views/ManualAnalysis.jsx](frontend/src/views/ManualAnalysis.jsx)
- [frontend/src/views/LiveFeed.jsx](frontend/src/views/LiveFeed.jsx)

## Slide 15 - Testing and Demo Readiness

Title:
Smoke-tested for hackathon speed

Bullets:
- Pytest smoke suite validates key lifecycle, auth, rate limits, routes, and regressions.
- Golden records catch unexpected model artifact swaps.
- Demo smoke script runs health, key create, predict, stream stats checks.

Reference:
- [backend/tests/test_smoke.py](backend/tests/test_smoke.py)
- [backend/scripts/smoke_check.sh](backend/scripts/smoke_check.sh)

## Slide 16 - Notebook to Backend Metrics Flow

Title:
Metrics Export Pipeline

Bullets:
- Notebook final cell exports metrics.json from actual computed metrics.
- Backend serves these metrics without hardcoding.
- Frontend insights panels display real values from API.

Reference:
- [MLT_Project (2).ipynb](MLT_Project%20(2).ipynb)
- [metrics.json](metrics.json)
- [backend/app/routes/model_info.py](backend/app/routes/model_info.py)

## Slide 17 - Demo Script (What to click)

Title:
Live Demo Sequence (5-7 minutes)

Bullets:
- Open Developer Portal, create API key, copy once.
- Set active key and switch to Live Feed.
- Wait for ambient stream rows to arrive.
- Inject ransomware_burst scenario.
- Expand injected row and show probability bars.
- Move to Manual Analysis and run one sample.
- Open Developer Portal usage chart to show activity impact.

## Slide 18 - Wrap-up

Title:
Outcome and Next Steps

Bullets:
- Converted static model API into realistic SOC simulation platform.
- Added practical API product controls and observability.
- Preserved ML behavior while improving operational usability.

Possible next steps:
- Role-based access and key scopes.
- Persistent event storage and replay controls.
- Alert rules and webhook integrations.
- Containerized deploy and staging environment.

---

## 60-second elevator summary

This project wraps an existing XGBoost malware classifier in a full SOC-like product surface. The backend adds secure API key lifecycle, per-key throttling, usage analytics, structured audit logging, and a live WebSocket event stream with ambient and injected scenario traffic. The frontend turns that into a dense six-view cyber dashboard where analysts can watch continuous threat flow, run manual and batch analysis, inspect model insights, and manage API keys like a real developer platform. The model logic itself remains unchanged and faithful to the original notebook pipeline.
