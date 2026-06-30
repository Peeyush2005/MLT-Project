#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }

echo "Smoke check target: ${BASE_URL}"

HEALTH=$(curl -sS "${BASE_URL}/api/health" || true)
if echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status')=='ok' else 1)"; then
  pass "GET /api/health"
else
  fail "GET /api/health"
fi

KEY_RESP=$(curl -sS -X POST "${BASE_URL}/api/keys" -H "Content-Type: application/json" -d '{"label":"smoke-check","rate_limit_per_min":60}' || true)
API_KEY=$(echo "$KEY_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key',''))" 2>/dev/null || true)
if [ -n "$API_KEY" ]; then
  pass "POST /api/keys"
else
  fail "POST /api/keys"
fi

PRED_PAYLOAD='{"ioc_type":"domain","threat_type":"botnet_cc","malware_family":"emotet","confidence_level":75,"dst_port":4444,"days_active":15,"src_country":"RU","tags":"c2","reporter":"honeypot_net"}'
PRED=$(curl -sS -X POST "${BASE_URL}/api/predict" -H "Content-Type: application/json" -H "X-API-Key: ${API_KEY}" -d "$PRED_PAYLOAD" || true)
if echo "$PRED" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('prediction') in ('benign','malware') else 1)"; then
  pass "POST /api/predict with X-API-Key"
else
  fail "POST /api/predict with X-API-Key"
fi

STATS=$(curl -sS "${BASE_URL}/api/stream/stats" -H "X-API-Key: ${API_KEY}" || true)
if echo "$STATS" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'events_last_60s' in d else 1)"; then
  pass "GET /api/stream/stats with X-API-Key"
else
  fail "GET /api/stream/stats with X-API-Key"
fi

TOTAL=$((PASS + FAIL))
echo "${PASS}/${TOTAL} checks passed"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
