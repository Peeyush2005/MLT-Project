"""WebSocket stream manager and realistic ambient IOC simulation."""

import asyncio
import json
import random
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from fastapi import WebSocket

from app.audit import write_audit_event
from app.inference import predict_malware

# ---------------------------------------------------------------------------
# Ring buffer — thread-safe deque with maxlen
# ---------------------------------------------------------------------------
MAX_BUFFER = 200
_event_buffer: deque = deque(maxlen=MAX_BUFFER)


def get_buffer_snapshot() -> list[dict]:
    return list(_event_buffer)


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class _Manager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, payload: dict) -> None:
        msg = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)
        for ws in targets:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

    def client_count(self) -> int:
        return len(self._connections)


manager = _Manager()

# ---------------------------------------------------------------------------
# Realistic IOC generator — exact notebook noise-injection distributions
# ---------------------------------------------------------------------------


def generate_ioc(label: Optional[int] = None) -> dict:
    """
    Generate a single realistic IOC record.
    label=1 → malware, label=0 → benign, label=None → 90% malware.
    Uses IDENTICAL per-class distributions as the notebook's Step 1.
    """
    if label is None:
        label = 1 if random.random() < 0.9 else 0

    if label == 1:
        threat_types = ["botnet_cc", "phishing", "trojan", "ransomware", "spyware"]
        threat_type = (
            random.choice(threat_types) if random.random() > 0.15 else "benign"
        )
        fam_pool = [
            "emotet",
            "trickbot",
            "qakbot",
            "cobalt_strike",
            "redline_stealer",
            "lockbit",
        ]
        fam_w = [0.22, 0.20, 0.15, 0.15, 0.14, 0.14]
        malware_family = (
            random.choices(fam_pool, fam_w)[0] if random.random() > 0.20 else "none"
        )
        confidence_level = int(np.clip(np.random.normal(58, 22), 0, 100))
        ports = [443, 8080, 4444, 6667, 80, 53, 8443, 1337, 9001]
        pw = [0.18, 0.18, 0.10, 0.07, 0.18, 0.10, 0.07, 0.06, 0.06]
        dst_port = random.choices(ports, pw)[0]
        days_active = int(np.clip(np.random.exponential(9), 0, 90))
        countries = [
            "US",
            "RU",
            "CN",
            "NL",
            "DE",
            "BR",
            "IN",
            "VN",
            "FR",
            "GB",
            "UA",
            "KR",
        ]
        cw = [0.13, 0.14, 0.12, 0.08, 0.07, 0.07, 0.08, 0.08, 0.06, 0.06, 0.07, 0.04]
        src_country = random.choices(countries, cw)[0]
        ioc_type = random.choices(
            ["ip", "domain", "url", "hash"], [0.32, 0.33, 0.20, 0.15]
        )[0]
        tag_pool = [
            "c2",
            "exfil",
            "suspicious",
            "recon",
            "lateral_movement",
            "persistence",
            "none",
        ]
        tw = [0.16, 0.13, 0.15, 0.10, 0.10, 0.10, 0.26]
        tags = random.choices(tag_pool, tw)[0]
        reporters = [
            "analyst_team_a",
            "analyst_team_b",
            "automated_feed_1",
            "automated_feed_2",
            "partner_org",
            "honeypot_net",
        ]
        rw = [0.17, 0.17, 0.22, 0.18, 0.12, 0.14]
        reporter = random.choices(reporters, rw)[0]
    else:
        threat_type = (
            "benign"
            if random.random() > 0.25
            else random.choice(
                ["botnet_cc", "phishing", "trojan", "ransomware", "spyware"]
            )
        )
        malware_family = (
            "none"
            if random.random() > 0.10
            else random.choice(
                [
                    "emotet",
                    "trickbot",
                    "qakbot",
                    "cobalt_strike",
                    "redline_stealer",
                    "lockbit",
                ]
            )
        )
        confidence_level = int(np.clip(np.random.normal(40, 22), 0, 100))
        ports = [80, 443, 22, 25, 53, 3306, 8080, 21]
        pw = [0.22, 0.20, 0.13, 0.08, 0.15, 0.08, 0.08, 0.06]
        dst_port = random.choices(ports, pw)[0]
        days_active = int(np.clip(np.random.exponential(6), 0, 90))
        countries = [
            "US",
            "RU",
            "CN",
            "NL",
            "DE",
            "BR",
            "IN",
            "VN",
            "FR",
            "GB",
            "UA",
            "KR",
        ]
        cw = [0.18, 0.06, 0.06, 0.10, 0.11, 0.06, 0.10, 0.05, 0.09, 0.10, 0.04, 0.05]
        src_country = random.choices(countries, cw)[0]
        ioc_type = random.choices(
            ["ip", "domain", "url", "hash"], [0.35, 0.30, 0.22, 0.13]
        )[0]
        tag_pool = ["scanner", "research", "cdn", "known_good", "monitoring", "none"]
        tw = [0.13, 0.13, 0.13, 0.13, 0.10, 0.38]
        tags = random.choices(tag_pool, tw)[0]
        reporters = [
            "analyst_team_a",
            "analyst_team_b",
            "automated_feed_1",
            "automated_feed_2",
            "partner_org",
            "honeypot_net",
        ]
        rw = [0.18, 0.18, 0.17, 0.13, 0.18, 0.16]
        reporter = random.choices(reporters, rw)[0]

    return {
        "ioc_type": ioc_type,
        "threat_type": threat_type,
        "malware_family": malware_family,
        "confidence_level": confidence_level,
        "dst_port": dst_port,
        "days_active": days_active,
        "src_country": src_country,
        "tags": tags,
        "reporter": reporter,
    }


def make_stream_event(
    raw_record: dict,
    source: str = "live_stream",
    is_injected: bool = False,
    scenario_id: Optional[str] = None,
) -> dict:
    """Run a raw record through the model and wrap the result as a stream event."""
    result = predict_malware(raw_record)
    ev = {
        "event_id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_record": raw_record,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "all_probabilities": result["all_probabilities"],
        "source": source,
        "is_injected": is_injected,
    }
    if scenario_id:
        ev["scenario_id"] = scenario_id
    return ev


async def push_event(event: dict) -> None:
    """Add event to ring buffer and broadcast to all connected WebSocket clients."""
    _event_buffer.append(event)
    await manager.broadcast({"type": "event", "data": event})


# ---------------------------------------------------------------------------
# Background generator task
# ---------------------------------------------------------------------------


async def stream_generator_task() -> None:
    """
    Infinite background task: generate + broadcast one IOC event every 1-3 s.
    Registered in FastAPI lifespan via asyncio.create_task().
    Never raises — swallows all exceptions to stay alive.
    """
    while True:
        try:
            await asyncio.sleep(random.uniform(1.0, 3.0))
            raw = generate_ioc()
            t0 = time.perf_counter()
            event = make_stream_event(raw, source="live_stream", is_injected=False)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            write_audit_event(
                key_id="system",
                source="live_stream",
                raw_record=raw,
                prediction=event["prediction"],
                confidence=float(event["confidence"]),
                latency_ms=latency_ms,
            )
            await push_event(event)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)


# ---------------------------------------------------------------------------
# Stats over ring buffer
# ---------------------------------------------------------------------------


def get_stream_stats() -> dict:
    """Rolling stats over the last 60 seconds of the ring buffer."""
    now = time.time()
    snapshot = get_buffer_snapshot()

    recent = []
    for ev in snapshot:
        try:
            ts_str = ev["timestamp"]
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            from datetime import datetime as _dt

            ts = _dt.fromisoformat(ts_str).timestamp()
            if now - ts <= 60:
                recent.append(ev)
        except Exception:
            pass

    total = len(recent)
    if total == 0:
        return {
            "events_last_60s": 0,
            "malware_rate": 0.0,
            "mean_confidence": 0.0,
            "top_src_country": {},
            "total_in_buffer": len(snapshot),
            "connected_clients": manager.client_count(),
        }

    malware_evs = [e for e in recent if e.get("prediction") == "malware"]
    country_mal: dict[str, int] = {}
    for ev in malware_evs:
        c = ev["raw_record"].get("src_country", "??")
        country_mal[c] = country_mal.get(c, 0) + 1
    top = dict(sorted(country_mal.items(), key=lambda x: x[1], reverse=True)[:5])

    return {
        "events_last_60s": total,
        "malware_rate": round(len(malware_evs) / total * 100, 1),
        "mean_confidence": round(sum(e["confidence"] for e in recent) / total, 4),
        "top_src_country": top,
        "total_in_buffer": len(snapshot),
        "connected_clients": manager.client_count(),
    }
