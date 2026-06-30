"""Structured JSONL audit logging for prediction events."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BACKEND_DIR = Path(__file__).parent.parent
_AUDIT_LOG = _BACKEND_DIR / "predictions.jsonl"


def _hash_input(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_audit_event(
    *,
    key_id: str,
    source: str,
    raw_record: dict[str, Any],
    prediction: str,
    confidence: float,
    latency_ms: float,
) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "key_id": key_id,
        "input_hash": _hash_input(raw_record),
        "prediction": prediction,
        "confidence": float(confidence),
        "latency_ms": round(float(latency_ms), 3),
        "source": source,
    }
    try:
        with open(_AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        # Logging should never break live inference.
        return
