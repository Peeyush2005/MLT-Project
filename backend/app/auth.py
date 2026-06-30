"""API key creation, validation, masking, and per-key rate limiting."""

import hashlib
import secrets
import threading
import time
from math import ceil
from typing import Optional

from fastapi import Header, HTTPException

from app.db import get_key_by_hash

KEY_PREFIX = "mw_live_sk_"

_bucket_lock = threading.Lock()
_buckets: dict[str, dict] = {}


def generate_api_key() -> tuple[str, str]:
    """Return (raw_key, hash_hex). Raw key is only shown once on create."""
    raw_key = f"{KEY_PREFIX}{secrets.token_hex(16)}"
    return raw_key, hash_key(raw_key)


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def mask_key(key_hash: str) -> str:
    return f"{KEY_PREFIX}....{key_hash[-4:]}"


def _consume_token(key_id: str, rate_limit_per_min: int) -> tuple[bool, int]:
    """
    Token-bucket limiter. Returns (allowed, retry_after_seconds).
    """
    now = time.monotonic()
    rate = max(1, int(rate_limit_per_min))
    refill_per_second = rate / 60.0

    with _bucket_lock:
        bucket = _buckets.get(key_id)
        if bucket is None:
            bucket = {"tokens": float(rate), "last_refill": now}
            _buckets[key_id] = bucket

        elapsed = now - bucket["last_refill"]
        bucket["tokens"] = min(float(rate), bucket["tokens"] + elapsed * refill_per_second)
        bucket["last_refill"] = now

        if bucket["tokens"] >= 1.0:
            bucket["tokens"] -= 1.0
            return True, 0

        missing = 1.0 - bucket["tokens"]
        retry_after = max(1, ceil(missing / refill_per_second))
        return False, retry_after


def _load_key_record(raw_key: str) -> Optional[dict]:
    if not raw_key:
        return None
    record = get_key_by_hash(hash_key(raw_key))
    if not record:
        return None
    if not bool(record.get("is_active", 0)):
        return None
    return dict(record)


async def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> dict:
    record = _load_key_record(x_api_key)
    if not record:
        raise HTTPException(
            status_code=401,
            detail={"error": "Missing, invalid, or revoked API key", "code": "UNAUTHORIZED"},
        )

    allowed, retry_after = _consume_token(
        str(record["key_id"]),
        int(record.get("rate_limit_per_min", 60)),
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "code": "RATE_LIMITED",
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    return record


def validate_ws_key(api_key: str) -> Optional[dict]:
    record = _load_key_record(api_key)
    if not record:
        return None

    allowed, _ = _consume_token(
        str(record["key_id"]),
        int(record.get("rate_limit_per_min", 60)),
    )
    if not allowed:
        return None
    return record
