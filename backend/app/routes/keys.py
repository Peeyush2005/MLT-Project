"""API key lifecycle and usage routes."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.auth import generate_api_key, mask_key
from app.db import (
    create_key,
    get_hourly_usage_last_24h,
    get_key_by_id,
    list_keys,
    revoke_key,
)

router = APIRouter(prefix="/keys", tags=["Keys"])


class KeyCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    rate_limit_per_min: int = Field(default=60, ge=1, le=2000)


@router.post("")
def create_api_key(payload: KeyCreateRequest) -> dict:
    key_id = f"key_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()
    raw_key, key_hash = generate_api_key()

    create_key(
        key_id=key_id,
        key_hash=key_hash,
        label=payload.label.strip(),
        created_at=created_at,
        rate_limit_per_min=payload.rate_limit_per_min,
    )

    return {
        "api_key": raw_key,
        "key_id": key_id,
        "label": payload.label.strip(),
        "created_at": created_at,
        "rate_limit_per_min": payload.rate_limit_per_min,
    }


@router.get("")
def get_keys() -> dict:
    keys = []
    for item in list_keys():
        keys.append(
            {
                "key_id": item["key_id"],
                "label": item["label"],
                "created_at": item["created_at"],
                "requests_total": item["requests_total"],
                "requests_today": item["requests_today"],
                "last_used_at": item["last_used_at"],
                "rate_limit_per_min": item["rate_limit_per_min"],
                "is_active": bool(item["is_active"]),
                "masked_key": mask_key(item["key_hash"]),
            }
        )
    return {"keys": keys}


@router.delete("/{key_id}")
def delete_key(key_id: str) -> dict:
    if not get_key_by_id(key_id):
        raise HTTPException(status_code=404, detail={"error": "Key not found"})
    revoke_key(key_id)
    return {"status": "revoked", "key_id": key_id}


@router.get("/{key_id}/usage")
def key_usage(key_id: str) -> dict:
    record = get_key_by_id(key_id)
    if not record:
        raise HTTPException(status_code=404, detail={"error": "Key not found"})

    return {
        "key_id": key_id,
        "label": record["label"],
        "series": get_hourly_usage_last_24h(key_id),
    }
