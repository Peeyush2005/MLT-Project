"""Live stream, simulation, and stream stats routes."""

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.audit import write_audit_event
from app.auth import require_api_key, validate_ws_key
from app.db import increment_usage
from app.scenarios import get_scenario_records, list_scenarios
from app.stream import (
    get_buffer_snapshot,
    get_stream_stats,
    make_stream_event,
    manager,
    push_event,
)

router = APIRouter(tags=["Stream"])


class ScenarioRequest(BaseModel):
    scenario: str


@router.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    api_key = websocket.query_params.get("api_key", "")
    key_record = validate_ws_key(api_key)
    if not key_record:
        await websocket.close(code=1008, reason="Missing/invalid/revoked API key")
        return

    await manager.connect(websocket)
    try:
        increment_usage(str(key_record["key_id"]), False, 0.0)
        await websocket.send_json(
            {
                "type": "backfill",
                "data": get_buffer_snapshot(),
            }
        )
        while True:
            # Keepalive receive to detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


@router.get("/stream/stats")
def stream_stats(_: dict = Depends(require_api_key)) -> dict:
    return get_stream_stats()


@router.get("/simulate/scenarios")
def scenarios(_: dict = Depends(require_api_key)) -> dict:
    return {"scenarios": list_scenarios()}


@router.post("/simulate/scenario")
async def simulate_scenario(
    payload: ScenarioRequest,
    key_record: dict = Depends(require_api_key),
) -> dict:
    try:
        records = get_scenario_records(payload.scenario)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "Unknown scenario"}) from exc

    outputs: list[dict] = []
    for raw in records:
        t0 = time.perf_counter()
        event = make_stream_event(
            raw,
            source="scenario",
            is_injected=True,
            scenario_id=payload.scenario,
        )
        latency_ms = (time.perf_counter() - t0) * 1000.0

        increment_usage(
            str(key_record["key_id"]),
            event["prediction"] == "malware",
            float(event["confidence"]),
        )
        write_audit_event(
            key_id=str(key_record["key_id"]),
            source="scenario",
            raw_record=raw,
            prediction=event["prediction"],
            confidence=float(event["confidence"]),
            latency_ms=latency_ms,
        )

        await push_event(event)
        outputs.append(event)

    return {
        "scenario": payload.scenario,
        "count": len(outputs),
        "results": outputs,
    }
