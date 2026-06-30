"""Prediction routes secured by API keys."""

import base64
import csv
import io
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile

from app.audit import write_audit_event
from app.db import increment_usage
from app.inference import predict_batch, predict_malware
from app.models import (
    BatchPredictionResponse,
    BatchRequest,
    BatchSummary,
    CSVErrorRow,
    CSVPredictionResponse,
    CSVResultRow,
    IOCRecord,
    PredictionResult,
)
from app.stream import make_stream_event, push_event
from app.auth import require_api_key

router = APIRouter(tags=["Prediction"])
MODEL_VERSION = "2.0.0"

_REQUIRED_COLUMNS = {
    "ioc_type",
    "threat_type",
    "malware_family",
    "confidence_level",
    "dst_port",
    "days_active",
    "src_country",
    "tags",
    "reporter",
}
_INT_COLUMNS = {"confidence_level", "dst_port", "days_active"}


def _coerce_row(raw: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for col, val in raw.items():
        if col in _INT_COLUMNS:
            try:
                result[col] = int(val)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Column '{col}' must be an integer, got {val!r}") from exc
        else:
            result[col] = val
    return result


def _prediction_payload(raw: dict, result: dict, latency_ms: float) -> PredictionResult:
    return PredictionResult(
        prediction=result["prediction"],
        class_index=result["class_index"],
        confidence=float(result["confidence"]),
        all_probabilities=result["all_probabilities"],
        model_version=MODEL_VERSION,
        request_id=uuid.uuid4().hex,
        latency_ms=round(latency_ms, 3),
    )


@router.post("/predict", response_model=PredictionResult)
async def predict_single(
    record: IOCRecord,
    key_record: dict = Depends(require_api_key),
) -> PredictionResult:
    raw = record.model_dump()

    t0 = time.perf_counter()
    result = predict_malware(raw)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    increment_usage(
        str(key_record["key_id"]),
        result["prediction"] == "malware",
        float(result["confidence"]),
    )

    write_audit_event(
        key_id=str(key_record["key_id"]),
        source="manual",
        raw_record=raw,
        prediction=result["prediction"],
        confidence=float(result["confidence"]),
        latency_ms=latency_ms,
    )

    stream_event = make_stream_event(raw, source="manual", is_injected=False)
    await push_event(stream_event)

    return _prediction_payload(raw, result, latency_ms)


@router.post("/predict/batch", response_model=BatchPredictionResponse)
def predict_batch_route(
    payload: BatchRequest,
    key_record: dict = Depends(require_api_key),
) -> BatchPredictionResponse:
    records = [r.model_dump() for r in payload.records]
    t0 = time.perf_counter()
    raw_results = predict_batch(records)
    total_latency_ms = (time.perf_counter() - t0) * 1000.0

    results: list[PredictionResult] = []
    benign_count = 0
    malware_count = 0
    conf_sum = 0.0

    avg_latency = total_latency_ms / max(1, len(raw_results))

    for raw_record, result in zip(records, raw_results):
        if result["prediction"] == "malware":
            malware_count += 1
        else:
            benign_count += 1
        conf_sum += float(result["confidence"])

        increment_usage(
            str(key_record["key_id"]),
            result["prediction"] == "malware",
            float(result["confidence"]),
        )
        write_audit_event(
            key_id=str(key_record["key_id"]),
            source="batch",
            raw_record=raw_record,
            prediction=result["prediction"],
            confidence=float(result["confidence"]),
            latency_ms=avg_latency,
        )
        results.append(_prediction_payload(raw_record, result, avg_latency))

    total = len(results)
    summary = BatchSummary(
        total=total,
        benign_count=benign_count,
        malware_count=malware_count,
        mean_confidence=round(conf_sum / max(1, total), 4),
    )
    return BatchPredictionResponse(results=results, summary=summary)


@router.post("/predict/csv", response_model=CSVPredictionResponse)
async def predict_csv(
    file: UploadFile,
    key_record: dict = Depends(require_api_key),
) -> CSVPredictionResponse:
    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV file must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV file is empty")

    fieldnames = [f.strip() for f in reader.fieldnames]
    missing_cols = _REQUIRED_COLUMNS - set(fieldnames)
    if missing_cols:
        raise HTTPException(
            status_code=422,
            detail=f"CSV missing required columns: {sorted(missing_cols)}",
        )

    rows: list[dict[str, str]] = []
    for row in reader:
        rows.append({k.strip(): (v.strip() if v else "") for k, v in row.items()})

    good_records: list[tuple[int, dict[str, Any]]] = []
    errors: list[CSVErrorRow] = []

    for i, row in enumerate(rows):
        try:
            coerce_target = {col: row.get(col, "") for col in _REQUIRED_COLUMNS}
            good_records.append((i, _coerce_row(coerce_target)))
        except ValueError as exc:
            errors.append(CSVErrorRow(row_index=i, error=str(exc), raw=dict(row)))

    results: list[CSVResultRow] = []
    if good_records:
        indices, records = zip(*good_records)
        t0 = time.perf_counter()
        raw_results = predict_batch(list(records))
        latency_per_row = ((time.perf_counter() - t0) * 1000.0) / max(1, len(raw_results))

        for idx, raw_record, result in zip(indices, records, raw_results):
            increment_usage(
                str(key_record["key_id"]),
                result["prediction"] == "malware",
                float(result["confidence"]),
            )
            write_audit_event(
                key_id=str(key_record["key_id"]),
                source="csv",
                raw_record=raw_record,
                prediction=result["prediction"],
                confidence=float(result["confidence"]),
                latency_ms=latency_per_row,
            )
            results.append(
                CSVResultRow(
                    row_index=idx,
                    input=raw_record,
                    prediction=result["prediction"],
                    confidence=float(result["confidence"]),
                    all_probabilities=result["all_probabilities"],
                )
            )

    out_fieldnames = fieldnames + ["prediction", "confidence", "error"]
    out_buffer = io.StringIO()
    writer = csv.DictWriter(out_buffer, fieldnames=out_fieldnames, extrasaction="ignore")
    writer.writeheader()

    result_by_idx = {r.row_index: r for r in results}
    error_by_idx = {e.row_index: e for e in errors}

    for i, row in enumerate(rows):
        out_row = dict(row)
        if i in result_by_idx:
            r = result_by_idx[i]
            out_row["prediction"] = r.prediction
            out_row["confidence"] = round(r.confidence, 6)
            out_row["error"] = ""
        elif i in error_by_idx:
            out_row["prediction"] = "error"
            out_row["confidence"] = ""
            out_row["error"] = error_by_idx[i].error
        writer.writerow(out_row)

    csv_bytes = out_buffer.getvalue().encode("utf-8")
    csv_b64 = base64.b64encode(csv_bytes).decode("ascii")

    benign_count = sum(1 for r in results if r.prediction == "benign")
    malware_count = sum(1 for r in results if r.prediction == "malware")
    mean_conf = (sum(r.confidence for r in results) / max(1, len(results))) if results else 0.0

    summary = {
        "total_rows": len(rows),
        "processed": len(results),
        "error_count": len(errors),
        "benign_count": benign_count,
        "malware_count": malware_count,
        "mean_confidence": round(mean_conf, 6),
    }

    return CSVPredictionResponse(
        results=results,
        errors=errors,
        summary=summary,
        csv_content=csv_b64,
    )
