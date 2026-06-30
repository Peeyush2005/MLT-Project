"""SQLite setup and helpers for API key + usage tracking."""

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "app.db"
_lock = threading.Lock()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc() -> str:
    return _utc_now().strftime("%Y-%m-%d")


def _hour_bucket(dt: datetime | None = None) -> str:
    value = dt or _utc_now()
    return value.strftime("%Y-%m-%dT%H:00:00Z")


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id             TEXT PRIMARY KEY,
                key_hash           TEXT UNIQUE NOT NULL,
                label              TEXT NOT NULL,
                created_at         TEXT NOT NULL,
                requests_total     INTEGER NOT NULL DEFAULT 0,
                requests_today     INTEGER NOT NULL DEFAULT 0,
                last_used_at       TEXT,
                last_reset_date    TEXT,
                rate_limit_per_min INTEGER NOT NULL DEFAULT 60,
                is_active          INTEGER NOT NULL DEFAULT 1
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hourly_usage (
                key_id           TEXT NOT NULL,
                hour_bucket      TEXT NOT NULL,
                request_count    INTEGER NOT NULL DEFAULT 0,
                malware_count    INTEGER NOT NULL DEFAULT 0,
                total_confidence REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (key_id, hour_bucket)
            )
        """
        )
        conn.commit()
        conn.close()


def create_key(
    key_id: str,
    key_hash: str,
    label: str,
    created_at: str,
    rate_limit_per_min: int,
) -> None:
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            INSERT INTO api_keys (
                key_id,
                key_hash,
                label,
                created_at,
                rate_limit_per_min,
                last_reset_date
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (key_id, key_hash, label, created_at, rate_limit_per_min, _today_utc()),
        )
        conn.commit()
        conn.close()


def get_key_by_hash(key_hash: str) -> dict | None:
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?",
            (key_hash,),
        ).fetchone()
        conn.close()
    return dict(row) if row else None


def get_key_by_id(key_id: str) -> dict | None:
    with _lock:
        conn = _get_conn()
        row = conn.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
        conn.close()
    return dict(row) if row else None


def list_keys() -> list[dict]:
    with _lock:
        conn = _get_conn()
        rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
        conn.close()
    return [dict(r) for r in rows]


def revoke_key(key_id: str) -> bool:
    with _lock:
        conn = _get_conn()
        cur = conn.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ?", (key_id,))
        conn.commit()
        changed = cur.rowcount > 0
        conn.close()
    return changed


def increment_usage(key_id: str, is_malware: bool, confidence: float) -> None:
    now = _utc_now()
    today = now.strftime("%Y-%m-%d")
    hour_bucket = _hour_bucket(now)
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            UPDATE api_keys
            SET
                requests_total = requests_total + 1,
                requests_today = CASE
                    WHEN last_reset_date = ? THEN requests_today + 1
                    ELSE 1
                END,
                last_reset_date = ?,
                last_used_at = ?
            WHERE key_id = ?
            """,
            (today, today, now.isoformat(), key_id),
        )

        conn.execute(
            """
            INSERT INTO hourly_usage (
                key_id,
                hour_bucket,
                request_count,
                malware_count,
                total_confidence
            )
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(key_id, hour_bucket) DO UPDATE SET
                request_count = request_count + 1,
                malware_count = malware_count + excluded.malware_count,
                total_confidence = total_confidence + excluded.total_confidence
            """,
            (key_id, hour_bucket, 1 if is_malware else 0, float(confidence)),
        )
        conn.commit()
        conn.close()


def get_hourly_usage_last_24h(key_id: str) -> list[dict]:
    start = _utc_now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    buckets = [(start + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z") for i in range(24)]

    with _lock:
        conn = _get_conn()
        rows = conn.execute(
            """
            SELECT hour_bucket, request_count, malware_count, total_confidence
            FROM hourly_usage
            WHERE key_id = ?
              AND hour_bucket >= ?
            ORDER BY hour_bucket ASC
            """,
            (key_id, buckets[0]),
        ).fetchall()
        conn.close()

    by_bucket = {row["hour_bucket"]: dict(row) for row in rows}
    result: list[dict] = []
    for bucket in buckets:
        row = by_bucket.get(bucket)
        req_count = int(row["request_count"]) if row else 0
        mal_count = int(row["malware_count"]) if row else 0
        total_conf = float(row["total_confidence"]) if row else 0.0
        avg_conf = (total_conf / req_count) if req_count > 0 else 0.0
        result.append(
            {
                "hour": bucket,
                "request_count": req_count,
                "malware_count": mal_count,
                "avg_confidence": round(avg_conf, 6),
            }
        )
    return result
