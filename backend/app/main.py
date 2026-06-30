"""
FastAPI application entry point for the Malware Detection API.

Startup order:
  1. inference.py is imported → PKL artifacts loaded (fail-fast if missing)
  2. Routers mounted under /api prefix
  3. CORS configured for localhost:3000 and localhost:5173
"""

import logging
import sys
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Trigger artifact loading early so startup errors are obvious
import app.inference as _inference  # noqa: F401
from app.db import init_db
from app.routes import health, keys, model_info, predict, streaming
from app.stream import stream_generator_task

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("malware_api")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(application: FastAPI):
    _backend_dir = Path(__file__).parent.parent
    init_db()
    stream_task = asyncio.create_task(stream_generator_task())
    logger.info("=" * 60)
    logger.info("Malware Detection API  v1.0.0  starting up")
    logger.info(f"  Backend directory : {_backend_dir}")
    logger.info(f"  Artifacts dir     : {_inference._ARTIFACTS_DIR}")
    logger.info(f"  Model loaded      : {_inference._MODEL_PATH.name}")
    logger.info(f"  Features          : {list(_inference.loaded_features)}")
    logger.info(f"  Cat columns       : {list(_inference.loaded_cat_cols)}")
    logger.info(f"  Metrics loaded    : {bool(_inference.loaded_metrics)}")
    logger.info(f"  Prediction log    : {_backend_dir / 'predictions.jsonl'}")
    logger.info("=" * 60)
    yield
    stream_task.cancel()
    try:
        await stream_task
    except asyncio.CancelledError:
        pass
    logger.info("Malware Detection API shutting down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Malware Detection API",
    description=(
        "Binary classification API (benign / malware) powered by an XGBoost model "
        "trained on network IOC records."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(predict.router, prefix="/api")
app.include_router(model_info.router, prefix="/api")
app.include_router(health.router, prefix="/api")
app.include_router(keys.router, prefix="/api")
app.include_router(streaming.router, prefix="/api")

# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "message": "Malware Detection API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
    }
