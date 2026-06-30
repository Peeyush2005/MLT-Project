"""
Health-check route: GET /api/health
"""

from fastapi import APIRouter

from app.models import HealthResponse

router = APIRouter()

# Artifact file names (informational — actual loading is in inference.py)
_ARTIFACT_FILES = {
    "model_file": "malware_detector_model.pkl",
    "encoders_file": "malware_detector_encoders.pkl",
    "features_file": "malware_detector_features.pkl",
    "cat_cols_file": "malware_detector_cat_cols.pkl",
}


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """
    Returns service health status.

    If the service is responding, artifacts are loaded (inference.py raises
    at import time if any PKL file is missing).
    """
    # Import here to avoid circular import; if inference loaded successfully
    # this import will not raise.
    from app import inference as _inf  # noqa: F401

    return HealthResponse(
        status="ok",
        artifacts_loaded=True,
        **_ARTIFACT_FILES,
    )
