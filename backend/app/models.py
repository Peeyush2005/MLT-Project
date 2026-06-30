"""
Pydantic v2 request/response models for the malware detection API.
"""

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class IOCRecord(BaseModel):
    ioc_type: str
    threat_type: str
    malware_family: str
    confidence_level: int = Field(ge=0, le=100)
    dst_port: int = Field(ge=0, le=65535)
    days_active: int = Field(ge=0, le=90)
    src_country: str
    tags: str
    reporter: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware_family": "emotet",
                "confidence_level": 75,
                "dst_port": 4444,
                "days_active": 15,
                "src_country": "RU",
                "tags": "c2",
                "reporter": "honeypot_net",
            }
        }
    }


class BatchRequest(BaseModel):
    records: List[IOCRecord] = Field(max_length=500)


class PredictionResult(BaseModel):
    prediction: str
    class_index: int
    confidence: float
    all_probabilities: Dict[str, float]
    model_version: str
    request_id: str
    latency_ms: float


class BatchSummary(BaseModel):
    total: int
    benign_count: int
    malware_count: int
    mean_confidence: float


class BatchPredictionResponse(BaseModel):
    results: List[PredictionResult]
    summary: BatchSummary


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class FeatureImportanceResponse(BaseModel):
    feature_importances: List[FeatureImportanceItem]


class HealthResponse(BaseModel):
    status: str
    artifacts_loaded: bool
    model_file: str
    encoders_file: str
    features_file: str
    cat_cols_file: str


class CSVResultRow(BaseModel):
    row_index: int
    input: Dict[str, Any]
    prediction: str
    confidence: float
    all_probabilities: Dict[str, float]


class CSVErrorRow(BaseModel):
    row_index: int
    error: str
    raw: Dict[str, Any]


class CSVPredictionResponse(BaseModel):
    results: List[CSVResultRow]
    errors: List[CSVErrorRow]
    summary: Dict[str, Any]
    csv_content: str  # base64-encoded CSV
