"""
Model information routes:
  GET /api/model/info
  GET /api/model/feature-importance
"""

from fastapi import APIRouter

from app.inference import (
    get_categorical_vocabularies,
    get_feature_importances,
    get_model_hyperparameters,
    loaded_features,
    loaded_metrics,
)
from app.models import FeatureImportanceItem, FeatureImportanceResponse

router = APIRouter()


@router.get("/model/info", tags=["Model"])
def model_info() -> dict:
    """
    Returns model metadata, feature information, hyperparameters, and
    evaluation metrics.
    """
    return {
        "algorithm": "XGBoost",
        "task": "binary_classification",
        "features": list(loaded_features),
        "categorical_vocabularies": get_categorical_vocabularies(),
        "hyperparameters": get_model_hyperparameters(),
        "metrics": loaded_metrics,
        "training_info": {
            "train_test_split": "80/20 stratified",
            "class_balancing": "SMOTE",
            "hyperparameter_search": (
                "RandomizedSearchCV, 30 candidates, 5-fold StratifiedKFold"
            ),
        },
    }


@router.get(
    "/model/feature-importance",
    response_model=FeatureImportanceResponse,
    tags=["Model"],
)
def feature_importance() -> FeatureImportanceResponse:
    """
    Returns the top-20 feature importances from the trained XGBoost model,
    sorted by importance descending.
    """
    raw = get_feature_importances(top_n=20)
    return FeatureImportanceResponse(
        feature_importances=[
            FeatureImportanceItem(
                feature=item["feature"], importance=item["importance"]
            )
            for item in raw
        ]
    )
