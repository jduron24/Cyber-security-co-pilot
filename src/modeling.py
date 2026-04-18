from __future__ import annotations

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

NUMERIC_FEATURES = [
    "incident_duration_seconds",
    "event_count",
    "distinct_event_names",
    "distinct_event_sources",
    "distinct_regions",
    "error_event_count",
    "success_event_count",
    "failure_ratio",
    "events_per_minute",
]

BOOLEAN_FEATURES = [
    "contains_console_login",
    "contains_recon_like_api",
    "contains_privilege_change_api",
    "contains_resource_creation_api",
    "actor_is_root",
    "actor_is_assumed_role",
    "has_high_failure_ratio",
    "has_failure_burst",
    "has_event_burst",
    "has_broad_surface_area",
    "has_iam_sequence",
    "has_sts_sequence",
    "has_ec2_sequence",
    "has_recon_plus_privilege",
    "has_recon_plus_resource_creation",
    "has_privilege_plus_resource_creation",
    "has_root_plus_privilege",
]

CATEGORICAL_FEATURES = [
    "actor_key",
    "primary_source_ip_address",
    "first_event_name",
    "last_event_name",
    "top_event_name",
]

ALL_FEATURES = NUMERIC_FEATURES + BOOLEAN_FEATURES + CATEGORICAL_FEATURES


def boolean_to_float(values):
    return values.astype(float)


def build_incident_preprocessor() -> ColumnTransformer:
    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
            ("scaler", StandardScaler()),
        ]
    )
    boolean_transformer = Pipeline(
        steps=[
            (
                "cast",
                FunctionTransformer(
                    boolean_to_float,
                    feature_names_out="one-to-one",
                ),
            ),
            ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
        ]
    )
    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=10)),
        ]
    )
    return ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, NUMERIC_FEATURES),
            ("bool", boolean_transformer, BOOLEAN_FEATURES),
            ("cat", categorical_transformer, CATEGORICAL_FEATURES),
        ]
    )
