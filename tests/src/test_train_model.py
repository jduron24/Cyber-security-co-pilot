from pathlib import Path

import pandas as pd

from src import train_model


def _labeled_frame() -> pd.DataFrame:
    rows = []
    for index in range(8):
        suspicious = index < 4
        rows.append(
            {
                "incident_duration_seconds": 120 + index,
                "event_count": 10 + index,
                "distinct_event_names": 4,
                "distinct_event_sources": 2,
                "distinct_regions": 1,
                "error_event_count": 3 if suspicious else 0,
                "success_event_count": 1 if suspicious else 4,
                "failure_ratio": 0.75 if suspicious else 0.0,
                "events_per_minute": 2.5 + index,
                "contains_console_login": suspicious,
                "contains_recon_like_api": suspicious,
                "contains_privilege_change_api": suspicious,
                "contains_resource_creation_api": False,
                "actor_is_root": suspicious,
                "actor_is_assumed_role": False,
                "has_high_failure_ratio": suspicious,
                "has_failure_burst": suspicious,
                "has_event_burst": suspicious,
                "has_broad_surface_area": suspicious,
                "has_iam_sequence": suspicious,
                "has_sts_sequence": False,
                "has_ec2_sequence": False,
                "has_recon_plus_privilege": suspicious,
                "has_recon_plus_resource_creation": False,
                "has_privilege_plus_resource_creation": False,
                "has_root_plus_privilege": suspicious,
                "actor_key": f"actor-{index}",
                "primary_source_ip_address": f"203.0.113.{index}",
                "first_event_name": "ConsoleLogin" if suspicious else "ListBuckets",
                "last_event_name": "AttachUserPolicy" if suspicious else "GetCallerIdentity",
                "top_event_name": "AttachUserPolicy" if suspicious else "ListBuckets",
                "weak_label_suspicious": int(suspicious),
            }
        )
    return pd.DataFrame(rows)


def test_train_incident_model_falls_back_to_logistic_when_ebm_unavailable(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        train_model,
        "train_ebm_incident_model",
        lambda labeled, artifact_path: (_ for _ in ()).throw(train_model.EBMUnavailableError("missing interpret")),
    )
    labeled = _labeled_frame()

    report, scored = train_model.train_incident_model(labeled, tmp_path / "model.joblib")

    assert report["model_type"] == "logistic"
    assert set(scored["model_type"]) == {"logistic"}


def test_train_incident_model_uses_explicit_logistic_backend(tmp_path: Path):
    labeled = _labeled_frame()

    report, scored = train_model.train_incident_model(
        labeled,
        tmp_path / "model.joblib",
        preferred_model_type="logistic",
    )

    assert report["model_type"] == "logistic"
    assert set(scored["model_type"]) == {"logistic"}
