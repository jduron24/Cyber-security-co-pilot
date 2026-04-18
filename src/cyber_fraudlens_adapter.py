from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import yaml
from sklearn.metrics.pairwise import linear_kernel
from sklearn.feature_extraction.text import TfidfVectorizer

from .weak_label import apply_weak_labels, load_label_rules


def load_model_payload(path: str | Path) -> dict[str, Any]:
    return joblib.load(Path(path))


def load_kb(project_root: Path) -> tuple[pd.DataFrame, TfidfVectorizer | None, Any]:
    features_csv = project_root / ".doc" / "cyber_knowledge_base_features.csv"
    patterns_md = project_root / ".doc" / "cyber_knowledge_base_patterns.md"

    kb_csv = pd.read_csv(features_csv)
    kb_csv["title"] = kb_csv.get("tags", "feature_definition").astype(str)
    kb_csv["source"] = features_csv.name
    kb_csv["kb_type"] = "feature"
    kb_csv = kb_csv[["title", "text", "source", "kb_type"]].copy()

    kb_md = load_patterns_md(patterns_md)
    kb = pd.concat([kb_csv, kb_md], ignore_index=True)
    kb["text"] = kb["text"].fillna("").astype(str)
    kb["title"] = kb["title"].fillna("").astype(str)
    kb["__fulltext"] = (kb["title"] + " " + kb["text"]).str.lower()
    vectorizer = TfidfVectorizer(max_features=20000, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(kb["__fulltext"])
    return kb, vectorizer, matrix


def load_patterns_md(path: Path) -> pd.DataFrame:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    rows = []
    for match in re.finditer(r"^##\s+(.+?)\n(.*?)(?=^##\s+|\Z)", raw, flags=re.S | re.M):
        rows.append(
            {
                "title": match.group(1).strip(),
                "text": match.group(2).strip(),
                "source": f"{path.name}::{match.group(1).strip()}",
                "kb_type": "pattern",
            }
        )
    return pd.DataFrame(rows, columns=["title", "text", "source", "kb_type"])


def kb_search(query: str, kb_df: pd.DataFrame, vectorizer: TfidfVectorizer, matrix: Any, k: int = 5) -> list[dict[str, Any]]:
    normalized = re.sub(r"[^\w\s]+", " ", (query or "").lower()).strip()
    if not normalized:
        return []
    qv = vectorizer.transform([normalized])
    sims = linear_kernel(qv, matrix).ravel()
    idx = sims.argsort()[::-1][:k]
    hits = []
    for i in idx:
        row = kb_df.iloc[i]
        hits.append(
            {
                "title": str(row["title"]),
                "text": str(row["text"]),
                "source": str(row["source"]),
                "kb_type": str(row["kb_type"]),
                "score": round(float(sims[i]), 6),
            }
        )
    return hits


def score_incidents(
    incidents: pd.DataFrame,
    model_payload: dict[str, Any],
    label_rules: dict[str, Any],
) -> pd.DataFrame:
    labeled, _ = apply_weak_labels(incidents, label_rules)
    feature_columns = model_payload["feature_columns"]
    model = model_payload["model"]
    labeled["ml_suspicion_proba"] = model.predict_proba(labeled[feature_columns])[:, 1]
    labeled["ml_suspicion_pred"] = (labeled["ml_suspicion_proba"] >= 0.5).astype(int)
    return labeled


def explain_incident(
    incident_row: pd.DataFrame,
    model_payload: dict[str, Any],
    label_rules: dict[str, Any],
    kb_df: pd.DataFrame,
    vectorizer: TfidfVectorizer,
    matrix: Any,
    top_k: int = 8,
) -> dict[str, Any]:
    scored = score_incidents(incident_row, model_payload, label_rules)
    row = scored.iloc[[0]]
    model = model_payload["model"]
    preprocessor = model.named_steps["preprocessor"]
    classifier = model.named_steps["classifier"]

    transformed = preprocessor.transform(row[model_payload["feature_columns"]])
    values = transformed.toarray()[0] if hasattr(transformed, "toarray") else transformed[0]
    feature_names = list(preprocessor.get_feature_names_out())
    contributions = values * classifier.coef_[0]

    contribution_rows = []
    for feature_name, value, contribution in zip(feature_names, values, contributions):
        if value == 0:
            continue
        original_feature, feature_detail = parse_feature_name(feature_name, model_payload["feature_columns"])
        contribution_rows.append(
            {
                "feature": feature_name,
                "display_feature": feature_detail,
                "original_feature": original_feature,
                "raw_value": jsonable(row.iloc[0].get(original_feature)),
                "transformed_value": jsonable(value),
                "contribution": round(float(contribution), 6),
            }
        )
    contribution_rows.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    top_contributors = contribution_rows[:top_k]

    feature_queries = [item["display_feature"] for item in top_contributors]
    feature_hits = []
    for query in feature_queries[:4]:
        feature_hits.extend(kb_search(query, kb_df, vectorizer, matrix, k=1))

    pattern_query = build_pattern_query(row.iloc[0])
    pattern_hits = kb_search(pattern_query, kb_df, vectorizer, matrix, k=4)

    return {
        "incident_id": str(row.iloc[0]["incident_id"]),
        "ml_suspicion_proba": round(float(row.iloc[0]["ml_suspicion_proba"]), 6),
        "ml_suspicion_pred": int(row.iloc[0]["ml_suspicion_pred"]),
        "weak_label_score": round(float(row.iloc[0]["weak_label_score"]), 6),
        "weak_label_suspicious": int(row.iloc[0]["weak_label_suspicious"]),
        "weak_label_reasons": json.loads(row.iloc[0]["weak_label_reasons_json"]),
        "top_contributors": top_contributors,
        "feature_kb_hits": dedupe_hits(feature_hits),
        "pattern_kb_hits": dedupe_hits(pattern_hits),
        "ordered_event_name_sequence": row.iloc[0].get("ordered_event_name_sequence"),
        "ordered_event_source_sequence": row.iloc[0].get("ordered_event_source_sequence"),
    }


def parse_feature_name(feature_name: str, base_columns: list[str]) -> tuple[str, str]:
    if feature_name.startswith("num__") or feature_name.startswith("bool__"):
        base = feature_name.split("__", 1)[1]
        return base, base
    if feature_name.startswith("cat__"):
        base = feature_name.split("__", 1)[1]
        for candidate in sorted(base_columns, key=len, reverse=True):
            prefix = f"{candidate}_"
            if base == candidate:
                return candidate, candidate
            if base.startswith(prefix):
                return candidate, f"{candidate} = {base[len(prefix):]}"
        return base, base
    return feature_name, feature_name


def build_pattern_query(row: pd.Series) -> str:
    parts = [
        str(row.get("top_event_name", "")),
        str(row.get("first_event_name", "")),
        str(row.get("last_event_name", "")),
    ]
    flag_map = {
        "contains_recon_like_api": "reconnaissance burst",
        "contains_privilege_change_api": "privilege escalation attempt",
        "contains_resource_creation_api": "resource creation activity",
        "contains_console_login": "console login followed by sensitive actions",
        "has_high_failure_ratio": "failure dominated probing",
        "has_sts_sequence": "sts heavy session churn",
        "has_ec2_sequence": "high velocity ec2 activity",
        "actor_is_root": "root driven sensitive activity",
    }
    for column, phrase in flag_map.items():
        if bool(row.get(column, False)):
            parts.append(phrase)
    return " ".join(part for part in parts if part)


def dedupe_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for hit in hits:
        key = (hit["title"], hit["source"])
        if key in seen:
            continue
        seen.add(key)
        output.append(hit)
    return output


def load_incidents(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    return pd.read_parquet(path)


def jsonable(value: Any) -> Any:
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="FraudLens-style adapter for CloudTrail incident suspicion scoring.")
    parser.add_argument("--project-root", default=".", help="Project root containing artifacts, reports, and .doc KB files.")
    parser.add_argument("--input", default="data/processed/incidents.parquet", help="Incident parquet/csv path relative to project root.")
    parser.add_argument("--artifact", default="artifacts/incident_suspicion_model.joblib", help="Model artifact path relative to project root.")
    parser.add_argument("--label-rules", default="configs/incident_label_rules.yaml", help="Weak label rule config relative to project root.")
    parser.add_argument("--incident-id", help="Single incident_id to explain.")
    parser.add_argument("--output", help="Optional scored output path relative to project root.")
    parser.add_argument("--top-k", type=int, default=8, help="Top contributor count for single-incident explanation.")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    incidents = load_incidents(project_root / args.input)
    model_payload = load_model_payload(project_root / args.artifact)
    label_rules = load_label_rules(project_root / args.label_rules)
    kb_df, vectorizer, matrix = load_kb(project_root)

    if args.incident_id:
        match = incidents.loc[incidents["incident_id"] == args.incident_id]
        if match.empty:
            raise SystemExit(f"Incident not found: {args.incident_id}")
        explanation = explain_incident(match.iloc[[0]], model_payload, label_rules, kb_df, vectorizer, matrix, top_k=args.top_k)
        print(json.dumps(explanation, indent=2))
        return 0

    scored = score_incidents(incidents, model_payload, label_rules)
    if args.output:
        output_path = project_root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.suffix.lower() == ".csv":
            scored.to_csv(output_path, index=False)
        else:
            scored.to_parquet(output_path, index=False)
    print(json.dumps({"rows": int(len(scored)), "avg_proba": round(float(scored["ml_suspicion_proba"].mean()), 6)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
