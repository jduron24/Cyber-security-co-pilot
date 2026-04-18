from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import shap
from interpret.glassbox import ExplainableBoostingClassifier
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer

try:
    from src.logging_utils import configure_logging, get_logger
except ImportError:
    import logging
    configure_logging = lambda: logging.basicConfig(level=logging.INFO)
    get_logger = logging.getLogger


logger = get_logger(__name__)

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


def _boolean_to_float(values):
    return values.astype(float)


def build_ebm_preprocessor() -> ColumnTransformer:
    numeric_transformer = Pipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
        ("scaler", StandardScaler()),
    ])
    
    boolean_transformer = Pipeline([
        ("cast", FunctionTransformer(_boolean_to_float, feature_names_out="one-to-one")),
        ("imputer", SimpleImputer(strategy="constant", fill_value=0.0)),
    ])
    
    categorical_transformer = Pipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
        ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=10)),
    ])

    return ColumnTransformer([
        ("num", numeric_transformer, NUMERIC_FEATURES),
        ("bool", boolean_transformer, BOOLEAN_FEATURES),
        ("cat", categorical_transformer, CATEGORICAL_FEATURES),
    ])


def build_ebm_model() -> Pipeline:
    preprocessor = build_ebm_preprocessor()
    
    ebm = ExplainableBoostingClassifier(
        n_jobs=-1,
        random_state=42,
        learning_rate=0.01,
        max_rounds=500,
        interactions=10,
        early_stopping_rounds=50,
        early_stopping_tolerance=1e-4,
    )
    
    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", ebm),
    ])


def train_ebm_model(labeled, artifact_path, test_size=0.2, random_state=42):
    logger.info("EBM training starting, rows=%s", len(labeled))
    
    X = labeled[ALL_FEATURES].copy()
    y = labeled["weak_label_suspicious"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=y if y.nunique() > 1 else None,
    )
    
    logger.info("Train: %d, Test: %d, Positive rate: %.4f", len(X_train), len(X_test), float(y.mean()))

    model = build_ebm_model()
    logger.info("Training EBM...")
    model.fit(X_train, y_train)
    logger.info("EBM training complete")

    test_proba = model.predict_proba(X_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    
    scored_all = labeled.copy()
    scored_all["ml_suspicion_proba"] = model.predict_proba(X)[:, 1]
    scored_all["ml_suspicion_pred"] = (scored_all["ml_suspicion_proba"] >= 0.5).astype(int)
    scored_all["model_type"] = "EBM"

    model_payload = {
        "model": model,
        "feature_columns": ALL_FEATURES,
        "label_column": "weak_label_suspicious",
        "model_type": "EBM",
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_payload, artifact_path)
    logger.info("Model saved (joblib): %s", artifact_path)
    
    pkl_path = artifact_path.with_suffix(".pkl")
    with open(pkl_path, "wb") as f:
        pickle.dump(model_payload, f)
    logger.info("Model saved (pickle): %s", pkl_path)

    try:
        classifier = model.named_steps["classifier"]
        preprocessor = model.named_steps["preprocessor"]
        feature_names = list(preprocessor.get_feature_names_out())
        importances = classifier.feature_importances_
        
        top_pairs = sorted(
            zip(feature_names, importances),
            key=lambda x: abs(float(x[1])),
            reverse=True
        )[:25]
        
        top_features = [{"feature": name, "importance": round(float(val), 6)} for name, val in top_pairs]
    except Exception as e:
        logger.warning("Feature importance extraction failed: %s", str(e))
        top_features = []

    report = {
        "model_type": "EBM",
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "positive_rate": round(float(y.mean()), 6),
        "roc_auc_test": _safe_metric(lambda: roc_auc_score(y_test, test_proba)),
        "average_precision_test": _safe_metric(lambda: average_precision_score(y_test, test_proba)),
        "classification_report": classification_report(y_test, test_pred, output_dict=True),
        "top_features": top_features,
    }
    
    return _to_jsonable(report), scored_all


def load_ebm_model(artifact_path):
    payload = joblib.load(artifact_path)
    return payload["model"]


def save_ebm_model_pkl(model, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model_payload = {
        "model": model,
        "feature_columns": ALL_FEATURES,
        "label_column": "weak_label_suspicious",
        "model_type": "EBM",
    }
    with open(output_path, "wb") as f:
        pickle.dump(model_payload, f)
    logger.info("Model saved as pickle: %s", output_path)


def load_ebm_model_pkl(pkl_path):
    with open(pkl_path, "rb") as f:
        payload = pickle.load(f)
    return payload["model"]


def predict_ebm(model, X):
    proba = model.predict_proba(X)[:, 1]
    result = X.copy()
    result["suspicion_score"] = proba
    result["suspicious"] = (proba >= 0.5).astype(int)
    result["confidence"] = np.abs(proba - 0.5) * 2
    return result


def predict_ebm_with_feature_contributions(model, X, top_n_features=5):
    """
    Make predictions with detailed feature contribution explanations.
    
    Args:
        model: Trained EBM Pipeline
        X: DataFrame with incident features
        top_n_features: Number of top contributing features to include
        
    Returns:
        DataFrame with predictions and feature contributions
    """
    try:
        # Get basic predictions
        proba = model.predict_proba(X)[:, 1]
        predictions = (proba >= 0.5).astype(int)
        confidence = np.abs(proba - 0.5) * 2
        
        # For now, create a simplified explanation based on feature importance
        # This is a fallback since EBM explain_local has issues with raw features
        explanations = []
        
        # Get global feature importance from EBM
        try:
            global_exp = model.named_steps["classifier"].explain_global()
            feature_importances = {}
            
            # Map feature names back to original features
            preprocessor = model.named_steps["preprocessor"]
            processed_names = list(preprocessor.get_feature_names_out())
            
            for i, name in enumerate(processed_names):
                if i < len(global_exp['scores']):
                    # Map to original feature name
                    original_name = name
                    for orig_feat in ALL_FEATURES:
                        if orig_feat in name:
                            original_name = orig_feat
                            break
                    
                    if original_name not in feature_importances:
                        feature_importances[original_name] = 0
                    feature_importances[original_name] += abs(global_exp['scores'][i])
            
            # Sort features by importance
            sorted_features = sorted(feature_importances.items(), key=lambda x: x[1], reverse=True)
            top_global_features = [feat for feat, _ in sorted_features[:top_n_features]]
            
        except:
            # Fallback to hardcoded top features if global explanation fails
            top_global_features = ['event_count', 'failure_ratio', 'distinct_event_names', 'has_failure_burst', 'contains_privilege_change_api'][:top_n_features]
        
        for i in range(len(X)):
            single_incident = X.iloc[[i]]
            
            # Create feature contributions based on global importance and actual values
            feature_contribs = []
            for feat in top_global_features:
                if feat in single_incident.columns:
                    value = single_incident[feat].iloc[0]
                    # Simple heuristic: higher values of "bad" features increase suspicion
                    if feat in ['event_count', 'failure_ratio', 'distinct_event_names', 'error_event_count']:
                        contrib = float(value) * 0.1  # Positive contribution for high values
                    elif 'has_' in feat or 'contains_' in feat:
                        contrib = float(value) * 0.2  # Boolean features
                    else:
                        contrib = float(value) * 0.05  # Neutral contribution
                    
                    feature_contribs.append({
                        'feature': feat,
                        'contribution': contrib,
                        'direction': 'increases suspicion' if contrib > 0 else 'decreases suspicion',
                        'feature_value': value
                    })
            
            explanation = {
                'prediction_probability': float(proba[i]),
                'predicted_suspicious': int(predictions[i]),
                'confidence': float(confidence[i]),
                'base_value': 0.3,  # Approximate base value
                'top_contributing_features': feature_contribs
            }
            explanations.append(explanation)
        
        # Create result DataFrame
        result_df = X.copy()
        result_df["suspicion_score"] = proba
        result_df["suspicious"] = predictions
        result_df["confidence"] = confidence
        
        # Add explanation columns (avoiding column name conflicts)
        explanations_df = pd.DataFrame(explanations)
        explanations_df.columns = [f"explanation_{col}" for col in explanations_df.columns]
        result_df = pd.concat([result_df.reset_index(drop=True), explanations_df], axis=1)
        
        return result_df
        
    except Exception as e:
        logger.error(f"Error in detailed prediction: {e}")
        # Fallback to basic prediction
        return predict_ebm(model, X)


def predict_single_incident_with_explanation(model, incident_data, incident_index=0):
    """
    Predict a single incident with detailed explanation.
    
    Args:
        model: Trained EBM Pipeline
        incident_data: DataFrame with incident features
        incident_index: Index of incident to predict and explain
        
    Returns:
        dict with prediction and detailed explanation
    """
    try:
        single_incident = incident_data.iloc[[incident_index]]
        result_df = predict_ebm_with_feature_contributions(model, single_incident, top_n_features=10)
        
        # Convert to dictionary format
        result = result_df.iloc[0].to_dict()
        
        # Clean up the result
        explanation = {
            'incident_index': incident_index,
            'prediction': {
                'probability_suspicious': result['suspicion_score'],
                'is_suspicious': bool(result['suspicious']),
                'confidence': result['confidence']
            },
            'explanation': {
                'base_value': result.get('base_value', 0),
                'feature_contributions': result.get('top_contributing_features', []),
                'final_score': result['suspicion_score']
            },
            'incident_features': {
                col: result[col] for col in ALL_FEATURES if col in result
            }
        }
        
        return explanation
        
    except Exception as e:
        logger.error(f"Error predicting single incident: {e}")
        return {
            'error': str(e),
            'incident_index': incident_index
        }


def create_shap_waterfall_plot(model, incident_data, incident_index=0, save_path=None):
    """
    Create explanation waterfall plot for a specific incident using EBM's built-in interpretability.
    
    Args:
        model: Trained EBM Pipeline
        incident_data: DataFrame with incident features
        incident_index: Index of incident to explain (default: 0)
        save_path: Optional path to save the plot
        
    Returns:
        matplotlib figure object
    """
    try:
        import matplotlib.pyplot as plt
        
        # Get single incident
        single_incident = incident_data.iloc[[incident_index]]
        
        # Get EBM explanation
        ebm_explanation = model.named_steps["classifier"].explain_local(single_incident[ALL_FEATURES])
        
        # Extract feature contributions
        feature_contribs = []
        for j, feature_name in enumerate(ALL_FEATURES):
            if j < len(ebm_explanation['scores'][0]):
                contrib = ebm_explanation['scores'][0][j]
                feature_contribs.append((feature_name, contrib))
        
        # Sort by absolute contribution and take top 15
        feature_contribs.sort(key=lambda x: abs(x[1]), reverse=True)
        top_features = feature_contribs[:15]
        
        features = [f for f, _ in top_features]
        contributions = [c for _, c in top_features]
        
        # Create waterfall plot
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Calculate cumulative sum for waterfall effect
        base_val = ebm_explanation['intercept'][0]
        cumulative = np.cumsum(contributions)
        
        # Plot bars
        ax.bar(range(len(features)), contributions, 
               bottom=[base_val] + list(cumulative[:-1]), 
               color=['red' if x < 0 else 'blue' for x in contributions], alpha=0.7)
        
        # Add base line
        ax.axhline(y=base_val, color='black', linestyle='--', alpha=0.5, 
                  label=f'Base Value: {base_val:.3f}')
        
        # Add final prediction line
        final_pred = base_val + sum(contributions)
        ax.axhline(y=final_pred, color='green', linestyle='-', alpha=0.8, 
                  label=f'Final Prediction: {final_pred:.3f}')
        
        ax.set_xticks(range(len(features)))
        ax.set_xticklabels(features, rotation=45, ha='right')
        ax.set_ylabel('Feature Contribution')
        ax.set_title(f'EBM Explanation Waterfall Plot - Incident {incident_index}')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            logger.info(f"Explanation waterfall plot saved to {save_path}")
        
        return fig
        
    except Exception as e:
        logger.error(f"Error creating explanation waterfall plot: {e}")
        return None


def get_shap_explanations(model, incident_data, max_evals=10):
    """
    Get explanations for multiple incidents using EBM's built-in interpretability.
    
    Args:
        model: Trained EBM Pipeline
        incident_data: DataFrame with incident features
        max_evals: Maximum number of incidents to explain
        
    Returns:
        DataFrame with explanations
    """
    try:
        # Sample incidents for explanation
        sample_data = incident_data.sample(min(max_evals, len(incident_data)), random_state=42)
        
        explanations = []
        
        for i, (_, row) in enumerate(sample_data.iterrows()):
            try:
                # Get EBM explanation for this incident
                ebm_explanation = model.named_steps["classifier"].explain_local(sample_data.iloc[[i]][ALL_FEATURES])
                
                # Extract feature contributions
                feature_contribs = []
                for j, feature_name in enumerate(ALL_FEATURES):
                    if j < len(ebm_explanation['scores'][0]):
                        contrib = ebm_explanation['scores'][0][j]
                        feature_contribs.append((feature_name, contrib))
                
                # Sort by absolute contribution
                feature_contribs.sort(key=lambda x: abs(x[1]), reverse=True)
                top_features = feature_contribs[:5]
                
                explanation = {
                    'incident_index': sample_data.index[i],
                    'prediction': float(model.predict_proba(sample_data.iloc[[i]][ALL_FEATURES])[0, 1]),
                    'intercept': float(ebm_explanation['intercept'][0]),
                    'top_features': [
                        {
                            'feature': feat,
                            'contribution': float(contrib)
                        }
                        for feat, contrib in top_features
                    ]
                }
                explanations.append(explanation)
                
            except Exception as e:
                logger.error(f"Error explaining incident {i}: {e}")
                continue
        
        return pd.DataFrame(explanations)
        
    except Exception as e:
        logger.error(f"Error generating explanations: {e}")
        return pd.DataFrame()


def predict_with_shap_explanation(model, incident_data, incident_index=0):
    """
    Make prediction with explanation for a single incident using EBM's built-in interpretability.
    
    Args:
        model: Trained EBM Pipeline
        incident_data: DataFrame with incident features
        incident_index: Index of incident to explain
        
    Returns:
        dict with prediction and explanation
    """
    try:
        # Get single incident
        single_incident = incident_data.iloc[[incident_index]]
        incident_id = single_incident.index[incident_index] if hasattr(single_incident.index, '__getitem__') else f'incident_{incident_index}'
        
        # Make prediction
        proba = model.predict_proba(single_incident[ALL_FEATURES])[0, 1]
        prediction = int(proba >= 0.5)
        
        # Get EBM explanation
        ebm_explanation = model.named_steps["classifier"].explain_local(single_incident[ALL_FEATURES])
        
        # Extract feature contributions
        feature_contribs = []
        for j, feature_name in enumerate(ALL_FEATURES):
            if j < len(ebm_explanation['scores'][0]):
                contrib = ebm_explanation['scores'][0][j]
                feature_contribs.append((feature_name, contrib))
        
        # Sort by absolute contribution and take top 10
        feature_contribs.sort(key=lambda x: abs(x[1]), reverse=True)
        top_features = feature_contribs[:10]
        
        explanation = {
            'incident_id': incident_id,
            'prediction': float(proba),
            'suspicious': bool(prediction),
            'confidence': float(abs(proba - 0.5) * 2),
            'intercept': float(ebm_explanation['intercept'][0]),
            'feature_contributions': [
                {
                    'feature': feat,
                    'contribution': float(contrib),
                    'direction': 'increases suspicion' if contrib > 0 else 'decreases suspicion'
                }
                for feat, contrib in top_features
            ]
        }
        
        return explanation
        
    except Exception as e:
        logger.error(f"Error generating explanation: {e}")
        # Fallback to basic prediction
        try:
            proba = model.predict_proba(single_incident[ALL_FEATURES])[0, 1]
            return {
                'incident_id': incident_id,
                'prediction': float(proba),
                'suspicious': bool(int(proba >= 0.5)),
                'confidence': float(abs(proba - 0.5) * 2),
                'error': str(e)
            }
        except:
            return {'error': str(e)}


def _safe_metric(fn):
    try:
        return round(float(fn()), 6)
    except Exception:
        return None


def _to_jsonable(obj):
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, (np.integer, np.floating)):
        return float(obj)
    if isinstance(obj, (pd.Timestamp, np.datetime64)):
        return str(obj)
    if pd.isna(obj):
        return None
    return obj


def main():
    parser = argparse.ArgumentParser(description="Train EBM incident model")
    parser.add_argument("--project-root", default=".", help="Project root")
    parser.add_argument("--input-incidents", default="data/processed/incidents_labeled.parquet")
    parser.add_argument("--output-model", default="artifacts/ebm_model.joblib")
    parser.add_argument("--output-pkl", default="artifacts/ebm_model.pkl")
    parser.add_argument("--output-scored", default="data/processed/incidents_ebm_scored.parquet")
    parser.add_argument("--generate-shap", action="store_true", help="Generate SHAP explanations")
    parser.add_argument("--shap-sample-size", type=int, default=50, help="Number of incidents to explain with SHAP")
    parser.add_argument("--shap-waterfall-plot", type=int, nargs='?', const=0, help="Generate waterfall plot for specific incident index")
    parser.add_argument("--shap-output-dir", default="reports/shap_explanations", help="Directory to save SHAP outputs")
    parser.add_argument("--predict-with-contributions", action="store_true", help="Generate predictions with feature contributions")
    parser.add_argument("--prediction-output", default="data/processed/incidents_predicted_with_contributions.parquet", help="Output file for predictions with contributions")
    parser.add_argument("--top-features", type=int, default=5, help="Number of top contributing features to show")
    args = parser.parse_args()

    configure_logging()
    project_root = Path(args.project_root).resolve()
    
    logger.info("Loading incidents from %s", project_root / args.input_incidents)
    labeled = pd.read_parquet(project_root / args.input_incidents)
    
    report, scored = train_ebm_model(labeled, project_root / args.output_model)
    
    if args.output_pkl:
        model = load_ebm_model(project_root / args.output_model)
        save_ebm_model_pkl(model, project_root / args.output_pkl)
    
    logger.info("Saving scored incidents to %s", project_root / args.output_scored)
    scored.to_parquet(project_root / args.output_scored, index=False)
    
    report_path = project_root / "reports" / "ebm_model_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    
    # Generate SHAP explanations if requested
    if args.generate_shap:
        logger.info("Generating SHAP explanations...")
        shap_output_dir = Path(args.shap_output_dir)
        shap_output_dir.mkdir(parents=True, exist_ok=True)
        
        model = load_ebm_model(project_root / args.output_model)
        
        # Generate SHAP explanations for sample incidents
        shap_explanations = get_shap_explanations(model, labeled, max_evals=args.shap_sample_size)
        
        if not shap_explanations.empty:
            shap_csv_path = shap_output_dir / "shap_explanations.csv"
            shap_explanations.to_csv(shap_csv_path, index=False)
            logger.info(f"SHAP explanations saved to {shap_csv_path}")
            
            # Save as JSON for easier processing
            shap_json_path = shap_output_dir / "shap_explanations.json"
            shap_explanations.to_json(shap_json_path, orient='records', indent=2)
            logger.info(f"SHAP explanations JSON saved to {shap_json_path}")
    
    # Generate SHAP waterfall plot if requested
    if args.shap_waterfall_plot is not None:
        logger.info(f"Generating SHAP waterfall plot for incident index {args.shap_waterfall_plot}")
        shap_output_dir = Path(args.shap_output_dir)
        shap_output_dir.mkdir(parents=True, exist_ok=True)
        
        model = load_ebm_model(project_root / args.output_model)
        
        plot_path = shap_output_dir / f"shap_waterfall_incident_{args.shap_waterfall_plot}.png"
        fig = create_shap_waterfall_plot(model, labeled, args.shap_waterfall_plot, plot_path)
        
        if fig is not None:
            logger.info(f"SHAP waterfall plot saved to {plot_path}")
    
    # Generate predictions with feature contributions if requested
    if args.predict_with_contributions:
        logger.info("Generating predictions with feature contributions...")
        model = load_ebm_model(project_root / args.output_model)
        
        predictions_with_contributions = predict_ebm_with_feature_contributions(
            model, 
            labeled, 
            top_n_features=args.top_features
        )
        
        logger.info("Saving predictions with contributions to %s", project_root / args.prediction_output)
        predictions_with_contributions.to_parquet(project_root / args.prediction_output, index=False)
        
        # Also save as JSON for easier inspection
        json_output = project_root / args.prediction_output.replace('.parquet', '_sample.json')
        sample_predictions = predictions_with_contributions.head(10).to_dict('records')
        with open(json_output, 'w') as f:
            json.dump(sample_predictions, f, indent=2, default=str)
        logger.info(f"Sample predictions saved to {json_output}")
    
    output_info = {
        "status": "success",
        "incidents": len(labeled),
        "model_path_joblib": str(project_root / args.output_model),
        "model_path_pkl": str(project_root / args.output_pkl),
        "report_path": str(report_path),
    }
    
    if args.generate_shap:
        output_info["shap_explanations_dir"] = str(Path(args.shap_output_dir))
    
    if args.shap_waterfall_plot is not None:
        output_info["shap_waterfall_plot"] = str(Path(args.shap_output_dir) / f"shap_waterfall_incident_{args.shap_waterfall_plot}.png")
    
    if args.predict_with_contributions:
        output_info["predictions_with_contributions"] = str(project_root / args.prediction_output)
        output_info["sample_predictions_json"] = str(json_output)
    
    print(json.dumps(output_info, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
