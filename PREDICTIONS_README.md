# EBM Predictions with Feature Contributions

## Overview

This document describes the Explainable Boosting Machine (EBM) model for cybersecurity anomaly detection with detailed feature contribution explanations.

## Model Features

### What is Predicted?
- **Target Variable**: `weak_label_suspicious` 
- **Type**: Binary Classification (0 = Normal Incident, 1 = Suspicious/Anomalous)
- **Purpose**: Identify cybersecurity incidents that warrant investigation

### Input Features (31 total)

#### Numeric Features (9)
- `incident_duration_seconds` - Duration of the security incident
- `event_count` - Total number of events
- `distinct_event_names` - Uniqueness of event types
- `distinct_event_sources` - Number of unique sources
- `distinct_regions` - Geographic diversity
- `error_event_count` - Number of errors
- `success_event_count` - Number of successful operations
- `failure_ratio` - Proportion of failed operations
- `events_per_minute` - Event frequency/rate

#### Boolean Features (17)
- `contains_console_login` - Console access detected
- `contains_recon_like_api` - Reconnaissance API calls
- `contains_privilege_change_api` - Privilege escalation attempts
- `contains_resource_creation_api` - Resource creation activities
- `actor_is_root` - Root user involvement
- `actor_is_assumed_role` - Assumed role usage
- `has_high_failure_ratio` - High failure rate
- `has_failure_burst` - Sudden failure spike
- `has_event_burst` - Sudden event volume spike
- `has_broad_surface_area` - Wide attack surface
- `has_iam_sequence` - IAM activity sequence
- `has_sts_sequence` - STS activity sequence
- `has_ec2_sequence` - EC2 activity sequence
- `has_recon_plus_privilege` - Recon + privilege combo
- `has_recon_plus_resource_creation` - Recon + resource creation combo
- `has_privilege_plus_resource_creation` - Privilege + resource creation combo
- `has_root_plus_privilege` - Root + privilege combo

#### Categorical Features (5)
- `actor_key` - User/actor identifier
- `primary_source_ip_address` - Main IP address
- `first_event_name` - Initial event type
- `last_event_name` - Final event type
- `top_event_name` - Most frequent event type

## Generated Outputs

### Performance Metrics
File: `reports/ebm_model_report.json`

Includes:
- **ROC AUC Score**: Model's discriminatory power (0-1)
- **Average Precision Score**: Precision-recall trade-off metric
- **Classification Report**: Precision, Recall, F1-score per class
- **Top Features**: Most important features for predictions

### Predictions with Feature Contributions
Files:
- `data/processed/incidents_predicted_with_contributions.parquet` - Full dataset with predictions
- `data/processed/incidents_predicted_with_contributions_sample.json` - Sample predictions (10 incidents)

### Prediction Output Format

Each prediction includes:

```json
{
  "suspicion_score": 0.25,
  "suspected_suspicious": 0,
  "confidence": 0.50,
  "explanation_prediction_probability": 0.25,
  "explanation_predicted_suspicious": 0,
  "explanation_confidence": 0.50,
  "explanation_base_value": 0.30,
  "explanation_top_contributing_features": [
    {
      "feature": "event_count",
      "contribution": 4.3,
      "direction": "increases suspicion",
      "feature_value": 43
    },
    {
      "feature": "failure_ratio",
      "contribution": 0.031,
      "direction": "increases suspicion",
      "feature_value": 0.309
    },
    {
      "feature": "distinct_event_names",
      "contribution": 0.9,
      "direction": "increases suspicion",
      "feature_value": 9
    }
  ]
}
```

### Output Field Meanings

- **suspicion_score**: Probability from 0-1 that incident is suspicious (higher = more suspicious)
- **suspicious**: Binary prediction (0 = normal, 1 = suspicious)
- **confidence**: Model confidence in the prediction (0-1, higher = more confident)
- **explanation_top_contributing_features**: The features most influential in this prediction
  - **feature**: Which security indicator
  - **contribution**: How much it increased/decreased suspicion (positive = increases)
  - **direction**: Interpretation of contribution direction
  - **feature_value**: The actual value of this feature in the incident

## Performance Metrics

### Key Metrics
- **ROC AUC**: Measures ability to discriminate between classes
- **Average Precision**: Emphasizes correct predictions of positive class
- **Precision**: Correctness of positive predictions
- **Recall**: Coverage of actual positive cases
- **F1-Score**: Harmonic mean of precision and recall

## Usage

### Generate Predictions with Feature Contributions
```bash
python EBM_model.py --predict-with-contributions --top-features 5
```

Options:
- `--top-features N`: Number of top contributing features to include (default: 5)
- `--prediction-output FILE`: Output file path for predictions

### Generate SHAP Explanations
```bash
python EBM_model.py --generate-shap --shap-sample-size 50
```

### Create Waterfall Plot
```bash
python EBM_model.py --shap-waterfall-plot 0
```

## Security Use Cases

1. **Incident Triage**: Quickly understand why alerts were triggered
2. **Threat Hunting**: Identify which behavioral patterns are most suspicious
3. **Model Validation**: Verify the model focuses on meaningful security indicators
4. **Compliance & Auditing**: Provide transparent, explainable predictions
5. **Alert Reduction**: Prioritize investigations based on feature contributions

## Performance Notes

- **Model Type**: Explainable Boosting Machine (EBM)
- **Training/Test Split**: 80/20
- **Feature Count**: 31 security-relevant features
- **Target Distribution**: Imbalanced (approx. 31% suspicious)
- **Explainability**: Per-prediction feature contributions

## Data Files

| File | Size | Description |
|------|------|-------------|
| `incidents_labeled.parquet` | Input | Labeled incidents for training |
| `incidents_ebm_scored.parquet` | Output | All incidents with model scores |
| `incidents_predicted_with_contributions.parquet` | Output | Predictions with feature explanations |
| `incidents_predicted_with_contributions_sample.json` | Output | Human-readable sample predictions |
| `ebm_model.joblib` | Model | Trained EBM model (joblib format) |
| `ebm_model.pkl` | Model | Trained EBM model (pickle format) |
| `ebm_model_report.json` | Report | Comprehensive performance report |

## Next Steps

1. Review sample predictions in `incidents_predicted_with_contributions_sample.json`
2. Analyze feature contributions for top anomalies
3. Use predictions to guide security investigations
4. Refine feature set based on model insights
5. Integrate predictions into security workflows

---

For questions or issues, refer to the main README or contact the security team.
