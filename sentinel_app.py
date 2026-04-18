Python 3.14.4 (v3.14.4:23116f998f6, Apr  7 2026, 09:45:22) [Clang 17.0.0 (clang-1700.6.4.2)] on darwin
Enter "help" below or click "Help" above for more information.
import streamlit as st
import json
from datetime import datetime

st.set_page_config(page_title="Sentinel", layout="wide")

st.title("Sentinel")
st.caption("Autonomous Cyber Defense Co-Pilot")
st.markdown("---")

if "incident_data" not in st.session_state:
    st.session_state.incident_data = None
if "backend_error" not in st.session_state:
    st.session_state.backend_error = None
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []
if "operator_decision" not in st.session_state:
    st.session_state.operator_decision = None


def now_str():
    return datetime.now().strftime("%I:%M:%S %p")


def add_audit(message):
    st.session_state.audit_log.append(f"{now_str()} - {message}")


def get_field(data, keys, default=None):
    if not isinstance(data, dict):
        return default
    for key in keys:
        if key in data and data[key] not in (None, "", []):
            return data[key]
    return default


def to_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def severity_badge(severity):
    sev = str(severity).lower()
    if sev == "critical":
        return "🔴 Critical"
    if sev == "high":
        return "🟠 High"
    if sev == "medium":
        return "🟡 Medium"
    if sev == "low":
        return "🟢 Low"
    return f"⚪ {severity}"


def mock_incident(incident_id):
    return {
        "incident_id": incident_id,
        "title": "Suspicious Login Burst Detected",
        "severity": "High",
        "system_name": "Municipal Water Utility Admin Panel",
        "plain_english_summary": "Multiple failed login attempts were detected from an unfamiliar source against a critical operator account.",
        "recommended_action": "Temporarily block the source IP and require credential reset.",
        "why_this_matters": "If this activity is malicious, it could lead to unauthorized access to a critical system.",
        "confidence": 0.91,
        "status": "Pending Operator Review",
        "evidence": [
            "17 failed login attempts in 3 minutes",
            "Source IP not previously seen for this account",
            "Activity occurred outside normal operating hours"
        ],
        "blind_spots": [
            "No confirmed geolocation enrichment available",
            "User device fingerprint unavailable"
        ],
        "double_check_paths": [
            "Verify whether this IP belongs to a vendor VPN",
            "Confirm whether maintenance activity was scheduled"
        ],
        "audit_log": [
            f"{now_str()} - Incident loaded",
            f"{now_str()} - Awaiting operator review"
        ]
    }


def load_incident(incident_id):
    try:
        from src.decision_support_bridge import generate_decision_support_for_incident
        data = generate_decision_support_for_incident(incident_id, project_root=".")
        add_audit(f"Loaded {incident_id} from backend")
        st.session_state.backend_error = None
        return data
    except Exception as e:
        st.session_state.backend_error = str(e)
        add_audit(f"Backend unavailable for {incident_id}; using mock data")
        return mock_incident(incident_id)


def record_decision(incident_id, decision, note=""):
    add_audit(f"Operator decision for {incident_id}: {decision}" + (f" | Note: {note}" if note else ""))


st.sidebar.header("Controls")
incident_id = st.sidebar.text_input("Incident ID", value="incident_000000001")

if st.sidebar.button("Load Incident") or st.session_state.incident_data is None:
    st.session_state.incident_data = load_incident(incident_id)

data = st.session_state.incident_data

if st.session_state.backend_error:
    st.warning("Backend not connected yet. Showing mock data.")
    st.caption(st.session_state.backend_error)
else:
    st.success("Backend connected.")

incident_id_val = get_field(data, ["incident_id", "id"], incident_id)
title = get_field(data, ["title", "incident_title"], "Cyber Incident")
severity = get_field(data, ["severity", "risk_level"], "Unknown")
system_name = get_field(data, ["system_name", "asset_name", "system"], "Unknown system")
summary = get_field(data, ["plain_english_summary", "summary", "plain_language_explanation"], "No summary available.")
recommended_action = get_field(data, ["recommended_action", "recommended_next_step", "action"], "No action available.")
why_this_matters = get_field(data, ["why_this_matters", "impact"], "No impact explanation available.")
confidence = get_field(data, ["confidence", "score"], "Unknown")
status = get_field(data, ["status"], "Pending Review")
evidence = to_list(get_field(data, ["evidence", "supporting_evidence"], []))
blind_spots = to_list(get_field(data, ["blind_spots", "coverage_gaps"], []))
double_check_paths = to_list(get_field(data, ["double_check_paths", "double_checks"], []))
backend_audit = to_list(get_field(data, ["audit_log", "audit_trail"], []))

left, right = st.columns([2, 1])

with left:
    st.subheader("Active Alert")
    st.markdown(f"**Incident ID:** {incident_id_val}")
    st.markdown(f"**Title:** {title}")
    st.markdown(f"**Severity:** {severity_badge(severity)}")
    st.markdown(f"**System:** {system_name}")
    st.markdown(f"**Status:** {status}")

    st.markdown("### Plain-English Explanation")
    st.write(summary)

    st.markdown("### Recommended Action")
    st.info(recommended_action)

    st.markdown("### Why This Matters")
    st.write(why_this_matters)

    st.markdown("### Confidence")
    if isinstance(confidence, (int, float)):
        score = max(0.0, min(float(confidence), 1.0))
        st.progress(score)
        st.write(f"{score:.0%}")
    else:
        st.write(confidence)

    st.markdown("### Human-in-the-Loop Review")
    note = st.text_input("Optional note")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        if st.button("Approve"):
            st.session_state.operator_decision = "Approved"
            record_decision(incident_id_val, "Approved", note)

    with c2:
        if st.button("Reject"):
            st.session_state.operator_decision = "Rejected"
            record_decision(incident_id_val, "Rejected", note)

    with c3:
        if st.button("Escalate"):
            st.session_state.operator_decision = "Escalated"
            record_decision(incident_id_val, "Escalated", note)

    with c4:
        if st.button("Double-Check"):
            st.session_state.operator_decision = "Double-Check Requested"
            record_decision(incident_id_val, "Double-Check Requested", note)

...     if st.session_state.operator_decision:
...         st.success(f"Latest operator decision: {st.session_state.operator_decision}")
... 
... with right:
...     st.subheader("Supporting Evidence")
...     if evidence:
...         for item in evidence:
...             st.write(f"- {item}")
...     else:
...         st.write("No evidence available.")
... 
...     st.markdown("---")
...     st.subheader("Blind Spots")
...     if blind_spots:
...         for item in blind_spots:
...             st.write(f"- {item}")
...     else:
...         st.write("No blind spots available.")
... 
...     st.markdown("---")
...     st.subheader("Double-Check Paths")
...     if double_check_paths:
...         for item in double_check_paths:
...             st.write(f"- {item}")
...     else:
...         st.write("No double-check steps available.")
... 
... st.markdown("---")
... st.subheader("Audit Trail")
... 
... combined_audit = backend_audit + st.session_state.audit_log
... if combined_audit:
...     for entry in combined_audit:
...         st.write(f"- {entry}")
... else:
...     st.write("No audit trail available.")
... 
... with st.expander("Raw Payload"):
