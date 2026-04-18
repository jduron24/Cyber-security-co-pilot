from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import httpx
import streamlit as st


BACKEND_URL = os.getenv("SENTINEL_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_URL = os.getenv("SENTINEL_AGENT_URL", "http://127.0.0.1:8001").rstrip("/")
DEFAULT_INCIDENT_ID = "incident_000000001"


st.set_page_config(page_title="Sentinel", layout="wide")
st.title("Sentinel")
st.caption("Autonomous Cyber Defense Co-Pilot")
st.markdown("---")


if "incident_bundle" not in st.session_state:
    st.session_state.incident_bundle = None
if "backend_error" not in st.session_state:
    st.session_state.backend_error = None
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []
if "operator_decision" not in st.session_state:
    st.session_state.operator_decision = None
if "agent_answer" not in st.session_state:
    st.session_state.agent_answer = None


def now_str() -> str:
    return datetime.now().strftime("%I:%M:%S %p")


def add_audit(message: str) -> None:
    st.session_state.audit_log.append(f"{now_str()} - {message}")


def severity_badge(severity: str) -> str:
    sev = str(severity).lower()
    if sev == "critical":
        return "Critical"
    if sev == "high":
        return "High"
    if sev == "medium":
        return "Medium"
    if sev == "low":
        return "Low"
    return str(severity)


def to_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def backend_get(path: str, **params: Any) -> dict[str, Any]:
    with httpx.Client(base_url=BACKEND_URL, timeout=10.0) as client:
        response = client.get(path, params={key: value for key, value in params.items() if value is not None})
        response.raise_for_status()
        return response.json()


def backend_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    with httpx.Client(base_url=BACKEND_URL, timeout=20.0) as client:
        response = client.post(path, json=payload)
        response.raise_for_status()
        return response.json()


def mock_bundle(incident_id: str) -> dict[str, Any]:
    return {
        "incident": {
            "incident_id": incident_id,
            "title": "Suspicious Login Burst Detected",
            "summary": "Multiple failed login attempts were detected from an unfamiliar source against a critical operator account.",
            "severity_hint": "high",
            "primary_actor": {"actor_key": "arn:aws:iam::123456789012:assumed-role/SalesApp"},
            "entities": {"primary_source_ip_address": "203.0.113.10"},
            "event_sequence": ["ConsoleLogin", "GetCallerIdentity", "ListUsers", "CreateAccessKey"],
        },
        "decision_support": {
            "decision_support_result": {
                "recommended_action": {"action_id": "reset_credentials", "label": "Reset credentials"},
                "alternative_actions": [{"action_id": "escalate_to_expert", "label": "Escalate to expert"}],
                "completeness_assessment": {
                    "level": "medium",
                    "warning": "Network activity was not checked.",
                    "reasons": ["Network telemetry was not checked."],
                },
                "operator_guidance": {
                    "plain_language_summary": "The login pattern looks suspicious, but the system did not check the network branch."
                },
            }
        },
        "coverage_review": {
            "incident_id": incident_id,
            "incident_summary": {
                "title": "Suspicious Login Burst Detected",
                "summary": "Multiple failed login attempts were detected from an unfamiliar source against a critical operator account.",
                "risk_band": "high",
                "risk_score": 0.91,
                "top_signals": [
                    {"label": "17 failed login attempts in 3 minutes", "weight": 4},
                    {"label": "Source IP not previously seen", "weight": 3},
                ],
                "event_sequence": ["ConsoleLogin", "GetCallerIdentity", "ListUsers", "CreateAccessKey"],
                "primary_actor": {"actor_key": "arn:aws:iam::123456789012:assumed-role/SalesApp"},
                "entities": {"primary_source_ip_address": "203.0.113.10"},
            },
            "recommended_action": {"action_id": "reset_credentials", "label": "Reset credentials", "requires_human_approval": True},
            "alternative_actions": [{"action_id": "escalate_to_expert", "label": "Escalate to expert"}],
            "coverage_status_by_category": [
                {"category": "login", "status": "checked_signal_found", "checks": [{"name": "login_activity", "status": "checked_signal_found"}], "missing_sources": []},
                {"category": "network", "status": "not_checked", "checks": [{"name": "network_logs", "status": "not_checked"}], "missing_sources": ["network_logs"]},
            ],
            "completeness": {
                "level": "medium",
                "warning": "Network activity was not checked.",
                "reasons": ["Network telemetry was not checked."],
            },
            "recommendation_may_be_incomplete": True,
            "decision_risk_note": "Network activity was not checked. Reset credentials should be reviewed carefully because it is a disruptive action.",
            "what_could_change_the_decision": [
                "If network_logs shows additional suspicious activity, the recommended action may need to change.",
                "Completing review network logs could confirm or weaken the current recommendation.",
            ],
            "double_check": {
                "available": True,
                "prompt": "Double check missing branches before taking disruptive action.",
                "candidates": ["Review network logs", "Confirm whether this IP belongs to a vendor VPN"],
            },
        },
    }


def load_incident_bundle(incident_id: str) -> dict[str, Any]:
    try:
        incident = backend_get(f"/incidents/{incident_id}")
        decision_support = backend_get(f"/incidents/{incident_id}/decision-support")
        coverage_review = backend_get(f"/incidents/{incident_id}/coverage-review")
        st.session_state.backend_error = None
        add_audit(f"Loaded {incident_id} from FastAPI backend")
        return {
            "incident": incident["incident"],
            "evidence_package": incident.get("evidence_package"),
            "detector_result": incident.get("detector_result"),
            "coverage_assessment": incident.get("coverage_assessment"),
            "decision_support": decision_support["result"],
            "coverage_review": coverage_review["review"],
        }
    except Exception as exc:
        st.session_state.backend_error = str(exc)
        add_audit(f"Backend unavailable for {incident_id}; using mock data")
        return mock_bundle(incident_id)


def post_operator_decision(incident_id: str, action: str, payload: dict[str, Any]) -> None:
    try:
        result = backend_post(f"/incidents/{incident_id}/{action}", payload)
        st.session_state.operator_decision = result["result"]
        add_audit(f"Operator action sent to backend: {action}")
    except Exception as exc:
        st.session_state.operator_decision = {"decision_type": action, "error": str(exc)}
        add_audit(f"Operator action failed against backend: {action}")


def ask_agent(incident_id: str, user_query: str) -> None:
    try:
        with httpx.Client(base_url=AGENT_URL, timeout=20.0) as client:
            response = client.post(f"/incidents/{incident_id}/agent-query", json={"user_query": user_query})
            response.raise_for_status()
            result = response.json()
        st.session_state.agent_answer = result["result"]
        add_audit(f"Asked agent about {incident_id}")
    except Exception as exc:
        st.session_state.agent_answer = {"answer": f"Agent request failed: {exc}"}
        add_audit(f"Agent request failed for {incident_id}")


st.sidebar.header("Controls")
st.sidebar.caption(f"Backend: {BACKEND_URL}")
st.sidebar.caption(f"Agent: {AGENT_URL}")
incident_id = st.sidebar.text_input("Incident ID", value=DEFAULT_INCIDENT_ID)

if st.sidebar.button("Load Incident") or st.session_state.incident_bundle is None:
    st.session_state.incident_bundle = load_incident_bundle(incident_id)

bundle = st.session_state.incident_bundle or mock_bundle(incident_id)
incident = bundle["incident"]
coverage_review = bundle["coverage_review"]
decision_support = bundle["decision_support"]["decision_support_result"]

if st.session_state.backend_error:
    st.warning("Backend not connected cleanly. Showing fallback data.")
    st.caption(st.session_state.backend_error)
else:
    st.success("Backend connected.")


incident_id_val = incident.get("incident_id", incident_id)
title = coverage_review["incident_summary"].get("title") or incident.get("title") or "Cyber Incident"
severity = coverage_review["incident_summary"].get("risk_band") or incident.get("severity_hint") or "unknown"
system_name = incident.get("system_name") or incident.get("entities", {}).get("primary_source_ip_address") or "Unknown system"
summary = coverage_review["incident_summary"].get("summary") or incident.get("summary") or "No summary available."
recommended_action = decision_support.get("recommended_action", {})
recommended_label = recommended_action.get("label") or recommended_action.get("action_id") or "No action available."
confidence = coverage_review["incident_summary"].get("risk_score")
status = "Pending Operator Review"
top_signals = to_list(coverage_review["incident_summary"].get("top_signals"))
blind_spots = to_list(coverage_review.get("what_could_change_the_decision"))
double_check_paths = to_list(coverage_review.get("double_check", {}).get("candidates"))
coverage_categories = to_list(coverage_review.get("coverage_status_by_category"))
backend_audit = []

left, right = st.columns([2, 1])

with left:
    st.subheader("Active Alert")
    st.markdown(f"**Incident ID:** {incident_id_val}")
    st.markdown(f"**Title:** {title}")
    st.markdown(f"**Severity:** {severity_badge(severity)}")
    st.markdown(f"**System / Entity:** {system_name}")
    st.markdown(f"**Status:** {status}")

    st.markdown("### Plain-English Explanation")
    st.write(summary)

    st.markdown("### Recommended Action")
    st.info(recommended_label)

    st.markdown("### Why This Matters")
    st.write(coverage_review.get("decision_risk_note", "No impact explanation available."))

    st.markdown("### Confidence")
    if isinstance(confidence, (int, float)):
        score = max(0.0, min(float(confidence), 1.0))
        st.progress(score)
        st.write(f"{score:.0%}")
    else:
        st.write("Unknown")

    st.markdown("### Human-in-the-Loop Review")
    note = st.text_input("Optional note")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        if st.button("Approve"):
            post_operator_decision(incident_id_val, "approve", {"rationale": note})

    with c2:
        alternatives = to_list(decision_support.get("alternative_actions"))
        alt_action = alternatives[0]["action_id"] if alternatives else "escalate_to_expert"
        if st.button("Choose Alternative"):
            post_operator_decision(incident_id_val, "alternative", {"action_id": alt_action, "rationale": note})

    with c3:
        if st.button("Escalate"):
            post_operator_decision(incident_id_val, "escalate", {"rationale": note})

    with c4:
        if st.button("Double-Check"):
            post_operator_decision(incident_id_val, "double-check", {"rationale": note, "used_double_check": True})

    if st.session_state.operator_decision:
        st.success(f"Latest operator decision: {st.session_state.operator_decision.get('decision_type', 'recorded')}")

    st.markdown("### Ask Agent")
    agent_query = st.text_input("Question for the agent", value="What should I do next?")
    if st.button("Send to Agent"):
        ask_agent(incident_id_val, agent_query)

    if st.session_state.agent_answer:
        st.markdown("### Agent Response")
        st.write(st.session_state.agent_answer.get("answer", st.session_state.agent_answer))

with right:
    st.subheader("Supporting Evidence")
    if top_signals:
        for item in top_signals:
            label = item.get("label") if isinstance(item, dict) else str(item)
            st.write(f"- {label}")
    else:
        st.write("No evidence available.")

    st.markdown("---")
    st.subheader("Coverage Status")
    if coverage_categories:
        for item in coverage_categories:
            st.write(f"- {item.get('category')}: {item.get('status')}")
    else:
        st.write("No coverage status available.")

    st.markdown("---")
    st.subheader("Blind Spots")
    if blind_spots:
        for item in blind_spots:
            st.write(f"- {item}")
    else:
        st.write("No blind spots available.")

    st.markdown("---")
    st.subheader("Double-Check Paths")
    if double_check_paths:
        for item in double_check_paths:
            st.write(f"- {item}")
    else:
        st.write("No double-check steps available.")

st.markdown("---")
st.subheader("Audit Trail")
combined_audit = backend_audit + st.session_state.audit_log
if combined_audit:
    for entry in combined_audit:
        st.write(f"- {entry}")
else:
    st.write("No audit trail available.")

with st.expander("Raw Payload"):
    st.json(bundle)
