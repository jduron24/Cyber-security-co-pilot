from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


REACT_SYSTEM_PROMPT = """You are a security triage assistant using a ReAct workflow.
You must reason step by step with the available tools before answering.
Ground every statement in tool observations only.
Do not invent evidence, checks, actions, policies, or missing context.
When coverage is incomplete, say so clearly.
If a stored or generated recommendation exists, explain it faithfully rather than replacing it.

Respond with a single JSON object on every turn using this schema:
{
  "thought": "short internal reasoning summary",
  "action": "tool_name or finish",
  "action_input": {"optional": "tool arguments"},
  "final_answer": "required only when action is finish"
}

Rules:
- You must call `load_incident` before finishing.
- You must use at least one additional context tool before finishing. Prefer `load_decision_support`, `load_detector_result`, or `load_coverage_assessment` depending on the question.
- If `load_mcp_cyber_context` is available and the operator asks for ATT&CK, threat, mitigation, cyber, or technique context, you must use it before finishing.
- Keep thoughts short and operational.
- When you have enough evidence, set action to "finish" and provide the operator-facing answer in final_answer.
- Do not wrap the JSON in markdown fences."""


@dataclass
class ReactStep:
    thought: str
    action: str
    action_input: dict[str, Any]
    final_answer: str | None
    raw_content: str


def build_react_messages(
    user_query: str,
    incident_id: str,
    tool_specs: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": REACT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Incident ID: {incident_id}\n"
                f"Operator request: {user_query}\n\n"
                "Available tools:\n"
                f"{json.dumps(tool_specs, indent=2)}\n\n"
                "Start by choosing a tool. In most cases call `load_incident` first."
            ),
        },
    ]


def parse_react_step(content: str) -> ReactStep:
    parsed = _extract_json_object(content)
    if parsed is None:
        return ReactStep(
            thought="Model returned non-JSON output; treating it as final answer.",
            action="finish",
            action_input={},
            final_answer=content.strip(),
            raw_content=content,
        )
    action = str(parsed.get("action") or "").strip() or "finish"
    action_input = parsed.get("action_input") or {}
    if not isinstance(action_input, dict):
        action_input = {}
    final_answer = parsed.get("final_answer")
    if final_answer is not None:
        final_answer = str(final_answer)
    return ReactStep(
        thought=str(parsed.get("thought") or "").strip(),
        action=action,
        action_input=action_input,
        final_answer=final_answer,
        raw_content=content,
    )


def build_observation_message(tool_name: str, observation: dict[str, Any]) -> str:
    return (
        f"Observation from tool `{tool_name}`:\n"
        f"{json.dumps(observation, indent=2, default=str)}\n\n"
        "Choose the next tool or finish."
    )


def build_correction_message(reason: str) -> str:
    return (
        f"Your last step could not be accepted: {reason}\n"
        "Return the next JSON step. Do not finish yet. Use a tool call next, starting with `load_incident` if it has not been called."
    )


def _extract_json_object(content: str) -> dict[str, Any] | None:
    stripped = content.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        try:
            parsed = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return None
    return parsed if isinstance(parsed, dict) else None
