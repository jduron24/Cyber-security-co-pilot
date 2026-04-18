from __future__ import annotations

import json

import pytest

from src.agent.mcp_client import McpClientError, McpCyberContextClient, _parse_tool_rows
from src.agent.react import REACT_SYSTEM_PROMPT, build_correction_message, build_react_messages, build_response_style_guidance, parse_react_step


def test_parse_react_step_extracts_embedded_json_object():
    content = 'preface {"thought":"Need incident","action":"load_incident","action_input":{"limit":1}} suffix'
    step = parse_react_step(content)

    assert step.action == "load_incident"
    assert step.action_input == {"limit": 1}
    assert step.thought == "Need incident"


def test_parse_react_step_coerces_non_dict_action_input_to_empty_dict():
    step = parse_react_step(json.dumps({"thought": "oops", "action": "load_incident", "action_input": ["bad"]}))
    assert step.action == "load_incident"
    assert step.action_input == {}


def test_build_react_messages_instructs_model_to_start_with_tool():
    messages = build_react_messages(
        user_query="What happened?",
        incident_id="INC-1",
        tool_specs=[{"name": "load_incident", "description": "Load incident"}],
    )
    assert messages[0]["role"] == "system"
    assert "load_incident" in messages[1]["content"]
    assert "Start by choosing a tool" in messages[1]["content"]


def test_react_system_prompt_demands_plain_language_operator_answer():
    assert "plain language" in REACT_SYSTEM_PROMPT
    assert "Do not say \"stored recommendation\"" in REACT_SYSTEM_PROMPT
    assert "lead with the recommended next step" in REACT_SYSTEM_PROMPT


def test_build_response_style_guidance_for_summary_question():
    guidance = build_response_style_guidance("What happened here?")
    assert "Do not lead with a recommendation" in guidance
    assert "incident summary" in guidance


def test_build_response_style_guidance_for_risk_question():
    guidance = build_response_style_guidance("How serious is this risk?")
    assert "Focus on risk and severity" in guidance
    assert "Lead with your risk assessment" in guidance


def test_build_response_style_guidance_for_alternatives_question():
    guidance = build_response_style_guidance("What other options do I have?")
    assert "Focus on the available options" in guidance
    assert "compare the main alternatives" in guidance


def test_build_correction_message_explicitly_blocks_finishing():
    message = build_correction_message("You did not use enough tools.")
    assert "Do not finish yet" in message
    assert "load_incident" in message


def test_parse_tool_rows_raises_on_invalid_json_payload():
    with pytest.raises(McpClientError, match="invalid JSON"):
        _parse_tool_rows("{not json}")


def test_parse_tool_rows_raises_when_tool_text_is_not_json():
    payload = json.dumps({"content": [{"type": "text", "text": "not-json"}]})
    with pytest.raises(McpClientError, match="not valid JSON"):
        _parse_tool_rows(payload)


def test_mcp_client_from_env_can_be_disabled_with_explicit_empty_dict():
    client = McpCyberContextClient.from_env(env={}, project_root=".")
    assert client.enabled is False
