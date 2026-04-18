import json
from pathlib import Path

import pytest

from src.agent.auth import CodexAuthError, load_codex_access_token, validate_codex_auth_base_url
from src.agent.openai_compat import OpenAICompatConfig, OpenAICompatError, create_chat_completion, extract_text_content
from src.agent.react import ReactStep
from src.agent.service import DecisionSupportAgent, normalize_operator_answer, recover_answer_after_loop
from src.services.agent_app_service import AgentAppConfig, load_agent_app_config, query_incident_agent


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeRepositories:
    def __init__(self, include_decision_support: bool = True):
        self.include_decision_support = include_decision_support

    def fetch_incident(self, incident_id: str):
        return {"incident_id": incident_id, "title": "Stored incident", "summary": "Stored summary"}

    def fetch_latest_evidence_package(self, incident_id: str):
        return {"summary_json": {"event_sequence": ["DescribeInstances", "RunInstances"]}}

    def fetch_latest_detector_result(self, incident_id: str):
        return {"risk_score": 0.8, "risk_band": "high"}

    def fetch_latest_coverage_assessment(self, incident_id: str):
        return {"completeness_level": "medium", "checks_json": [{"name": "network_logs", "status": "not_checked"}]}

    def fetch_latest_decision_support_result(self, incident_id: str):
        if not self.include_decision_support:
            return None
        return {"decision_support_result": {"incident_id": incident_id, "recommended_action": {"action_id": "collect_more_evidence"}}}


class FakeDecisionSupportService:
    def __init__(self):
        self.called = False

    def generate_for_incident(self, incident_id: str, policy_version=None):
        self.called = True
        return {"decision_support_result": {"incident_id": incident_id, "recommended_action": {"action_id": "reset_credentials"}}}


class FakeMcpClient:
    enabled = True

    def search(self, query: str, limit: int = 5):
        return [{"title": "Brute Force", "domain": "Credential Access", "score": 0.9}][:limit]


def fake_request(request):
    return FakeResponse({"choices": [{"message": {"content": "Use the stored decision support and review missing checks."}}]})


class SequencedRequest:
    def __init__(self, contents: list[str]):
        self._contents = contents
        self.calls = 0

    def __call__(self, request):
        try:
            content = self._contents[self.calls]
        except IndexError as exc:
            raise AssertionError("Request sequence exhausted.") from exc
        self.calls += 1
        return FakeResponse({"choices": [{"message": {"content": content}}]})


def test_openai_compat_completion_round_trip():
    config = OpenAICompatConfig(model="test-model", base_url="https://example.test/v1", api_key="secret")
    response = create_chat_completion(config, [{"role": "user", "content": "Hello"}], request_fn=fake_request)
    assert extract_text_content(response) == "Use the stored decision support and review missing checks."


def test_extract_text_content_from_openai_content_parts():
    response = {
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": "Part one"},
                        {"type": "input_text", "text": "ignored"},
                        {"type": "text", "text": "Part two"},
                    ]
                }
            }
        ]
    }
    assert extract_text_content(response) == "Part one\nPart two"


def test_extract_text_content_raises_on_missing_message():
    with pytest.raises(OpenAICompatError):
        extract_text_content({"choices": []})


def test_load_codex_access_token_from_auth_file(tmp_path: Path):
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "codex-access-token",
                },
            }
        ),
        encoding="utf-8",
    )
    assert load_codex_access_token({"CODEX_AUTH_PATH": str(auth_path)}) == "codex-access-token"


def test_validate_codex_auth_base_url_rejects_non_openai_endpoint():
    with pytest.raises(CodexAuthError):
        validate_codex_auth_base_url("https://example.test/v1")


def test_agent_uses_existing_decision_support_when_present():
    request = SequencedRequest(
        [
            json.dumps({"thought": "Need the stored recommendation.", "action": "load_decision_support", "action_input": {}}),
            json.dumps({"thought": "Enough context.", "action": "finish", "final_answer": "Use the stored decision support and review missing checks."}),
        ]
    )
    agent = DecisionSupportAgent(
        repositories=FakeRepositories(include_decision_support=True),
        decision_support_service=FakeDecisionSupportService(),
        mcp_client=None,
        endpoint_config=OpenAICompatConfig(model="test-model", base_url="https://example.test/v1"),
    )
    result = agent.respond("INC-1", "What should I do next?", request_fn=request)
    assert result["incident_id"] == "INC-1"
    assert "Use the stored decision support" in result["answer"]
    assert result["decision_support_source"] == "database"
    assert result["reasoning_trace"][0]["action"] == "load_decision_support"


def test_agent_generates_decision_support_when_missing():
    ds_service = FakeDecisionSupportService()
    request = SequencedRequest(
        [
            json.dumps({"thought": "Stored recommendation may be missing.", "action": "generate_decision_support", "action_input": {}}),
            json.dumps({"thought": "Now I can answer.", "action": "finish", "final_answer": "Reset credentials and continue the review."}),
        ]
    )
    agent = DecisionSupportAgent(
        repositories=FakeRepositories(include_decision_support=False),
        decision_support_service=ds_service,
        mcp_client=None,
        endpoint_config=OpenAICompatConfig(model="test-model", base_url="https://example.test/v1"),
    )
    result = agent.respond("INC-2", "Summarize this incident.", request_fn=request)
    assert ds_service.called is True
    assert result["context_summary"]["has_decision_support_result"] is True
    assert result["decision_support_source"] == "generated"


def test_agent_rejects_finish_before_tool_use():
    request = SequencedRequest(
        [
            json.dumps({"thought": "I can answer immediately.", "action": "finish", "final_answer": "Premature answer"}),
            json.dumps({"thought": "Need detector context.", "action": "load_detector_result", "action_input": {}}),
            json.dumps({"thought": "Now I can answer.", "action": "finish", "final_answer": "Risk is high based on detector output."}),
        ]
    )
    agent = DecisionSupportAgent(
        repositories=FakeRepositories(include_decision_support=True),
        decision_support_service=FakeDecisionSupportService(),
        mcp_client=None,
        endpoint_config=OpenAICompatConfig(model="test-model", base_url="https://example.test/v1"),
    )
    result = agent.respond("INC-3", "Assess the risk.", request_fn=request)
    assert result["answer"] == "Risk is high based on detector output."
    assert result["reasoning_trace"][0]["status"] == "rejected"
    assert result["context_summary"]["has_detector_result"] is True


def test_recover_answer_after_loop_returns_grounded_finish():
    reasoning_trace = [{"step": 3, "action": "finish"}]
    step = ReactStep(
        thought="Enough grounded context.",
        action="finish",
        action_input={},
        final_answer="Use the stored recommendation.",
        raw_content='{"action":"finish"}',
    )

    answer = recover_answer_after_loop(
        last_react_step=step,
        context_summary={"has_incident": True, "has_decision_support_result": True},
        reasoning_trace=reasoning_trace,
    )

    assert answer == "Use the stored recommendation."
    assert reasoning_trace[-1]["status"] == "finished_after_loop"


def test_normalize_operator_answer_formats_json_string_for_operator():
    answer = normalize_operator_answer(
        json.dumps(
            {
                "recommended_next_step": "Collect more evidence before taking disruptive action.",
                "why": "Important checks are still missing.",
                "missing_context": "Device context was unavailable for this session.",
            }
        )
    )

    assert answer.startswith("Collect more evidence before taking disruptive action.")
    assert "Why: Important checks are still missing." in answer
    assert "Missing context: Device context was unavailable for this session." in answer


def test_normalize_operator_answer_supports_summary_shape():
    answer = normalize_operator_answer(
        json.dumps(
            {
                "summary": "A user signed in and then launched a new virtual machine.",
                "explanation": "That sequence can indicate account misuse followed by resource creation.",
                "uncertainty": "Network telemetry was not checked.",
            }
        )
    )

    assert answer.startswith("A user signed in and then launched a new virtual machine.")
    assert "Why: That sequence can indicate account misuse followed by resource creation." in answer
    assert "Missing context: Network telemetry was not checked." in answer


def test_agent_can_load_mcp_cyber_context():
    request = SequencedRequest(
        [
            json.dumps({"thought": "Need incident context first.", "action": "load_incident", "action_input": {}}),
            json.dumps({"thought": "Need cyber context from MCP.", "action": "load_mcp_cyber_context", "action_input": {"query": "brute force login"}}),
            json.dumps({"thought": "Enough context.", "action": "finish", "final_answer": "ATT&CK context loaded."}),
        ]
    )
    agent = DecisionSupportAgent(
        repositories=FakeRepositories(include_decision_support=True),
        decision_support_service=FakeDecisionSupportService(),
        mcp_client=FakeMcpClient(),
        endpoint_config=OpenAICompatConfig(model="test-model", base_url="https://example.test/v1"),
    )
    result = agent.respond("INC-MCP", "What should I do next?", request_fn=request)
    assert result["answer"] == "ATT&CK context loaded."
    assert result["context_summary"]["has_mcp_cyber_context"] is True
    assert result["reasoning_trace"][1]["action"] == "load_mcp_cyber_context"

def test_load_agent_app_config_supports_openai_style_env_names():
    config = load_agent_app_config(
        {
            "OPENAI_MODEL": "gpt-4.1-mini",
            "OPENAI_BASE_URL": "https://endpoint.example/v1",
            "OPENAI_API_KEY": "secret",
            "OPENAI_CHAT_PATH": "/chat/completions",
            "AGENT_TEMPERATURE": "0.3",
            "AGENT_MAX_TOKENS": "512",
            "AGENT_MAX_REASONING_STEPS": "8",
        }
    )
    assert config == AgentAppConfig(
        model="gpt-4.1-mini",
        base_url="https://endpoint.example/v1",
        auth_mode="api_key",
        api_key="secret",
        chat_path="/chat/completions",
        temperature=0.3,
        max_tokens=512,
        max_reasoning_steps=8,
    )


def test_load_agent_app_config_can_use_codex_auth_token(tmp_path: Path):
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(
        json.dumps(
            {
                "tokens": {
                    "access_token": "codex-access-token",
                }
            }
        ),
        encoding="utf-8",
    )
    config = load_agent_app_config(
        {
            "OPENAI_MODEL": "gpt-4.1-mini",
            "OPENAI_BASE_URL": "https://api.openai.com/v1",
            "AGENT_USE_CODEX_AUTH": "1",
            "CODEX_AUTH_PATH": str(auth_path),
        }
    )
    assert config.api_key == "codex-access-token"


def test_load_agent_app_config_requires_base_url_when_not_mock():
    with pytest.raises(ValueError):
        load_agent_app_config({})


def test_query_incident_agent_supports_mock_mode(monkeypatch):
    fake_agent = DecisionSupportAgent(
        repositories=FakeRepositories(include_decision_support=True),
        decision_support_service=FakeDecisionSupportService(),
        mcp_client=None,
        endpoint_config=OpenAICompatConfig(model="gpt-5.4", base_url="mock://local/v1"),
    )

    monkeypatch.setattr("src.services.agent_app_service.build_postgres_backed_agent", lambda config, env=None: fake_agent)

    result = query_incident_agent(
        incident_id="INC-MOCK",
        user_query="What should I do next?",
        env={
            "AGENT_AUTH_MODE": "mock",
        },
    )

    assert result["incident_id"] == "INC-MOCK"
    assert result["model"] == "gpt-5.4"
    assert result["raw_response"]["mock_mode"] is True
    assert result["context_summary"]["has_incident"] is True
