from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Protocol

from src.logging_utils import get_logger
from .mcp_client import McpCyberContextClient
from .openai_compat import OpenAICompatConfig, create_chat_completion, extract_text_content
from .react import build_correction_message, build_observation_message, build_react_messages, parse_react_step
from .tools import AgentRuntimeState
from .context import AgentRepositoryBundle

logger = get_logger(__name__)


class DecisionSupportGenerator(Protocol):
    def generate_for_incident(self, incident_id: str, policy_version: str | None = None) -> dict[str, Any]: ...


def normalize_operator_answer(answer: str) -> str:
    stripped = answer.strip()
    if not stripped:
        return answer
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return answer
    if not isinstance(parsed, dict):
        return answer

    primary = str(
        parsed.get("recommended_next_step")
        or parsed.get("summary")
        or parsed.get("risk_assessment")
        or parsed.get("answer")
        or ""
    ).strip()
    why = str(parsed.get("why") or parsed.get("explanation") or "").strip()
    missing = str(parsed.get("missing_context") or parsed.get("uncertainty") or "").strip()
    alternatives = str(parsed.get("alternatives") or parsed.get("options") or "").strip()

    parts: list[str] = []
    if primary:
        parts.append(primary)
    if why:
        parts.append(f"Why: {why}")
    if missing:
        parts.append(f"Missing context: {missing}")
    if alternatives:
        parts.append(f"Alternatives: {alternatives}")
    return "\n\n".join(parts) if parts else answer


def recover_answer_after_loop(
    *,
    last_react_step,
    context_summary: dict[str, bool],
    reasoning_trace: list[dict[str, Any]],
) -> str | None:
    if last_react_step is None:
        return None
    if not any(context_summary.values()):
        return None
    if last_react_step.action != "finish":
        return None
    if reasoning_trace:
        reasoning_trace[-1]["status"] = "finished_after_loop"
    return last_react_step.final_answer or last_react_step.raw_content.strip()


@dataclass
class DecisionSupportAgent:
    repositories: AgentRepositoryBundle
    decision_support_service: DecisionSupportGenerator
    mcp_client: McpCyberContextClient | None
    endpoint_config: OpenAICompatConfig
    max_reasoning_steps: int = 6

    def respond(
        self,
        incident_id: str,
        user_query: str,
        policy_version: str | None = None,
        request_fn=None,
    ) -> dict[str, Any]:
        logger.info("Starting agent response incident_id=%s model=%s", incident_id, self.endpoint_config.model)
        runtime = AgentRuntimeState(
            repositories=self.repositories,
            decision_support_service=self.decision_support_service,
            incident_id=incident_id,
            policy_version=policy_version,
            mcp_client=self.mcp_client,
        )
        tools = runtime.build_tools()
        messages = build_react_messages(
            user_query=user_query,
            incident_id=incident_id,
            tool_specs=[{"name": tool.name, "description": tool.description} for tool in tools.values()],
        )
        reasoning_trace: list[dict[str, Any]] = []
        answer: str | None = None
        last_response: dict[str, Any] | None = None
        last_react_step = None

        for step_index in range(1, self.max_reasoning_steps + 1):
            logger.debug("Agent step start incident_id=%s step=%s", incident_id, step_index)
            response = create_chat_completion(
                self.endpoint_config,
                messages,
                request_fn=request_fn,
            )
            last_response = response
            content = extract_text_content(response)
            react_step = parse_react_step(content)
            last_react_step = react_step
            trace_item = {
                "step": step_index,
                "thought": react_step.thought,
                "action": react_step.action,
            }
            reasoning_trace.append(trace_item)
            logger.debug("Agent parsed step incident_id=%s step=%s action=%s", incident_id, step_index, react_step.action)

            if react_step.action == "finish":
                if not any(runtime.context_summary().values()):
                    messages.append({"role": "assistant", "content": react_step.raw_content})
                    messages.append({"role": "user", "content": build_correction_message("You must use at least one tool before finishing.")})
                    trace_item["status"] = "rejected"
                    logger.warning("Agent attempted to finish before loading context incident_id=%s step=%s", incident_id, step_index)
                    continue
                answer = normalize_operator_answer(react_step.final_answer or react_step.raw_content.strip())
                trace_item["status"] = "finished"
                logger.info("Agent finished incident_id=%s step=%s source=%s", incident_id, step_index, runtime.decision_support_source)
                break

            tool = tools.get(react_step.action)
            if tool is None:
                messages.append({"role": "assistant", "content": react_step.raw_content})
                messages.append({"role": "user", "content": build_correction_message(f"Unknown tool `{react_step.action}`.")})
                trace_item["status"] = "unknown_tool"
                logger.warning("Agent requested unknown tool incident_id=%s step=%s tool=%s", incident_id, step_index, react_step.action)
                continue

            try:
                observation = tool.handler(react_step.action_input)
            except Exception as exc:
                observation = {"error": str(exc)}
                trace_item["status"] = "tool_error"
                logger.exception("Agent tool failed incident_id=%s step=%s tool=%s", incident_id, step_index, tool.name)
            else:
                trace_item["status"] = "observed"
                logger.debug("Agent tool succeeded incident_id=%s step=%s tool=%s", incident_id, step_index, tool.name)
            trace_item["observation"] = observation
            messages.append({"role": "assistant", "content": react_step.raw_content})
            messages.append({"role": "user", "content": build_observation_message(tool.name, observation)})

        if answer is None:
            answer = recover_answer_after_loop(
                last_react_step=last_react_step,
                context_summary=runtime.context_summary(),
                reasoning_trace=reasoning_trace,
            )
            if answer is not None:
                answer = normalize_operator_answer(answer)
                logger.warning(
                    "Agent recovered final answer after loop incident_id=%s source=%s",
                    incident_id,
                    runtime.decision_support_source,
                )

        if answer is None:
            logger.error("Agent failed to finish incident_id=%s max_steps=%s", incident_id, self.max_reasoning_steps)
            raise RuntimeError(f"Agent did not finish within {self.max_reasoning_steps} reasoning steps.")

        logger.info("Agent response ready incident_id=%s steps=%s", incident_id, len(reasoning_trace))
        return {
            "incident_id": incident_id,
            "user_query": user_query,
            "answer": answer,
            "model": self.endpoint_config.model,
            "endpoint": self.endpoint_config.endpoint(),
            "decision_support_source": runtime.decision_support_source,
            "context_summary": runtime.context_summary(),
            "reasoning_trace": reasoning_trace,
            "raw_response": last_response,
        }
