from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LLMAdapter:
    responder = None
    prompt_version: str = "v1"
    tasks_requested: list[str] = field(default_factory=list)
    llm_used: bool = False
    parse_success: bool = True
    fallback_used: bool = True

    def run(self, task_type: str, payload: dict):
        self.tasks_requested.append(task_type)
        if self.responder is None:
            self.fallback_used = True
            return None
        self.llm_used = True
        for _ in range(2):
            response = self.responder(task_type, payload)
            if isinstance(response, dict):
                self.parse_success = True
                self.fallback_used = False
                return response
        self.parse_success = False
        self.fallback_used = True
        return None

    def trace(self) -> dict:
        return {
            "llm_used": self.llm_used,
            "prompt_version": self.prompt_version if self.llm_used else None,
            "tasks_requested": self.tasks_requested,
            "parse_success": self.parse_success,
            "fallback_used": self.fallback_used,
        }
