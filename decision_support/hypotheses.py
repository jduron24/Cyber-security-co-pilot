from __future__ import annotations

from .models import AlternativeHypothesis, Confidence


def build_hypotheses(incident: dict, detector_output: dict, coverage: dict, llm_adapter=None) -> list[AlternativeHypothesis]:
    hypotheses = _deterministic_hypotheses(detector_output, coverage)
    if llm_adapter is not None:
        expanded = llm_adapter.run(
            "hypothesis_expansion",
            {"incident": incident, "detector_output": detector_output, "coverage": coverage, "hypotheses": [h.__dict__ for h in hypotheses]},
        )
        if expanded and expanded.get("hypotheses"):
            hypotheses = _merge_hypothesis_phrasing(hypotheses, expanded["hypotheses"])
    return hypotheses[:4]


def _deterministic_hypotheses(detector_output: dict, coverage: dict) -> list[AlternativeHypothesis]:
    labels = set(detector_output.get("detector_labels") or [])
    missing = list(coverage.get("incompleteness_reasons") or [])
    top_signals = [signal.get("label", signal.get("feature", "signal")) for signal in detector_output.get("top_signals", [])[:3]]
    patterns = detector_output.get("retrieved_patterns") or []
    output = [
        AlternativeHypothesis(
            hypothesis_id="compromised_identity",
            label="Compromised identity or credential misuse",
            supporting_evidence=top_signals[:2] or ["Elevated detector signals"],
            weakening_evidence=["No confirmed remediation outcome yet"],
            missing_evidence=missing[:2],
            confidence=Confidence.MEDIUM,
        ),
        AlternativeHypothesis(
            hypothesis_id="misconfigured_automation",
            label="Misconfigured or broken automation",
            supporting_evidence=["Repeated or bursty control-plane activity"] + ([patterns[0]] if patterns else []),
            weakening_evidence=["Some signals also match abuse patterns"],
            missing_evidence=missing[:2],
            confidence=Confidence.LOW if "privilege_change" in labels else Confidence.MEDIUM,
        ),
    ]
    if "root_actor" in labels or any("root" in pattern.lower() for pattern in patterns):
        output.append(
            AlternativeHypothesis(
                hypothesis_id="high_privilege_operator_activity",
                label="High-privilege operator or root-driven activity",
                supporting_evidence=["Root or high-privilege activity was observed"],
                weakening_evidence=["Intent is not confirmed from CloudTrail alone"],
                missing_evidence=missing[:2],
                confidence=Confidence.MEDIUM,
            )
        )
    return output


def _merge_hypothesis_phrasing(base: list[AlternativeHypothesis], llm_hypotheses: list[dict]) -> list[AlternativeHypothesis]:
    output = []
    for index, hypothesis in enumerate(base):
        replacement = llm_hypotheses[index] if index < len(llm_hypotheses) else {}
        output.append(
            AlternativeHypothesis(
                hypothesis_id=hypothesis.hypothesis_id,
                label=str(replacement.get("label") or hypothesis.label),
                supporting_evidence=list(replacement.get("supporting_evidence") or hypothesis.supporting_evidence),
                weakening_evidence=list(replacement.get("weakening_evidence") or hypothesis.weakening_evidence),
                missing_evidence=list(replacement.get("missing_evidence") or hypothesis.missing_evidence),
                confidence=Confidence(str(replacement.get("confidence") or hypothesis.confidence.value)),
            )
        )
    return output
