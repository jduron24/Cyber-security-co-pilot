from decision_support.completeness import build_completeness_assessment


def test_low_completeness_always_warns():
    result = build_completeness_assessment(
        {"completeness_level": "low", "incompleteness_reasons": ["Missing source"], "checks": [], "missing_sources": []}
    )
    assert result.warning
    assert result.level.value == "low"
