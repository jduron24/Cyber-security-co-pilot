from decision_support.models import validate_coverage_input, validate_incident_input


def test_valid_incident_input_passes():
    incident = {"incident_id": "INC-1", "title": "Test", "summary": "Example"}
    assert validate_incident_input(incident)["incident_id"] == "INC-1"


def test_invalid_coverage_enum_fails():
    coverage = {"completeness_level": "bad", "incompleteness_reasons": [], "checks": []}
    try:
        validate_coverage_input(coverage)
    except Exception as exc:
        assert "Invalid completeness_level" in str(exc)
    else:
        raise AssertionError("Expected invalid completeness_level to fail")
