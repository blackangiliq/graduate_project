from tools.verify_dynamic_audit import verify_locations


def test_runtime_line_must_reference_the_observations_own_event():
    report = {"events": [{"id": 1}, {"id": 2}], "observations": [
        {"id": "test", "event_ids": [1], "evidence": {"line": 2}, "locations": []}]}
    result = verify_locations(report, {})
    assert result["issues"] == ["test: runtime line and event ID disagree"]


def test_verified_source_location_must_reproduce_full_unmasked_value():
    observation = {"id": "test", "value": "FixtureOnly", "event_ids": [1], "evidence": {"line": 1},
                   "locations": [{"file": "a.java", "line": 1, "column": 2,
                                  "end_column": 13, "verified": True}]}
    report = {"events": [{"id": 1}], "observations": [observation]}
    assert verify_locations(report, {"a.java": {"lines": ['"FixtureOnly"']}}) == {
        "issues": [], "verified_source_coordinates": 1}
    result = verify_locations(report, {"a.java": {"lines": ['"[redacted]"']}})
    assert result["verified_source_coordinates"] == 0
    assert "exact full value" in result["issues"][0]
