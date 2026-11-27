"""The validation driver must not confuse missing static evidence with generation."""
from tools.audit_dynamic_apps import compare_observations, url_key


def test_comparison_distinguishes_observation_types_and_missing_static_evidence():
    static = {"app": {"apis": {"endpoints": [{"url": "https://api.example.test/v1?a=1&b=2",
                                               "host": "api.example.test"}],
                                "keys": [{"value": "FixtureOnlyValue1"}]}}}
    capture = {"observations": [
        {"id": "url-1", "kind": "url", "value": "HTTPS://API.EXAMPLE.TEST/v1?a=1&b=2",
         "locations": [{"verified": True}], "evidence": {"file": "_runtime/test/events.jsonl", "line": 1}},
        {"id": "url-2", "kind": "url", "value": "https://api.example.test/session/123"},
        {"id": "host", "kind": "host", "value": "API.EXAMPLE.TEST"},
        {"id": "key-1", "kind": "credential", "value": "FixtureOnlyValue1"},
        {"id": "key-2", "kind": "crypto_key", "value": "a1b2c3"},
        {"id": "connection", "kind": "connection", "value": "192.0.2.1:443"},
    ]}
    report = compare_observations(capture, static)
    by_id = {item["observation_id"]: item for item in report["observations"]}
    assert by_id["url-1"]["static_inventory_exact_match"] is True
    assert by_id["url-1"]["verified_source_locations"] == 1
    assert by_id["url-1"]["has_runtime_event_location"] is True
    assert by_id["url-2"]["comparison"] == "not_found_in_static_inventory"
    assert by_id["host"]["static_inventory_exact_match"] is True
    assert by_id["key-1"]["static_inventory_exact_match"] is True
    assert by_id["key-2"]["comparison"] == "not_found_in_static_inventory"
    assert by_id["connection"]["static_inventory_exact_match"] is None
    assert "does not prove runtime generation" in report["interpretation"]
    assert report["counts"] == {"also_in_static_inventory": 3,
                                "not_found_in_static_inventory": 2, "not_compared": 1}


def test_exact_comparison_does_not_equate_different_query_values_or_paths():
    assert url_key("https://api.example.test/Token?a=X") != url_key("https://api.example.test/token?a=X")
    assert url_key("https://api.example.test/?a=X") != url_key("https://api.example.test/?a=Y")
    assert url_key("https://api.example.test/?a=%2F") != url_key("https://api.example.test/?a=/")
    assert url_key("https://User:Pass@API.EXAMPLE.TEST/") == "https://User:Pass@api.example.test/"
    assert url_key("https://User:Pass@api.example.test/") != url_key("https://user:pass@api.example.test/")
    assert url_key("https://api.example.test/?a=1&amp;b=2") != url_key("https://api.example.test/?a=1&b=2")


def test_failed_capture_remains_empty_without_using_static_values_as_runtime_events():
    result = compare_observations({"status": "failed", "observations": []},
                                  {"app": {"apis": {"keys": [{"value": "FixtureOnlyValue1"}]}}})
    assert result["observations"] == []
    assert result["counts"] == {}
