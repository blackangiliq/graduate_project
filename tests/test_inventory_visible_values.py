"""Complete inventory values for the dashboard, with unchanged default reports.

All values below are invented test data and are never sent to a service.
"""
from pathlib import Path

import pytest

from sca.flutter import inventory
from sca.models import Finding
from sca.walker import SourceFile, mask_secret


def source(rel, text, language="config"):
    return SourceFile(Path(rel), rel, language, text)


def test_visible_key_keeps_complete_value_without_changing_analysis_inputs():
    value = "local-value-" + "aB0123456789" * 50
    sf = source("app.properties", f'api_key="{value}"')
    sf.secret_values = [value]
    sf.secret_hits = [(1, "SECRET-HARDCODED-001", value, "Hard-coded secret", "high")]
    finding = Finding("SECRET-HARDCODED-001", "Hard-coded secret", sf.rel, 1,
                      cwe="CWE-798", snippet=sf.line_text(1), engines=["secrets"])
    fingerprint = finding.fingerprint
    before = inventory.build(None, [sf], [finding])

    shown = inventory.build(None, [sf], [finding], reveal_values=True)

    assert shown["values_visible"] is True
    assert shown["keys"][0]["value"] == value
    assert shown["keys"][0]["locations"] == [{"file": sf.rel, "line": 1}]
    assert "values_visible" not in before
    assert before["keys"][0]["value"] == mask_secret(value)
    assert inventory.build(None, [sf], [finding]) == before
    assert sf.secret_values == [value]
    assert value not in finding.snippet
    assert finding.fingerprint == fingerprint


def test_visible_inventory_preserves_config_and_env_values():
    token = "client-value-" + "aB0123456789" * 20
    project = "project-" + "p" * 245
    address = "https://api.inventory-visible.example/status?api_key=" + token
    config = source("config.json", f'{{"facebook_client_token":"{token}","project_id":"{project}"}}')
    env = source("assets/.env", f"APP_SECRET={token}\nAPI_URL={address}\n")
    default = inventory.build(None, [config, env], [])
    shown = inventory.build(None, [config, env], [], reveal_values=True)

    assert {item["name"]: item["value"] for item in shown["config"]} == {
        "facebook_client_token": token, "project_id": project}
    assert {item["name"]: item["value"] for item in shown["env"]} == {
        "APP_SECRET": token, "API_URL": address}
    assert token not in {item["value"] for item in default["config"]}
    assert token not in {item["value"] for item in default["env"]}
    assert project not in {item["value"] for item in default["config"]}


def test_visible_urls_keep_distinct_values_that_mask_to_the_same_text():
    first, second = "ABCD" + "xA9Z" * 4 + "YZ", "ABCD" + "mB8K" * 4 + "YZ"
    assert mask_secret(first) == mask_secret(second)
    addresses = ["https://api.inventory-visible.example/status?token=" + value
                 for value in (first, second)]
    sf = source("addresses.txt", "\n".join(addresses))

    default = inventory.build(None, [sf], [])
    shown = inventory.build(None, [sf], [], reveal_values=True)

    assert len(default["endpoints"]) == 1
    assert {item["url"] for item in shown["endpoints"]} == set(addresses)
    assert {item["locations"][0]["line"] for item in shown["endpoints"]} == {1, 2}
    assert all(item["count"] == 1 for item in shown["endpoints"])


def test_visible_endpoints_and_calls_keep_long_values_and_dynamic_arguments():
    token = "observed-" + "aB0123456789" * 45
    address = "https://api.inventory-visible.example/status?access_token=" + token
    expression = "Uri.https('api.inventory-visible.example', '/status', {'token': '" + token + "'})"
    sf = source("lib/api.dart", f"http.get('{address}');\n"
                f"http.post(Uri.parse('{address}'));\nhttp.get({expression});", "dart")

    shown = inventory.build(None, [sf], [], reveal_values=True)

    assert {item["url"] for item in shown["endpoints"]} == {address}
    assert [item["target"] for item in shown["calls"]] == [address, address, expression]
    assert [item["line"] for item in shown["calls"]] == [1, 2, 3]
    assert inventory.build(None, [sf], [])["endpoints"][0]["url"] != address


def test_visible_paths_keep_the_complete_query_value():
    token = "observed-path-value-0123456789"
    path = "/api/v1/status?access_token=" + token
    sf = source("lib/api.dart", f"dio.get('{path}');", "dart")
    shown = inventory.build(None, [sf], [], reveal_values=True)
    default = inventory.build(None, [sf], [])
    assert shown["paths"][0]["path"] == path
    assert shown["calls"][0]["target"] == path
    assert token not in default["paths"][0]["path"]


def test_visible_dynamic_call_does_not_treat_quoted_punctuation_as_code():
    expression = "Uri.https('api.inventory-visible.example', '/status', {'token': 'local)token,value'})"
    sf = source("lib/api.dart", f"http.get({expression});", "dart")
    shown = inventory.build(None, [sf], [], reveal_values=True)
    assert shown["calls"][0]["target"] == expression


def test_visible_inventory_keeps_item_limits_and_reports_omissions(monkeypatch):
    monkeypatch.setattr(inventory, "MAX_VISIBLE_ITEMS", 2)
    sf = source("addresses.txt", "\n".join(
        f"https://api.inventory-visible.example/item/{i}" for i in range(4)))
    shown = inventory.build(None, [sf], [], reveal_values=True)
    assert len(shown["endpoints"]) == 2
    assert shown["summary"]["endpoints"] == 4
    assert shown["truncated"]["endpoints"] == 2


@pytest.mark.parametrize("visible, label", [(False, "Value (masked)"), (True, "Value")])
def test_inventory_key_table_labels_match_value_representation(visible, label):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_string(
        "from sca.ui.app_panel import _key_rows\n"
        "_key_rows([{'value': 'local-inventory-value'}], lambda text: text, {}, "
        f"values_visible={visible!r})\n").run()
    assert not app.exception
    assert label in app.dataframe[0].value.columns
    assert any(("shown in full" if visible else "Values are masked") in caption.value
               for caption in app.caption)
