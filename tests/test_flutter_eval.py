"""Tests for evaluation/flutter_eval.py: the scoring of the Flutter samples, the lab truth
files, the DVMA registry reader and the APK probe table. The thresholds are measured on the
samples only, so no lab, APK or external tool is needed."""
import importlib.util
import json
import os
import re
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from sca.cwe import canonical
from sca.models import Finding

ROOT = Path(__file__).resolve().parent.parent
TRUTH_DIR = ROOT / "evaluation" / "flutter_truth"
LABS = ROOT / "infected_project"
PROBE_DIR = os.environ.get("SCA_FLUTTER_PROBE_DIR", "")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ev = load_module(ROOT / "evaluation" / "flutter_eval.py", "flutter_eval_for_tests")


def finding(file, line, cwe, rule="RULE-1", rules=()):
    made = Finding(rule_id=rule, title="t", file=file, line=line, cwe=cwe)
    if rules:
        made.rule_ids = list(rules)
    return made


def truth(name):
    return json.loads((TRUTH_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def samples():
    return ev.evaluate_samples()


# ------------------------------------------------------------------ samples
def test_ground_truth_has_every_tag():
    tags = json.loads(ev.GROUND_TRUTH.read_text(encoding="utf-8"))["tags"]
    items = ev.load_ground_truth()
    assert sorted(i["tag"] for i in items) == sorted(tags)
    assert all(i["line"] >= 1 and (ev.VULN_DIR / i["file"]).is_file() for i in items)
    counts = ev.truth_counts(items)
    assert counts["weaknesses"] == sum(len(spec["cwe"]) for spec in tags.values())
    assert counts["decoys"] == sum(1 for spec in tags.values() if not spec["cwe"])


def test_anchor_resolution_matches_the_sample_rule(tmp_path):
    (tmp_path / "a.xml").write_text("<a\n  x=\"1\"\n/>\n<b\n  x=\"1\"\n/>\n", encoding="utf-8")
    assert ev.resolve_anchor(tmp_path, {"file": "a.xml", "text": 'x="1"'}) == 2
    assert ev.resolve_anchor(tmp_path, {"file": "a.xml", "text": 'x="1"', "near": "<b"}) == 5
    assert ev.resolve_anchor(tmp_path, {"file": "a.xml", "text": "y"}) == 0


def test_sample_thresholds(samples):
    configs = {r["name"]: r for r in samples["configs"]}
    main = configs[ev.MAIN_CONFIG]
    assert main["precision"] >= 0.9 and main["recall"] >= 0.9 and main["f1"] >= 0.9
    assert main["fp"] <= 3
    pattern = configs["Pattern rules + secrets (no Flutter checks)"]
    assert pattern["recall"] < main["recall"] - 0.2       # the Flutter checks find the rest
    strict = configs["All static, strict mode (confirmed only)"]
    assert strict["precision"] >= 0.95 and strict["tp"] <= main["tp"]
    for group in samples["groups"]:
        assert group["expected"] > 0 and group["recall"] >= 0.8, group


def test_missed_items_are_the_hard_ones(samples):
    main = next(r for r in samples["configs"] if r["name"] == ev.MAIN_CONFIG)
    assert all(m["hard"] for m in main["missed"]), main["missed"]


def test_safe_app_false_positives_are_named_by_folder():
    safe = [finding("lib/main.dart", 3, "CWE-319")]
    result = ev.score_samples([], safe, [{"tag": "D01", "file": "lib/main.dart", "line": 9,
                                          "cwe": ["CWE-89"], "also": [], "hard": False,
                                          "note": ""}])
    assert result["fp"] == 1 and result["fn"] == 1
    assert result["false_positives"][0]["file"] == "flutter_safe_app/lib/main.dart"


# ------------------------------------------------------------------ truth files
def test_lab_truth_files_are_well_formed():
    for name in ("ostorlab.json", "dvfa.json"):
        spec = truth(name)
        assert spec["_about"] and spec["lab"] and spec["unit"] and spec["items"], name
        ids = [item["id"] for item in spec["items"]]
        assert len(ids) == len(set(ids)), name
        for item in spec["items"]:
            assert item["title"] and item["note"] and isinstance(item["hard"], bool), item
            assert item["cwe"] and all(canonical(c) == c for c in item["cwe"]), item
            for place in item["locations"]:
                assert not place["file"].startswith("/") and "\\" not in place["file"], item
                assert isinstance(place["line"], int) and place["line"] >= 1, item
            assert item["locations"] or item["hard"], item     # only hard items lack a place


@pytest.mark.parametrize("name,file", [("Ostorlab-Insecure-Flutter", "ostorlab.json"),
                                       ("DVFA", "dvfa.json")])
def test_lab_locations_exist(name, file):
    lab = LABS / name
    if not lab.is_dir():
        pytest.skip("%s is not downloaded (python infected_project/fetch_labs.py)" % name)
    for item in truth(file)["items"]:
        for place in item["locations"]:
            lines = (lab / place["file"]).read_text(encoding="utf-8").splitlines()
            assert place["line"] <= len(lines) and lines[place["line"] - 1].strip(), item["id"]


def test_dvma_kinds_cover_every_category():
    spec = truth("dvma.json")
    assert set(spec["kinds"]) == {"code", "design", "runtime"}
    assert all(c["kind"] in spec["kinds"] and c["why"] for c in spec["categories"].values())
    registry = LABS / "DVMA" / "config" / "registry"
    if registry.is_dir():
        assert {m["category"] for m in ev.load_dvma(LABS / "DVMA")} == set(spec["categories"])


def test_probe_truth_is_well_formed():
    items = truth("apk_probe.json")["items"]
    ids = [item["id"] for item in items]
    assert len(ids) == len(set(ids))
    modes = {mode for mode, _name in ev.PROBE_BUILDS}
    probe_files = [p.relative_to(ev.PROBE_DIR).as_posix() for p in ev.PROBE_DIR.rglob("*")
                   if p.is_file()]
    for item in items:
        assert re.fullmatch(r"[PB]\d\d", item["id"]) and item["what"] and item["rules"], item
        assert canonical(item["cwe"]) == item["cwe"] and item["app"], item
        if item["id"].startswith("P"):          # planted in the source, present in every build
            assert item["source"] and "modes" not in item, item
            for glob in item["source"]:
                assert any(fnmatchcase(rel, glob) for rel in probe_files), (item, glob)
        else:                                   # a property of some build modes only
            assert "source" not in item and set(item["modes"]) <= modes, item


def test_probe_source_finds_every_planted_weakness():
    probe = ev.evaluate_probe(None)
    source = probe["runs"][0]
    assert [run["mode"] for run in probe["runs"]] == ["source"]
    assert probe["found"]["source"] == probe["planted"] == 16
    assert {s["state"] for s in source["items"].values()} <= {"found", "n/a"}


# ------------------------------------------------------------------ scoring
def test_score_lab_uses_cwe_and_a_one_line_window():
    spec = {"unit": "file", "items": [
        {"id": "A", "title": "a", "cwe": ["CWE-327"], "hard": False,
         "locations": [{"file": "x.dart", "line": 10}]},
        {"id": "B", "title": "b", "cwe": ["CWE-89"], "hard": True,
         "locations": [{"file": "x.dart", "line": 20}]},
        {"id": "C", "title": "c", "cwe": ["CWE-200"], "hard": True, "locations": []}]}
    found = [finding("x.dart", 11, "CWE-328"),       # folds into CWE-327, one line away
             finding("x.dart", 22, "CWE-89"),        # two lines away: not counted
             finding("y.dart", 20, "CWE-89")]        # other file
    result = ev.score_lab(spec, found)
    states = {item["id"]: item["found"] for item in result["items"]}
    assert states == {"A": True, "B": False, "C": False}
    assert result["all"] == {"items": 3, "found": 1, "recall": 0.333}
    assert result["not_hard"] == {"items": 1, "found": 1, "recall": 1.0}
    assert result["matched_findings"] == 1
    assert result["items"][0]["by"] == [{"file": "x.dart", "line": 11, "cwe": "CWE-327",
                                         "rules": ["RULE-1"]}]


def test_score_probe_states():
    items = [
        {"id": "P01", "what": "key", "cwe": "CWE-798", "rules": ["SECRET-*"],
         "source": ["lib/main.dart"], "app": ["lib/*/libapp.so"]},
        {"id": "P02", "what": "sql", "cwe": "CWE-89", "rules": ["DART-SQLI-*"],
         "source": ["lib/main.dart"], "app": ["lib/*/libapp.so"]},
        {"id": "B01", "what": "debug", "cwe": "CWE-489", "rules": ["FLUTTER-APP-001"],
         "app": ["_sca/build.txt"], "modes": ["debug"]}]
    found = [finding("lib/arm64-v8a/libapp.so", 5, "CWE-798", rules=["X-1", "SECRET-AWS-001"]),
             finding("lib/arm64-v8a/libapp.so", 9, "CWE-89", rule="FLUTTER-APP-008"),
             finding("_sca/build.txt", 2, "CWE-489", rule="FLUTTER-APP-001")]
    release = ev.score_probe(items, found, "release")
    assert {k: v["state"] for k, v in release["items"].items()} == {
        "P01": "found", "P02": "missed", "B01": "unexpected"}
    assert [o["rules"] for o in release["others"]] == [["FLUTTER-APP-008"]]
    debug = ev.score_probe(items, found, "debug")
    assert debug["items"]["B01"]["state"] == "found"
    source = ev.score_probe(items, [finding("lib/main.dart", 3, "CWE-89", "DART-SQLI-001")],
                            "source")
    assert {k: v["state"] for k, v in source["items"].items()} == {
        "P01": "missed", "P02": "found", "B01": "n/a"}


def test_dvma_registry_and_module_recall(tmp_path):
    categories = tmp_path / "config" / "registry" / "categories"
    (categories / "platform").mkdir(parents=True)
    (categories / "network.yaml").write_text(
        "network:\n  vulnerabilities:\n  - id: cleartext\n    cwe: [CWE-319]\n"
        "  - id: pinning\n    cwe: [CWE-295]\n", encoding="utf-8")
    (categories / "platform" / "01_core.yaml").write_text(
        "platform:\n  vulnerabilities:\n  - id: webview\n    cwe: [CWE-749, CWE-1204]\n",
        encoding="utf-8")
    (tmp_path / "config" / "registry" / "meta.yaml").write_text(
        "category_order:\n- platform\n- network\n", encoding="utf-8")
    modules = ev.load_dvma(tmp_path)
    assert [(m["category"], m["id"]) for m in modules] == [
        ("network", "cleartext"), ("network", "pinning"), ("platform", "webview")]
    assert modules[2]["cwe"] == ["CWE-327", "CWE-749"]
    assert modules[0]["folder"] == "lib/modules/network/cleartext/"
    assert ev.category_order(tmp_path) == ["platform", "network"]
    found = [finding("lib/modules/network/cleartext/a.dart", 4, "CWE-319"),
             finding("lib/modules/network/pinning/b.dart", 7, "CWE-798"),
             finding("android/app/src/main/AndroidManifest.xml", 9, "CWE-926", "ANDROID-M")]
    result = ev.score_dvma(modules, found, {"network": {"kind": "code"},
                                            "platform": {"kind": "design"}})
    assert result["total"] == {"name": "all", "modules": 3, "found": 1, "any": 2,
                               "recall": 0.333}
    assert [(c["name"], c["found"], c["any"]) for c in result["categories"]] == [
        ("network", 1, 2), ("platform", 0, 0)]
    assert [(k["name"], k["modules"]) for k in result["kinds"]] == [("code", 2), ("design", 1)]
    assert result["outside"] == {"ANDROID-M": 1}


# ------------------------------------------------------------------ command line
@pytest.mark.parametrize("item_id,collection,field,address", [
    ("I14", "endpoints", "url", "https://maps.shop-probe.example/geocode?api_key="),
    ("I15", "paths", "path", "/orders/$orderId/receipt.pdf?access_token=$token"),
    ("I15", "paths", "path", "/receipt.pdf?access_token="),
])
def test_query_template_truth_requires_presence_location_and_no_false_secret_alert(
        item_id, collection, field, address):
    match = next(i["match"] for i in truth("api_probe.json")["items"] if i["id"] == item_id)
    item = {field: address, "alerts": [], "locations": [{"file": "lib/main.dart", "line": 28}]}
    assert ev.inventory_match(match, {collection: [item]})
    assert not ev.inventory_match(match, {collection: []})
    assert not ev.inventory_match(match, {collection: [{**item, "locations": []}]})
    assert not ev.inventory_match(match, {collection: [{**item, "locations": [{"file": "a.dart", "line": 0}]}]})
    assert not ev.inventory_match(match, {collection: [{**item, "alerts": ["secret_in_url"]}]})
    assert not ev.inventory_match(match, {collection: [{**item, field: address + "literalValue"}]})
    assert not ev.inventory_match(match, {collection: [{**item, field: address.replace("?", "/wrong?")}]})


def test_main_writes_both_reports(tmp_path):
    out = tmp_path / "flutter_results"
    assert ev.main(["--no-labs", "--apks", "", "--api-apks", "", "--out", str(out)]) == 0
    data = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    assert data["labs"] == {} and data["probe"]["apk_folder_given"] is False
    text = out.with_suffix(".md").read_text(encoding="utf-8")
    for heading in ("## 1. Flutter samples", "## 2. Labs",
                    "## 3. What survives compilation: the APK probe"):
        assert heading in text
    assert "| P16 | Release build signed with the debug key | CWE-1188 | found |" in text
    assert "## 4. API and key inventory: the API probe" in text
    inventory = data["inventory"]
    assert [run["mode"] for run in inventory["runs"]] == ["source"]
    assert inventory["found"]["source"] == inventory["expected"]["source"]
    assert "| I11 | ngrok tunnel | found |" in text and "| I01 | Stripe secret key" in text


def test_main_rejects_a_folder_without_builds(tmp_path):
    with pytest.raises(SystemExit) as stop:
        ev.main(["--no-labs", "--apks", str(tmp_path), "--out", str(tmp_path / "r")])
    assert stop.value.code == 2
    assert not (tmp_path / "r.json").exists()


@pytest.mark.skipif(not PROBE_DIR, reason="set SCA_FLUTTER_PROBE_DIR to the probe builds")
def test_probe_builds_keep_the_planted_weaknesses():
    probe = ev.evaluate_probe(Path(PROBE_DIR))
    states = {run["mode"]: run["items"] for run in probe["runs"]}
    assert set(states) >= {"source", "debug", "release", "release_obf"}
    assert probe["found"]["debug"] == probe["planted"]
    for mode in ("release", "release_obf", "aab"):
        if mode in states:
            assert probe["found"][mode] >= probe["planted"] - 2, mode
    for mode, items in states.items():
        assert "unexpected" not in {s["state"] for s in items.values()}, mode
