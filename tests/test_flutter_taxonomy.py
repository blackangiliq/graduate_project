"""Tests for the weakness taxonomy of the Flutter / Android module: the knowledge-base entries
and folds of its CWE ids, the OWASP Mobile Top 10 (2024) and MASVS mapping, the mobile fields
that merge fills in, and the app facts of a scan in storage."""
import json
import sqlite3
from pathlib import Path

import pytest

from sca import merge
from sca.cwe import (FLOW_CWES, MASVS_GROUPS, MOBILE_BY_CWE, MOBILE_TOP10_2024, canonical,
                     info, masvs_name, mobile_name)
from sca.models import Finding, ScanResult
from sca.storage import Storage

# section 2.3 of the module design
ALREADY_IN_KB = [22, 78, 79, 89, 95, 295, 319, 327, 338, 347, 489, 494, 502, 601, 693, 732,
                 798, 862]
NEW_ENTRIES = [94, 200, 215, 250, 284, 287, 311, 312, 322, 530, 532, 552, 749, 829, 922, 926, 939,
               1021, 1104, 1188, 1357, 1395]
FOLDS = {260: 798, 23: 22, 331: 338, 780: 327, 1204: 327, 297: 295,
         259: 798, 321: 798, 540: 798, 326: 327, 328: 327, 916: 327, 330: 338}

# section 2.4 of the module design
MOBILE_TABLE = [
    ("M1", "MASVS-STORAGE", [798]),
    ("M2", "MASVS-CODE", [494, 1104, 1357, 1395]),
    ("M3", "MASVS-AUTH", [287, 347, 862, 284, 639]),
    ("M3", "MASVS-PLATFORM", [939]),
    ("M4", "MASVS-CODE", [89, 78, 22, 94, 95, 601, 643, 943, 90, 98, 1336, 502, 611]),
    ("M4", "MASVS-PLATFORM", [79, 749]),
    ("M5", "MASVS-NETWORK", [295, 319, 322, 829]),
    ("M6", "MASVS-PRIVACY", [200, 359]),
    ("M7", "MASVS-RESILIENCE", [693, 489, 215]),
    ("M8", "MASVS-PLATFORM", [1188, 926, 1021, 250, 732, 276, 942, 614, 1004]),
    ("M8", "MASVS-STORAGE", [552]),
    ("M9", "MASVS-STORAGE", [312, 311, 922, 530, 532]),
    ("M10", "MASVS-CRYPTO", [327, 338]),
]


def cwe(number):
    return "CWE-%d" % number


def arabic(text):
    return any("\u0600" <= ch <= "\u06ff" for ch in text)


def finding(**kw):
    base = dict(rule_id="R1", title="t", file="lib/main.dart", line=10, severity="medium",
                cwe="CWE-319", confidence=0.6, engines=["rules"], snippet="http.get(url)")
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------------------------ knowledge base
@pytest.mark.parametrize("number", ALREADY_IN_KB + NEW_ENTRIES + sorted(FOLDS))
def test_every_module_cwe_has_english_and_arabic_text(number):
    en, ar = info(cwe(number)), info(cwe(number), "ar")
    assert en["name"] != en["cwe"] and en["owasp"] != "Other"
    assert en["description"] and en["fix"] and ar["description"] and ar["fix"]
    assert arabic(ar["description"]) and arabic(ar["fix"])
    assert not arabic(en["description"]) and not arabic(en["fix"])
    assert en["url"] == "https://cwe.mitre.org/data/definitions/%s.html" % en["cwe"][4:]


@pytest.mark.parametrize("number", NEW_ENTRIES + [276, 359])
def test_new_cwes_have_an_entry_of_their_own(number):
    assert canonical(cwe(number)) == cwe(number)
    assert info(cwe(number))["cwe"] == cwe(number)


def test_folds():
    for source, target in FOLDS.items():
        assert canonical(cwe(source)) == cwe(target)
    # cleartext storage is no longer reported as a hard-coded credential
    assert canonical("CWE-312") == "CWE-312"
    assert info("CWE-312")["name"] != info("CWE-798")["name"]
    # dynamic code loading has its own text, and keeps the data-flow rule of code injection
    assert canonical("CWE-94") == "CWE-94" and canonical("CWE-96") == "CWE-95"
    assert info("CWE-94")["description"] != info("CWE-95")["description"]
    assert {"CWE-94", "CWE-95"} <= FLOW_CWES


def test_owasp_2021_category_of_the_new_entries():
    expected = {"A01": [200, 276, 284, 359, 552, 922], "A03": [94], "A04": [311, 312, 1021],
                "A05": [215, 250, 530, 749, 926, 939, 1188], "A06": [1104, 1357, 1395],
                "A07": [287], "A08": [829], "A09": [532], "A02": [322]}
    for key, numbers in expected.items():
        for number in numbers:
            assert info(cwe(number))["owasp"].startswith(key + ":2021 "), number


# ------------------------------------------------------------------ mobile taxonomy
def test_mobile_mapping_is_the_design_table():
    table = {cwe(n): (risk, group) for risk, group, numbers in MOBILE_TABLE for n in numbers}
    assert MOBILE_BY_CWE == table
    assert {risk for risk, _ in table.values()} == set(MOBILE_TOP10_2024)
    assert {group for _, group in table.values()} == set(MASVS_GROUPS)
    for key in table:
        assert canonical(key) == key                       # a folded key would never match
        assert info(key)["description"] and info(key, "ar")["description"]


def test_taxonomy_names_in_english_and_arabic():
    assert list(MOBILE_TOP10_2024) == ["M%d" % n for n in range(1, 11)]
    assert MOBILE_TOP10_2024["M5"][0] == "Insecure Communication"
    assert len(MASVS_GROUPS) == 8 and all(key.startswith("MASVS-") for key in MASVS_GROUPS)
    for table in (MOBILE_TOP10_2024, MASVS_GROUPS):
        for english, arabic_name in table.values():
            assert english and not arabic(english) and arabic(arabic_name)
    assert mobile_name("M9") == "Insecure Data Storage"
    assert mobile_name("M9", "ar") == MOBILE_TOP10_2024["M9"][1]
    assert masvs_name("MASVS-NETWORK") == "Network Communication"
    assert masvs_name("MASVS-NETWORK", "ar") == MASVS_GROUPS["MASVS-NETWORK"][1]
    assert mobile_name("") == mobile_name("M11") == masvs_name("MASVS-X") == ""


def test_info_returns_the_localized_mobile_classification():
    en, ar = info("CWE-319"), info("CWE-319", "ar")
    assert set(en) == {"cwe", "name", "owasp", "description", "fix", "url",
                       "owasp_mobile", "owasp_mobile_name", "masvs", "masvs_name"}
    assert (en["owasp_mobile"], en["owasp_mobile_name"]) == ("M5", "Insecure Communication")
    assert (en["masvs"], en["masvs_name"]) == ("MASVS-NETWORK", "Network Communication")
    assert (ar["owasp_mobile"], ar["masvs"]) == ("M5", "MASVS-NETWORK")
    assert arabic(ar["owasp_mobile_name"]) and arabic(ar["masvs_name"])
    # folded ids take the class of the id they fold into
    assert (info("CWE-260")["owasp_mobile"], info("CWE-260")["masvs"]) == ("M1", "MASVS-STORAGE")
    assert info("CWE-1204")["masvs"] == "MASVS-CRYPTO" and info("CWE-297")["owasp_mobile"] == "M5"
    # outside the mapping, and unknown or empty ids: empty values, same keys
    for value in ("CWE-120", "CWE-99999", ""):
        data = info(value, "ar")
        assert set(data) == set(en)
        assert data["owasp_mobile"] == data["owasp_mobile_name"] == ""
        assert data["masvs"] == data["masvs_name"] == ""


# ------------------------------------------------------------------ merge
def test_merge_fills_the_mobile_fields_only_for_mobile_targets():
    plain = merge.merge_findings([finding()])
    assert (plain[0].owasp_mobile, plain[0].masvs) == ("", "")
    assert plain[0].owasp.startswith("A02") and plain[0].description

    mobile = merge.merge_findings([
        finding(), finding(cwe="CWE-260", line=30), finding(cwe="CWE-120", line=50),
    ], lang="ar", mobile=True)
    fields = {f.cwe: (f.owasp_mobile, f.masvs) for f in mobile}
    assert fields == {"CWE-319": ("M5", "MASVS-NETWORK"), "CWE-798": ("M1", "MASVS-STORAGE"),
                      "CWE-120": ("", "")}
    assert all(f.owasp for f in mobile)
    assert arabic(next(f for f in mobile if f.cwe == "CWE-319").description)


def test_merge_still_combines_engines_for_mobile_targets():
    merged = merge.merge_findings([
        finding(engines=["flutter"], confidence=0.8),
        finding(engines=["rules"], confidence=0.6, line=11, severity="high"),
    ], mobile=True)
    assert len(merged) == 1
    assert merged[0].engines == ["flutter", "rules"] and merged[0].severity == "high"
    assert merged[0].confidence == pytest.approx(1 - 0.2 * 0.4)
    assert (merged[0].owasp_mobile, merged[0].masvs) == ("M5", "MASVS-NETWORK")


def test_mobile_merge_changes_nothing_but_the_mobile_fields():
    def batch():
        return [finding(), finding(engines=["secrets"], line=11, confidence=0.9),
                finding(cwe="CWE-259", line=20), finding(cwe="CWE-94", line=30),
                finding(cwe="CWE-1395", file="pubspec.lock", line=4, engines=["flutter"]),
                finding(cwe="CWE-120", line=50, snippet="strcpy(buf, src); // nosec")]

    def without_mobile_fields(findings):
        return [{k: v for k, v in f.to_dict().items() if k not in ("owasp_mobile", "masvs")}
                for f in findings]

    for lang in ("en", "ar"):
        plain = merge.merge_findings(batch(), lang)
        mobile = merge.merge_findings(batch(), lang, mobile=True)
        assert len(plain) == 4                              # one merge, one suppressed
        assert without_mobile_fields(plain) == without_mobile_fields(mobile)
        assert all(f.owasp_mobile == f.masvs == "" for f in plain)
        assert all(f.owasp_mobile and f.masvs for f in mobile)


def test_cleartext_storage_is_not_merged_with_hard_coded_credentials():
    merged = merge.merge_findings([
        finding(cwe="CWE-312", engines=["rules"], snippet="prefs.setString('token', t)"),
        finding(cwe="CWE-798", engines=["secrets"], snippet="prefs.setString('token', t)"),
    ], mobile=True)
    assert sorted((f.cwe, f.owasp_mobile) for f in merged) == [("CWE-312", "M9"),
                                                               ("CWE-798", "M1")]
    assert len({f.description for f in merged}) == 2


# ------------------------------------------------------------------ models and storage
def test_new_fields_default_to_empty_and_reach_the_json():
    plain = finding()
    assert plain.owasp_mobile == "" and plain.masvs == ""
    data = finding(owasp_mobile="M5", masvs="MASVS-NETWORK").to_dict()
    assert (data["owasp_mobile"], data["masvs"]) == ("M5", "MASVS-NETWORK")
    old = {k: v for k, v in data.items() if k not in ("owasp_mobile", "masvs")}
    assert Finding.from_dict(old).masvs == ""

    first, second = ScanResult(target="a"), ScanResult(target="b")
    first.app["kind"] = "apk"
    assert second.app == {} and first.to_dict()["app"] == {"kind": "apk"}


def app_facts():
    return {
        "kind": "apk", "name": "release.apk", "size_bytes": 16_000_000, "flutter": True,
        "package": "com.example.vuln_probe", "min_sdk": 21, "target_sdk": None,
        "build_mode": "release", "abis": ["arm64-v8a", "armeabi-v7a"], "obfuscated": False,
        "signing": {"schemes": ["v2"], "verified": None, "certificates": [
            {"subject": "CN=Android Debug, O=Android, C=US", "debug": True}]},
        "permissions": [{"name": "android.permission.CAMERA", "dangerous": True}],
        "warnings": ["تحذير: duplicate entry name res/a.xml"],
    }


def test_scan_with_app_facts_survives_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    storage = Storage()
    assert Path(storage.path) == tmp_path / "data" / "sca.db"
    result = ScanResult(target="release.apk", files_scanned=3, lines_scanned=120,
                        app=app_facts(), findings=merge.merge_findings([
                            finding(file="AndroidManifest.xml", cwe="CWE-530", line=7),
                        ], mobile=True))

    loaded = storage.load_scan(storage.save_scan(result))
    assert loaded.app == app_facts()
    assert (loaded.findings[0].owasp_mobile, loaded.findings[0].masvs) == ("M9", "MASVS-STORAGE")
    assert loaded.findings[0].fingerprint == result.findings[0].fingerprint
    assert loaded.to_dict()["app"] == result.to_dict()["app"]


def test_scan_stored_before_the_mobile_fields_still_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("SCA_DATA_DIR", str(tmp_path / "data"))
    storage = Storage()
    old = ScanResult(target="samples/vulnerable_app", findings=[finding()]).to_dict()
    del old["app"]
    for item in old["findings"]:
        del item["owasp_mobile"], item["masvs"]
    with sqlite3.connect(storage.path) as conn:
        scan_id = conn.execute(
            "INSERT INTO scans (target, started_at, result_json) VALUES (?, ?, ?)",
            (old["target"], "2025-01-01 10:00:00", json.dumps(old))).lastrowid
    conn.close()

    loaded = storage.load_scan(scan_id)
    assert loaded.app == {} and loaded.target == "samples/vulnerable_app"
    assert (loaded.findings[0].owasp_mobile, loaded.findings[0].masvs) == ("", "")
    assert loaded.findings[0].cwe == "CWE-319"
