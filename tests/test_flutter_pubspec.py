"""Tests for the pub dependency module of the Flutter / Android analysis: pub version order and
constraints, the shipped advisory data, pubspec.yaml and pubspec.lock parsing, and the
FLUTTER-PUB-* findings of the audit."""
import json
import time
from pathlib import Path

import pytest

from sca.flutter import pubspec
from sca.flutter.pubspec import (Version, advisories_for, affecting_advisories, audit_packages,
                                 audit_project, in_range, load_advisories, load_discontinued,
                                 parse_constraint, parse_lock, parse_pubspec, parse_version)
from sca.walker import SourceFile

DATA = Path(pubspec.__file__).resolve().parent / "data"


def v(text):
    version = parse_version(text)
    assert version is not None, text
    return version


def source(rel, text, secrets=()):
    sf = SourceFile(Path(rel), rel, "config", text)
    sf.secret_values = list(secrets)
    return sf


def line_of(text, line_text):
    """1-based number of the first line that is exactly `line_text` (indentation included)."""
    return text.splitlines().index(line_text) + 1


def line_starting(text, prefix):
    return [n for n, line in enumerate(text.splitlines(), 1) if line.startswith(prefix)][0]


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def at(findings, rule_id, line):
    hits = [f for f in findings if f.rule_id == rule_id and f.line == line]
    assert len(hits) == 1, (rule_id, line, [(f.rule_id, f.line) for f in findings])
    return hits[0]


# ------------------------------------------------------------------ versions
# osv.dev's pub ordering test list: pre-release < release, build metadata after the release
ORDERED = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1",
           "1.0.0-rc.1+build.1", "1.0.0", "1.0.0+0.3.7", "1.3.7+build", "1.3.7+build.2.b8f12d7",
           "1.3.7+build.11.e0f985a", "2.0.0", "2.1.0", "2.2.0", "2.11.0", "2.11.1"]


def test_version_order_follows_pub():
    for i, a in enumerate(ORDERED):
        for j, b in enumerate(ORDERED):
            assert (v(a) < v(b)) == (i < j), (a, b)
            assert (v(a) == v(b)) == (i == j), (a, b)
    assert sorted(reversed(ORDERED), key=v) == ORDERED


@pytest.mark.parametrize("lower, higher", [
    ("0.3.5", "0.3.5+1"),                    # jose: fixed in 0.3.5+1
    ("0.3.5+1", "0.3.6"),
    ("0.8.12+17", "0.8.12+18"),              # image_picker_android: fixed in 0.8.12+18
    ("0.8.12+9", "0.8.12+18"),               # build numbers compare as numbers
    ("0.8.5+6", "0.8.12+17"),
    ("0.5.1", "0.5.1+12"),                   # file_selector_android
    ("1.0.0-dev.28", "1.0.0-dev.29"),        # agent_dart: fixed in 1.0.0-dev.29
    ("1.0.0-dev.3", "1.0.0-dev.28"),
    ("0.1.24+1", "1.0.0-dev.29"),            # its latest stable release is still affected
    ("1.0.0-dev.29", "1.0.0"),
    ("2.0.0-beta1", "2.0.0-prev1"),          # dio_http2_adapter pre-releases
    ("2.0.0-prev1", "2.0.0"),
    ("4.0.0-beta.0", "4.0.0-rc.1"),          # serverpod lines
    ("3.5.0-beta.12", "3.5.0"),
    ("1.0.0-0", "1.0.0-alpha"),              # numbers sort before words
])
def test_real_advisory_versions_order(lower, higher):
    assert v(lower) < v(higher) and v(higher) > v(lower) and v(lower) != v(higher)


def test_version_parsing_and_canonical_text():
    assert v("01.02.03-01.dev+pre.02") == v("1.2.3-1.dev+pre.2")
    assert str(v("01.02.03-01.dev+pre.02")) == "1.2.3-1.dev+pre.2"
    assert str(v(" 0.3.5+1 ")) == "0.3.5+1"
    assert v("1.0.0-dev.29").is_prerelease and not v("0.3.5+1").is_prerelease
    assert v("1.2.3").next_breaking() == v("2.0.0") and v("0.1.2").next_breaking() == v("0.2.0")
    for bad in ["", "1.2", "v1.2.3", "1.2.3.4", "1.2.3-", "1.2.3+", "1.2.3-a..b", "x",
                "1.2.3 4", "9" * 200, None, 123, 1.5]:
        assert parse_version(bad) is None, bad


def test_huge_identifiers_stay_text_like_pub():
    # pub turns an all-digit identifier into a number only when it fits in 64 bits
    largest, too_big = v("1.0.0-9223372036854775807"), v("1.0.0-9223372036854775808")
    assert largest.pre == (9223372036854775807,) and too_big.pre == ("9223372036854775808",)
    assert v("1.0.0-5") < largest < too_big < v("1.0.0-alpha")


def test_only_ascii_digits_make_numbers():
    # "²".isdigit() is true but int() refuses it; other Unicode digits stay text too
    assert pubspec._parts("1.².٣") == (1, "²", "٣")
    assert parse_version("1.0.0-²") is None


# ------------------------------------------------------------------ constraints
def test_constraint_exclusive_maximum_excludes_its_prereleases():
    c = parse_constraint(">=1.0.0 <2.0.0")
    assert c.allows(v("1.2.0")) and c.allows(v("1.99.0-dev"))
    assert not c.allows(v("2.0.0-alpha")) and not c.allows(v("2.0.0"))
    c = parse_constraint("<2.0.0-beta")
    assert c.allows(v("2.0.0-alpha")) and not c.allows(v("2.0.0-beta"))
    c = parse_constraint(">2.0.0-alpha <2.0.0")
    assert not c.allows(v("2.0.0-alpha")) and c.allows(v("2.0.0-beta"))
    assert not c.allows(v("2.0.0"))
    c = parse_constraint("<2.0.0+1")            # a maximum with a build keeps the pre-releases
    assert c.allows(v("2.0.0-beta")) and c.allows(v("2.0.0"))


@pytest.mark.parametrize("text, allowed, rejected", [
    ("^1.3.0", ["1.3.0", "1.99.0", "1.3.0+5"], ["1.2.9", "2.0.0", "2.0.0-dev.1", "1.3.0-dev"]),
    ("^0.1.2", ["0.1.2", "0.1.9"], ["0.2.0", "0.1.1"]),
    ("^0.0.3", ["0.0.3", "0.0.9"], ["0.1.0"]),        # pub, unlike npm: < 0.1.0
    ("^1.0.0-alpha", ["1.0.0-beta", "1.0.0", "1.5.0"], ["2.0.0-0", "0.9.0"]),
    ("1.2.3", ["1.2.3"], ["1.2.3+1", "1.2.4", "1.2.2"]),
    ("any", ["0.0.1-dev", "99.0.0"], []),
    (">2.0.4 <= 2.4.6", ["2.4.6", "2.0.5"], ["2.0.4", "2.4.7"]),
    ("<=5.1.4", ["5.1.4", "0.0.1"], ["5.1.5"]),
    (">=1.0.0 >=1.5.0 <3.0.0 <2.0.0", ["1.5.0", "1.9.9"], ["1.4.0", "2.0.0"]),
    ("1.0.0<2.0.0", ["1.0.0"], ["1.5.0"]),
])
def test_constraint_forms(text, allowed, rejected):
    c = parse_constraint(text)
    assert c is not None, text
    for item in allowed:
        assert c.allows(v(item)), (text, item)
    for item in rejected:
        assert not c.allows(v(item)), (text, item)


def test_constraint_exact_empty_and_invalid():
    assert parse_constraint("1.2.3").exact == v("1.2.3")
    assert parse_constraint(">=1.2.3 <=1.2.3").exact == v("1.2.3")
    assert parse_constraint("^1.2.3").exact is None
    for empty in [">=2.0.0 <1.0.0", ">1.0.0 <1.0.0", ">=1.0.0+1 <1.0.0"]:
        c = parse_constraint(empty)
        assert c is not None and c.empty and not c.allows(v("1.0.0")), empty
    for bad in ["", "   ", "^1.2.3 <2.0.0", "any <2.0.0", ">=", "1.2", "^", ">= 1.0.0 || 3.0.0",
                "latest", None, 1, "<" * 1000]:
        assert parse_constraint(bad) is None, bad


# ------------------------------------------------------------------ advisory ranges
def test_in_range_uses_plain_order_unlike_constraints():
    fixed_5 = [{"introduced": "0", "fixed": "5.0.0"}]
    assert in_range("4.0.6", fixed_5) and in_range("5.0.0-dev.1", fixed_5)
    assert not in_range("5.0.0", fixed_5) and not in_range("5.0.0+1", fixed_5)
    assert not parse_constraint("<5.0.0").allows(v("5.0.0-dev.1"))
    last = [{"introduced": "1.4.1", "last_affected": "1.9.0"}]
    assert in_range("1.4.1", last) and in_range("1.9.0", last)
    assert not in_range("1.4.0", last) and not in_range("1.9.0+1", last)
    assert in_range("7.0.0", [{"introduced": "1.0.0"}])           # no end: every later one
    assert not in_range("0.9.0", [{"introduced": "1.0.0"}])
    assert in_range(v("0.3.5"), [{"introduced": "0", "fixed": "0.3.5+1"}])


def test_in_range_ignores_unreadable_versions_and_ranges():
    assert not in_range("not a version", [{"introduced": "0", "fixed": "1.0.0"}])
    assert not in_range("0.5.0", [{"introduced": "0", "fixed": "1.0"}])
    assert not in_range("0.5.0", [{"introduced": "0", "fixed": "1.0.0",
                                   "last_affected": "0.9.0"}])
    assert not in_range("0.5.0", ["0", None, 7])
    assert in_range("0.5.0", [{"introduced": "x"}, {"introduced": "0", "fixed": "1.0.0"}])


# ------------------------------------------------------------------ shipped advisory data
RAW_ADVISORIES = json.loads((DATA / "advisories.json").read_text(encoding="utf-8"))
RAW_DISCONTINUED = json.loads((DATA / "discontinued.json").read_text(encoding="utf-8"))


def test_every_shipped_advisory_loads():
    loaded = load_advisories()
    assert len(loaded) == len(RAW_ADVISORIES) == 25
    assert {(a.id, a.package) for a in loaded} == {(r["id"], r["package"])
                                                   for r in RAW_ADVISORIES}
    assert load_advisories() is not loaded and len(load_advisories()) == 25   # cached table


def record_id(record):
    return "%s-%s" % (record["package"], record["id"])


@pytest.mark.parametrize("record", RAW_ADVISORIES, ids=record_id)
def test_advisory_record_is_complete(record):
    assert set(record) == {"id", "aliases", "package", "affected", "severity", "cwes",
                           "summary", "url", "source"}
    assert record["id"].startswith("GHSA-") and record["package"].islower()
    assert record["severity"] in ("low", "medium", "high", "critical")
    assert record["source"] in ("global-database", "repository-advisory", "cve-only")
    assert record["url"].startswith("https://") and len(record["summary"]) > 40
    assert any(ident in record["url"] for ident in [record["id"]] + record["aliases"])
    assert all(cwe.startswith("CWE-") for cwe in record["cwes"])
    if record["source"] == "cve-only":
        assert any(alias.startswith("CVE-") for alias in record["aliases"])


@pytest.mark.parametrize("record", RAW_ADVISORIES, ids=record_id)
def test_advisory_ranges_behave(record):
    advisory = [a for a in advisories_for(record["package"]) if a.id == record["id"]][0]
    assert advisory.affected == record["affected"]
    for entry in record["affected"]:
        assert set(entry) in ({"introduced", "fixed"}, {"introduced", "last_affected"}), entry
        start = entry["introduced"]
        if start != "0":
            assert advisory.affects(start), (record["id"], start)
            first = v(start)
            below = Version(first.major, first.minor, first.patch, first.pre) if first.build \
                else first.first_prerelease()
            if below != first:
                assert not in_range(below, [entry]), (record["id"], str(below))
        if "fixed" in entry:
            assert v(entry["fixed"]) > (v(start) if start != "0" else v("0.0.0-0"))
            assert not advisory.affects(entry["fixed"]), (record["id"], entry["fixed"])
        else:
            last = v(entry["last_affected"])
            assert advisory.affects(last)
            assert not in_range(Version(last.major, last.minor, last.patch + 1), [entry])


# (package, advisory, version, affected): boundaries and published versions from the research
REAL_VERSIONS = [
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "0.9.0", False),
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "1.0.0", True),
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "2.0.0-beta1", True),
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "2.0.0-prev1", True),
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "2.7.1", True),
    ("dio_http2_adapter", "GHSA-cr65-55v9-xhvv", "2.8.0", False),
    ("jose", "GHSA-vm9r-h74p-hg97", "0.3.4", True),
    ("jose", "GHSA-vm9r-h74p-hg97", "0.3.5", True),
    ("jose", "GHSA-vm9r-h74p-hg97", "0.3.5+1", False),
    ("jose", "GHSA-vm9r-h74p-hg97", "0.3.6", False),
    ("shared_preferences_android", "GHSA-3hpf-ff72-j67p", "2.3.2", False),
    ("shared_preferences_android", "GHSA-3hpf-ff72-j67p", "2.3.3", True),
    ("shared_preferences_android", "GHSA-3hpf-ff72-j67p", "2.3.4", False),
    ("agent_dart", "GHSA-fmj7-7gfw-64pg", "0.1.24+1", True),
    ("agent_dart", "GHSA-fmj7-7gfw-64pg", "1.0.0-dev.28", True),
    ("agent_dart", "GHSA-fmj7-7gfw-64pg", "1.0.0-dev.29", False),
    ("agent_dart", "GHSA-fmj7-7gfw-64pg", "1.0.0-dev.39", False),
    ("agent_dart", "GHSA-fmj7-7gfw-64pg", "1.0.0", False),
    ("serverpod_auth_server", "GHSA-r75m-26cq-mjxc", "1.2.5", True),
    ("serverpod_auth_server", "GHSA-r75m-26cq-mjxc", "1.2.6", False),
    ("serverpod_client", "GHSA-h6x7-r5rg-x5fw", "1.2.5", True),
    ("serverpod_client", "GHSA-h6x7-r5rg-x5fw", "1.2.6", False),
    ("pubnub", "GHSA-5844-q3fc-56rh", "4.2.4", True),
    ("pubnub", "GHSA-5844-q3fc-56rh", "4.3.0", False),
    ("archive", "GHSA-9v85-q87q-g4vg", "3.3.7", True),
    ("archive", "GHSA-9v85-q87q-g4vg", "3.3.8", False),
    ("archive", "GHSA-r285-q736-9v95", "3.3.7", True),
    ("archive", "GHSA-r285-q736-9v95", "3.3.8", False),
    ("dio", "GHSA-9324-jv53-9cc8", "4.0.6", True),
    ("dio", "GHSA-9324-jv53-9cc8", "5.0.0-dev.1", True),
    ("dio", "GHSA-9324-jv53-9cc8", "5.0.0", False),
    ("personnummer", "GHSA-4xh4-v2pq-jvhm", "3.0.2", True),
    ("personnummer", "GHSA-4xh4-v2pq-jvhm", "3.0.3", False),
    ("http", "GHSA-4rgh-jx4f-qfcq", "0.12.2", True),
    ("http", "GHSA-4rgh-jx4f-qfcq", "0.13.2", True),
    ("http", "GHSA-4rgh-jx4f-qfcq", "0.13.3", False),
    ("http", "GHSA-4rgh-jx4f-qfcq", "1.2.0", False),
    ("file_selector_android", "GHSA-r465-vhm9-7r5h", "0.5.0+2", False),
    ("file_selector_android", "GHSA-r465-vhm9-7r5h", "0.5.1", True),
    ("file_selector_android", "GHSA-r465-vhm9-7r5h", "0.5.1+11", True),
    ("file_selector_android", "GHSA-r465-vhm9-7r5h", "0.5.1+12", False),
    ("image_picker_android", "GHSA-98v2-f47x-89xw", "0.8.5+5", False),
    ("image_picker_android", "GHSA-98v2-f47x-89xw", "0.8.5+6", True),
    ("image_picker_android", "GHSA-98v2-f47x-89xw", "0.8.12+17", True),
    ("image_picker_android", "GHSA-98v2-f47x-89xw", "0.8.12+18", False),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "2.9.4", True),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "2.9.5", False),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "3.0.0", True),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "3.4.12", True),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "3.4.13", False),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "3.5.0-beta.1", False),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "4.0.0-beta.0", True),
    ("serverpod_auth_server", "GHSA-m6hm-gg8r-43xx", "4.0.0-rc.1", False),
    ("serverpod_auth_bridge_server", "GHSA-m6hm-gg8r-43xx", "3.4.0", False),
    ("serverpod_auth_bridge_server", "GHSA-m6hm-gg8r-43xx", "4.0.0-beta.5", True),
    ("serverpod_auth_bridge_server", "GHSA-m6hm-gg8r-43xx", "4.0.0-rc.1", False),
    ("serverpod_auth_idp_server", "GHSA-3hrq-4vpw-386w", "3.4.11", True),
    ("serverpod_auth_idp_server", "GHSA-3hrq-4vpw-386w", "3.4.12", False),
    ("serverpod_auth_idp_server", "GHSA-3hrq-4vpw-386w", "3.5.0-beta.1", True),
    ("serverpod_auth_idp_server", "GHSA-3hrq-4vpw-386w", "4.0.0-beta.2", True),
    ("serverpod_auth_idp_server", "GHSA-3hrq-4vpw-386w", "4.0.0-beta.3", False),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "0.9.18", False),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "0.9.19", True),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "1.2.7", True),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "2.9.4", False),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "3.0.0", True),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "3.4.12", False),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "3.5.0-beta.12", True),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "4.0.0-beta.1", True),
    ("serverpod", "GHSA-868m-gf4j-xr8g", "4.0.0-beta.2", False),
    ("serverpod_database", "GHSA-868m-gf4j-xr8g", "4.0.0-beta.0", False),
    ("serverpod_database", "GHSA-868m-gf4j-xr8g", "4.0.0-beta.1", True),
    ("serverpod_database", "GHSA-868m-gf4j-xr8g", "4.0.0-beta.2", False),
    ("boring", "GHSA-3pvf-h66p-qwjp", "0.4.1", True),
    ("boring", "GHSA-3pvf-h66p-qwjp", "0.4.2", False),
    ("permission_handler_android", "GHSA-v2vf-262r-fghf", "14.0.9", False),
    ("permission_handler_android", "GHSA-v2vf-262r-fghf", "14.1.0", True),
    ("permission_handler_android", "GHSA-v2vf-262r-fghf", "14.1.1", False),
    ("flutter_downloader", "GHSA-jmj6-wqfw-54vr", "1.11.0", True),
    ("flutter_downloader", "GHSA-jmj6-wqfw-54vr", "1.11.1", True),
    ("flutter_downloader", "GHSA-jmj6-wqfw-54vr", "1.11.2", False),
    ("file_picker", "GHSA-r2rg-pm28-j8gw", "10.3.10", True),
    ("file_picker", "GHSA-r2rg-pm28-j8gw", "11.0.1", True),
    ("file_picker", "GHSA-r2rg-pm28-j8gw", "11.0.2", False),
    ("receive_sharing_intent", "GHSA-wvv2-g99g-c5px", "1.4.0", False),
    ("receive_sharing_intent", "GHSA-wvv2-g99g-c5px", "1.4.1", True),
    ("receive_sharing_intent", "GHSA-wvv2-g99g-c5px", "1.9.0", True),
    ("receive_sharing_intent", "GHSA-wvv2-g99g-c5px", "1.9.1", False),
    ("http_server", "GHSA-3vf7-gh27-gx55", "0.9.5", True),
    ("http_server", "GHSA-3vf7-gh27-gx55", "0.9.6", False),
    ("http_server", "GHSA-3vf7-gh27-gx55", "1.0.0", False),
]


@pytest.mark.parametrize("package, advisory_id, version, affected", REAL_VERSIONS)
def test_real_versions_against_shipped_ranges(package, advisory_id, version, affected):
    advisory = [a for a in advisories_for(package) if a.id == advisory_id]
    assert len(advisory) == 1, (package, advisory_id)
    assert advisory[0].affects(version) is affected
    assert (advisory_id in [a.id for a in affecting_advisories(package, version)]) is affected


def test_every_shipped_advisory_has_real_version_checks():
    covered = {(package, advisory_id) for package, advisory_id, _v, _a in REAL_VERSIONS}
    assert covered == {(r["package"], r["id"]) for r in RAW_ADVISORIES}


def test_data_skips_withdrawn_and_unconfirmed_records():
    ids = {r["id"] for r in RAW_ADVISORIES} | {a for r in RAW_ADVISORIES for a in r["aliases"]}
    assert not ids & {"GHSA-jwpw-q68h-r678", "GHSA-9f2c-xxfm-32mj"}           # withdrawn
    assert not ids & {"GHSA-95m7-jx48-r539", "GHSA-cqj7-79w2-9qmf", "GHSA-r8jh-g5f6-x77p",
                      "GHSA-26jj-r8fx-8pm3"}                                  # thrift
    assert "thrift" not in {r["package"] for r in RAW_ADVISORIES} | set(RAW_DISCONTINUED)
    assert advisories_for("thrift") == [] and advisories_for("no_such_package") == []


def test_discontinued_data():
    table = load_discontinued()
    assert set(table) == set(RAW_DISCONTINUED) and len(table) == 16
    for name, entry in table.items():
        assert entry.reason and entry.url.startswith("https://"), name
        if entry.replaced_by:
            assert entry.replaced_by != name and entry.discontinued, name
    unfixed = sorted(name for name, entry in table.items() if not entry.discontinued)
    assert unfixed == ["receive_sharing_intent"]
    for name in unfixed:           # its vulnerability has no fixed version
        assert advisories_for(name) and all("fixed" not in entry for a in advisories_for(name)
                                            for entry in a.affected)
    assert table["uni_links"].replaced_by == "app_links"
    assert table["flutter_sodium"].replaced_by == "sodium_libs"
    assert table["sodium_libs"].replaced_by == "sodium"


# ------------------------------------------------------------------ pubspec.yaml / pubspec.lock
APP_PUBSPEC = """\
name: demo_app
description: A test app.
publish_to: 'none'
version: 1.0.0+1

environment:
  sdk: ^3.5.0
  flutter: ">=3.22.0"

dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.0
  dio: ^4.0.0
  jose: 0.3.5
  uni_links: ^0.5.1
  local_lib:
    path: ../local_lib
  pinned_git:
    git:
      url: https://github.com/example/pinned.git
      ref: 0123456789abcdef0123456789abcdef01234567
  branch_git:
    git:
      url: git://example.com/branch.git
      ref: main
  tagged_git:
    git:
      url: https://github.com/example/tagged.git
      ref: v1.2.3
  loose: any
  private_pkg:
    hosted: http://pub.example.com
    version: ^1.0.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  archive: ^3.3.0

dependency_overrides:
  path_provider: 2.1.0

flutter:
  uses-material-design: true
  assets:
    - assets/images/
    - .env
    - path: assets/config.json
      flavors: [staging]
"""


def locked(name, version, dependency="direct main", url="https://pub.dev"):
    return ("  %s:\n    dependency: \"%s\"\n    description:\n      name: %s\n"
            "      sha256: \"%s\"\n      url: \"%s\"\n    source: hosted\n    version: \"%s\"\n"
            % (name, dependency, name, "ab" * 32, url, version))


APP_LOCK = ("# Generated by pub\n# See https://dart.dev/tools/pub/glossary#lockfile\n"
            "packages:\n"
            + locked("archive", "3.3.7", "direct dev")
            + "  branch_git:\n    dependency: \"direct main\"\n    description:\n"
              "      path: \".\"\n      ref: main\n"
              "      resolved-ref: \"1111111111111111111111111111111111111111\"\n"
              "      url: \"git://example.com/branch.git\"\n    source: git\n"
              "    version: \"0.0.1\"\n"
            + locked("dio", "4.0.6")
            + "  flutter:\n    dependency: \"direct main\"\n    description: flutter\n"
              "    source: sdk\n    version: \"0.0.0\"\n"
            + "  flutter_test:\n    dependency: \"direct dev\"\n    description: flutter\n"
              "    source: sdk\n    version: \"0.0.0\"\n"
            + locked("http", "0.13.0")
            + locked("image_picker_android", "0.8.12+17", "transitive")
            + locked("jose", "0.3.5+1")
            + "  local_lib:\n    dependency: \"direct main\"\n    description:\n"
              "      path: \"../local_lib\"\n      relative: true\n    source: path\n"
              "    version: \"1.0.0\"\n"
            + locked("loose", "1.4.0")
            + locked("path_provider", "2.1.0", "direct overridden")
            + "  pinned_git:\n    dependency: \"direct main\"\n    description:\n"
              "      path: \".\"\n      ref: \"0123456789abcdef0123456789abcdef01234567\"\n"
              "      resolved-ref: \"0123456789abcdef0123456789abcdef01234567\"\n"
              "      url: \"https://github.com/example/pinned.git\"\n    source: git\n"
              "    version: \"2.0.0\"\n"
            + locked("private_pkg", "1.0.0", url="http://pub.example.com")
            + "  tagged_git:\n    dependency: \"direct main\"\n    description:\n"
              "      path: \".\"\n      ref: v1.2.3\n"
              "      resolved-ref: \"2222222222222222222222222222222222222222\"\n"
              "      url: \"https://github.com/example/tagged.git\"\n    source: git\n"
              "    version: \"1.2.3\"\n"
            + locked("uni_links", "0.5.1")
            + "sdks:\n  dart: \">=3.5.0 <4.0.0\"\n  flutter: \">=3.22.0\"\n")


def test_parse_pubspec_reads_every_section_with_lines():
    spec = parse_pubspec(APP_PUBSPEC)
    assert spec.error == "" and spec.name == "demo_app" and spec.version == "1.0.0+1"
    assert spec.sdk == "^3.5.0" and spec.flutter_sdk == ">=3.22.0"
    assert spec.is_flutter and spec.is_app and not spec.is_plugin
    deps = spec.dependencies
    assert (deps["flutter"].source, deps["flutter"].sdk) == ("sdk", "flutter")
    assert (deps["http"].source, deps["http"].constraint) == ("hosted", "^0.13.0")
    assert (deps["local_lib"].source, deps["local_lib"].path) == ("path", "../local_lib")
    assert (deps["branch_git"].source, deps["branch_git"].url, deps["branch_git"].ref) == (
        "git", "git://example.com/branch.git", "main")
    assert (deps["private_pkg"].url, deps["private_pkg"].constraint) == (
        "http://pub.example.com", "^1.0.0")
    assert deps["loose"].constraint == "any"
    assert list(spec.dev_dependencies) == ["flutter_test", "archive"]
    assert spec.overrides["path_provider"].constraint == "2.1.0"
    assert spec.declared()["path_provider"].section == "dependency_overrides"
    for name in ["http", "dio", "branch_git", "private_pkg", "loose"]:
        assert deps[name].line == line_starting(APP_PUBSPEC, "  %s:" % name), name
    assert spec.dev_dependencies["archive"].line == line_of(APP_PUBSPEC, "  archive: ^3.3.0")
    assert spec.line_of("dependencies", "jose") == line_of(APP_PUBSPEC, "  jose: 0.3.5")
    assert [(a.path, a.line) for a in spec.assets] == [
        ("assets/images/", line_of(APP_PUBSPEC, "    - assets/images/")),
        (".env", line_of(APP_PUBSPEC, "    - .env")),
        ("assets/config.json", line_of(APP_PUBSPEC, "    - path: assets/config.json"))]
    assert spec.line_of("name") == 1 and spec.line_of("nothing") == 0


def test_parse_pubspec_app_package_plugin_and_workspace():
    assert not parse_pubspec("name: lib\nversion: 1.0.0\n").is_app
    plugin = parse_pubspec("name: p\npublish_to: none\nflutter:\n  plugin:\n    platforms: {}\n")
    assert plugin.is_plugin and not plugin.is_app
    member = parse_pubspec("name: m\nresolution: workspace\npublish_to: none\n")
    assert member.resolution == "workspace" and member.is_app
    spec = parse_pubspec("name: a\nignored_advisories: [GHSA-x, 7, {a: b}, CVE-1]\n")
    assert spec.ignored_advisories == ["GHSA-x", "CVE-1"]


def test_parse_lock_reads_packages_lines_and_sdks():
    lock = parse_lock(APP_LOCK)
    assert lock.error == "" and len(lock.packages) == 15
    http = lock.packages["http"]
    assert (http.version, http.source, http.dependency) == ("0.13.0", "hosted", "direct main")
    assert http.line == line_of(APP_LOCK, "  http:") and http.url == "https://pub.dev"
    assert http.description["sha256"] == "ab" * 32
    git = lock.packages["branch_git"]
    assert (git.source, git.url, git.ref) == ("git", "git://example.com/branch.git", "main")
    assert git.resolved_ref == "1" * 40 and git.tag_pattern == ""
    assert lock.packages["flutter"].description == "flutter"
    assert lock.packages["local_lib"].description == {"path": "../local_lib", "relative": True}
    assert lock.packages["path_provider"].dependency == "direct overridden"
    assert lock.sdks == {"dart": ">=3.5.0 <4.0.0", "flutter": ">=3.22.0"}
    assert parse_lock("packages: {}\nsdk: '>=1.8.0 <2.0.0'\n").sdks == {"dart": ">=1.8.0 <2.0.0"}


def test_parse_lock_keeps_lines_with_crlf_and_plain_descriptions():
    text = APP_LOCK.replace("\n", "\r\n")
    lock = parse_lock(text)
    assert lock.packages["uni_links"].line == line_of(APP_LOCK, "  uni_links:")
    nested = parse_lock("packages:\n  a:\n    description: {url: x, deep: {k: [1, 2]}}\n"
                        "    source: hosted\n    version: '1.0.0'\n")
    assert nested.packages["a"].description == {"url": "x"}
    json.dumps({name: vars(p) for name, p in lock.packages.items()})   # JSON-safe


HOSTILE = [
    "", "   \n", "[]", "just text", "a: [", "a: {b: c", "\x0c", "name: a\x00b", "\x1b[31m",
    "[" * 5000 + "]" * 5000, "- " * 3000 + "x", "a: &a [1]\nb: *a\nc: *missing\n",
    "name: !!python/object/apply:os.system ['echo hi']\n", "--- a\n--- b\n",
    "packages: [1, 2]\nsdks: 5\n", "packages:\n  ? [a, b]\n  : x\n",
    "dependencies: {http: {git: [1]}, dio: {hosted: [2]}, x: {path: {y: 1}}}\n",
    "flutter: {assets: [1, {path: [2]}, null, '']}\n", "version: 2001-12-14\n",
    "a: " + "9" * 5000 + "\n", "\ufeffname: bom\n", "date: 2001-02-30\n",
]
LAUGHS = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
    "%s: &%s [%s]\n" % (chr(98 + i), chr(98 + i), ", ".join(["*" + chr(97 + i)] * 9))
    for i in range(8)) + "ignored_advisories: [*i]\npackages: {p: {description: *i}}\n"


@pytest.mark.parametrize("text", HOSTILE + [LAUGHS], ids=range(len(HOSTILE) + 1))
def test_parsers_never_raise_on_hostile_text(text, loader):
    spec, lock = parse_pubspec(text), parse_lock(text)
    assert isinstance(spec.error, str) and isinstance(lock.error, str)
    json.dumps({name: vars(p) for name, p in lock.packages.items()})
    warnings = []
    findings = audit_project(source("pubspec.yaml", text), source("pubspec.lock", text),
                             warnings)
    assert all(f.engines == ["flutter"] for f in findings)
    assert len(warnings) == bool(spec.error) + bool(lock.error)


ANCHORS = """\
base: &base
  version: ^1.0.0
dependencies:
  http:
    *base
  dio: &pinned 5.4.0
dependency_overrides:
  dio: *pinned
"""


@pytest.fixture(params=["libyaml", "python"])
def loader(request, monkeypatch):
    """Runs a test with the libyaml-based loader and with the pure-Python fallback."""
    if request.param == "python":
        monkeypatch.setattr(pubspec, "_Loader", pubspec._PureLoader)
    elif pubspec.CParser is None:
        pytest.skip("PyYAML is built without libyaml")
    return request.param


def test_both_loaders_read_the_same_data_and_lines(loader):
    spec = parse_pubspec(ANCHORS)
    assert spec.error == "" and spec.dependencies["http"].constraint == "^1.0.0"
    assert spec.overrides["dio"].constraint == "5.4.0"
    assert spec.line_of("dependencies", "dio") == 6 and spec.line_of("dependency_overrides",
                                                                     "dio") == 8
    lock = parse_lock(APP_LOCK)
    assert len(lock.packages) == 15 and lock.packages["http"].line == line_of(APP_LOCK,
                                                                              "  http:")
    full = parse_pubspec(APP_PUBSPEC)
    assert [a.line for a in full.assets] == [
        line_of(APP_PUBSPEC, "    - assets/images/"), line_of(APP_PUBSPEC, "    - .env"),
        line_of(APP_PUBSPEC, "    - path: assets/config.json")]
    assert full.line_of("flutter") == line_of(APP_PUBSPEC, "flutter:")


def merge_levels(levels):
    """Each level merges the one before twice: PyYAML's merge keys would copy 4 * 2**levels
    pairs into the last mapping."""
    lines = ["name: app", "a0: &a0 {k0: 1, k1: 2, k2: 3, k3: 4}"]
    lines += ["a%d: &a%d {<<: [*a%d, *a%d]}" % (i, i, i - 1, i - 1) for i in range(1, levels + 1)]
    return "\n".join(lines + ["dependencies: {flutter: {sdk: flutter}}"]) + "\n"


def test_merge_keys_are_plain_keys_as_in_pub(loader):
    text = "base: &base {version: ^1.0.0}\ndependencies:\n  http:\n    <<: *base\n"
    data, lines, error = pubspec._load_yaml(text + "other: {=: 1}\n")
    assert error == "" and data["dependencies"]["http"] == {"<<": {"version": "^1.0.0"}}
    assert data["other"] == {"=": 1} and lines[("dependencies", "http", "<<")] == 4
    assert parse_pubspec(text).dependencies["http"].constraint == ""     # pub merges nothing
    started = time.perf_counter()
    spec = parse_pubspec(merge_levels(40))
    assert spec.error == "" and spec.is_flutter and time.perf_counter() - started < 2
    data, _, _ = pubspec._load_yaml(merge_levels(3))
    assert data["a3"] == {"<<": [data["a2"], data["a2"]]}


def test_node_limit(monkeypatch, loader):
    monkeypatch.setattr(pubspec, "MAX_NODES", 50)
    assert parse_lock("packages: [" + "1, " * 60 + "]").error == \
        "not valid YAML (more than 50 YAML nodes)"
    assert parse_lock("packages: [" + "1, " * 40 + "]").error == ""


def test_parse_errors_are_reported_not_raised(loader):
    assert parse_pubspec("a: 1\nb: c: d\ne: 2\n").error.startswith("not valid YAML at line 2 (")
    assert "nested too deeply" in parse_pubspec("[" * 5000 + "]" * 5000).error
    assert parse_pubspec("\x0c").error.startswith("not valid YAML")
    assert parse_pubspec("[]").error == "pubspec.yaml does not hold a YAML mapping"
    assert parse_lock("x" * (pubspec.MAX_TEXT + 1)).error.startswith("file too large")
    warnings = []
    assert audit_project(source("app/pubspec.yaml", "a: ["),
                         source("app/pubspec.lock", "\x00"), warnings) == []
    assert len(warnings) == 2 and warnings[0].startswith("app/pubspec.yaml: not valid YAML")


# ------------------------------------------------------------------ audit with pubspec.lock
def test_audit_with_lock_points_to_lock_lines():
    findings = audit_project(source("app/pubspec.yaml", APP_PUBSPEC),
                             source("app/pubspec.lock", APP_LOCK))
    assert all(f.file == "app/pubspec.lock" and f.engines == ["flutter"] for f in findings)
    assert all(f.snippet == f.context.splitlines()[0].split("| ", 1)[1].strip()
               for f in findings)
    summary = sorted((f.rule_id, f.snippet) for f in findings)
    assert summary == sorted([
        ("FLUTTER-PUB-001", "archive:"), ("FLUTTER-PUB-001", "dio:"),
        ("FLUTTER-PUB-001", "http:"), ("FLUTTER-PUB-001", "image_picker_android:"),
        ("FLUTTER-PUB-002", "uni_links:"),
        ("FLUTTER-PUB-003", "branch_git:"), ("FLUTTER-PUB-003", "private_pkg:"),
        ("FLUTTER-PUB-004", "loose:"), ("FLUTTER-PUB-004", "path_provider:"),
        ("FLUTTER-PUB-006", "branch_git:")])
    dio = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  dio:"))
    assert (dio.cwe, dio.severity, dio.confidence) == ("CWE-1395", "high", 0.9)
    assert dio.title == "Vulnerable dependency: dio 4.0.6"
    for text in ["GHSA-9324-jv53-9cc8", "CVE-2021-31402", "CWE-93", "affected: < 5.0.0"]:
        assert text in dio.description
    assert dio.fix.startswith("Upgrade dio to 5.0.0 or a later fixed release.")
    assert "constraint ^4.0.0 in pubspec.yaml does not allow that version: change it to ^5.0.0" \
        in dio.fix
    http = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  http:"))
    assert (http.severity, http.language) == ("medium", "config")
    assert "change it" not in http.fix                    # ^0.13.0 allows 0.13.3
    archive = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  archive:"))
    assert "2 known vulnerabilities" in archive.description and archive.severity == "high"
    assert "GHSA-9v85-q87q-g4vg" in archive.description and "CWE-22" in archive.description
    assert pubspec.DEV_NOTE in archive.description
    picker = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  image_picker_android:"))
    assert picker.severity == "low" and "0.8.12+18" in picker.fix
    assert "transitive dependency" in picker.fix
    links = at(findings, "FLUTTER-PUB-002", line_of(APP_LOCK, "  uni_links:"))
    assert (links.cwe, links.severity, links.confidence) == ("CWE-1104", "low", 0.8)
    assert links.title == "Discontinued package: uni_links" and "app_links" in links.fix
    insecure = at(findings, "FLUTTER-PUB-003", line_of(APP_LOCK, "  branch_git:"))
    assert (insecure.cwe, insecure.severity, insecure.confidence) == ("CWE-494", "high", 0.85)
    assert "git://" in insecure.title
    hosted = at(findings, "FLUTTER-PUB-003", line_of(APP_LOCK, "  private_pkg:"))
    assert "http://pub.example.com" in hosted.description
    branch = at(findings, "FLUTTER-PUB-006", line_of(APP_LOCK, "  branch_git:"))
    assert (branch.cwe, branch.severity, branch.confidence) == ("CWE-494", "low", 0.6)
    assert "'main'" in branch.description and "111111111111" in branch.description
    override = at(findings, "FLUTTER-PUB-004", line_of(APP_LOCK, "  path_provider:"))
    assert (override.cwe, override.severity, override.confidence) == ("CWE-1357", "low", 0.7)
    assert override.title == "Dependency override: path_provider"
    loose = at(findings, "FLUTTER-PUB-004", line_of(APP_LOCK, "  loose:"))
    assert loose.title == "Unconstrained dependency: loose" and "^1.4.0" in loose.fix


def test_lock_context_shows_the_package_entry():
    findings = audit_project(source("pubspec.yaml", APP_PUBSPEC),
                             source("pubspec.lock", APP_LOCK))
    dio = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  dio:"))
    assert 'version: "4.0.6"' in dio.context and "source: hosted" in dio.context


def test_fixed_versions_and_unchecked_sources_give_no_finding():
    lock = ("packages:\n" + locked("jose", "0.3.5+1") + locked("http", "1.2.2")
            + locked("dio", "5.0.0") + locked("image_picker_android", "0.8.12+18")
            + locked("agent_dart", "1.0.0-dev.29")
            + "  archive:\n    dependency: \"direct main\"\n    description:\n"
              "      path: \"../archive\"\n      relative: true\n    source: path\n"
              "    version: \"3.3.0\"\n")
    spec = "name: a\npublish_to: none\ndependencies:\n  http: ^1.2.0\n  dio: ^5.0.0\n" \
           "  jose: ^0.3.5\n  archive:\n    path: ../archive\n"
    assert audit_project(source("pubspec.yaml", spec), source("pubspec.lock", lock)) == []


def test_ignored_advisories_turn_the_finding_into_info():
    spec = APP_PUBSPEC + "ignored_advisories:\n  - CVE-2021-31402\n"
    findings = audit_project(source("pubspec.yaml", spec), source("pubspec.lock", APP_LOCK))
    dio = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  dio:"))
    assert dio.severity == "info"
    assert "lists GHSA-9324-jv53-9cc8 under ignored_advisories" in dio.description
    http = at(findings, "FLUTTER-PUB-001", line_of(APP_LOCK, "  http:"))
    assert http.severity == "medium"


def test_other_package_repository_lowers_confidence():
    lock = "packages:\n" + locked("dio", "4.0.6", url="https://pub.example.com") \
        + locked("uni_links", "0.5.1", url="https://pub.example.com") \
        + locked("http", "0.13.0", url="https://pub.flutter-io.cn")
    findings = audit_project(source("pubspec.yaml", "name: a\n"), source("pubspec.lock", lock))
    dio = at(findings, "FLUTTER-PUB-001", line_of(lock, "  dio:"))
    assert dio.confidence == pubspec.OTHER_REPOSITORY_CONFIDENCE
    assert "package repository at pub.example.com" in dio.description
    links = at(findings, "FLUTTER-PUB-002", line_of(lock, "  uni_links:"))
    assert links.confidence == pubspec.OTHER_REPOSITORY_CONFIDENCE
    http = at(findings, "FLUTTER-PUB-001", line_of(lock, "  http:"))      # a pub.dev mirror
    assert http.confidence == 0.9 and "package repository" not in http.description


def test_lock_version_that_cannot_be_read_falls_back_to_the_constraint():
    lock = "packages:\n" + locked("dio", "four")
    findings = audit_project(source("pubspec.yaml", "name: a\ndependencies:\n  dio: ^4.0.0\n"),
                             source("pubspec.lock", lock))
    dio = at(findings, "FLUTTER-PUB-001", line_of(lock, "  dio:"))
    assert dio.confidence == 0.8 and dio.title == "Vulnerable dependency: dio ^4.0.0"


def test_unreadable_lock_version_of_a_transitive_package_keeps_the_advisory_severity():
    # only app packages turn an unknown version into information; a project's lock still
    # names the package, so the advisory's severity stays
    lock = "packages:\n" + locked("dio", "four", dependency="transitive")
    findings = audit_project(source("pubspec.yaml", "name: a\n"), source("pubspec.lock", lock))
    dio = at(findings, "FLUTTER-PUB-001", line_of(lock, "  dio:"))
    assert dio.title == "Possibly vulnerable dependency: dio (version unknown)"
    assert dio.severity == "high" and dio.confidence == 0.35


# ------------------------------------------------------------------ audit without pubspec.lock
def pub(line_text):
    return line_of(APP_PUBSPEC, line_text)


def test_audit_without_lock_points_to_pubspec_lines():
    findings = audit_project(source("app/pubspec.yaml", APP_PUBSPEC))
    assert all(f.file == "app/pubspec.yaml" for f in findings)
    http = at(findings, "FLUTTER-PUB-001", pub("  http: ^0.13.0"))
    assert http.confidence == 0.35 and http.snippet == "http: ^0.13.0"
    assert http.title == "Dependency constraint allows a vulnerable version: http ^0.13.0"
    assert "change the constraint of http in pubspec.yaml to ^0.13.3" in http.fix.lower()
    dio = at(findings, "FLUTTER-PUB-001", pub("  dio: ^4.0.0"))
    assert dio.confidence == 0.8 and dio.title == "Vulnerable dependency: dio ^4.0.0"
    assert "Every version of dio that the constraint ^4.0.0 allows" in dio.description
    assert "^5.0.0" in dio.fix
    jose = at(findings, "FLUTTER-PUB-001", pub("  jose: 0.3.5"))
    assert jose.confidence == 0.9 and jose.title == "Vulnerable dependency: jose 0.3.5"
    assert "Upgrade jose to 0.3.5+1" in jose.fix and "change it to ^0.3.5+1" in jose.fix
    archive = at(findings, "FLUTTER-PUB-001", pub("  archive: ^3.3.0"))
    assert archive.confidence == 0.35 and pubspec.DEV_NOTE in archive.description
    at(findings, "FLUTTER-PUB-002", pub("  uni_links: ^0.5.1"))
    branch = pub("  branch_git:")
    at(findings, "FLUTTER-PUB-003", branch)
    at(findings, "FLUTTER-PUB-006", branch)
    at(findings, "FLUTTER-PUB-003", pub("  private_pkg:"))
    at(findings, "FLUTTER-PUB-004", pub("  loose: any"))
    at(findings, "FLUTTER-PUB-004", pub("  path_provider: 2.1.0"))
    no_lock = at(findings, "FLUTTER-PUB-005", 1)
    assert (no_lock.cwe, no_lock.severity, no_lock.confidence) == ("CWE-1357", "info", 0.6)
    assert no_lock.snippet == "name: demo_app"
    assert len(findings) == 11


def test_no_lock_finding_only_for_flutter_apps():
    app = "name: a\npublish_to: none\ndependencies:\n  flutter:\n    sdk: flutter\n"
    assert by_rule(audit_project(source("pubspec.yaml", app)), "FLUTTER-PUB-005")
    package = app.replace("publish_to: none\n", "")
    assert not by_rule(audit_project(source("pubspec.yaml", package)), "FLUTTER-PUB-005")
    assert by_rule(audit_project(source("pubspec.yaml", package), app=True), "FLUTTER-PUB-005")
    assert not by_rule(audit_project(source("pubspec.yaml", app), app=False), "FLUTTER-PUB-005")
    member = app + "resolution: workspace\n"
    assert not by_rule(audit_project(source("pubspec.yaml", member)), "FLUTTER-PUB-005")
    dart_app = "name: a\npublish_to: none\ndependencies:\n  args: ^2.0.0\n"
    assert not audit_project(source("pubspec.yaml", dart_app))
    with_lock = audit_project(source("pubspec.yaml", app), source("pubspec.lock", "packages: {}"))
    assert not with_lock


def test_overrides_and_any_only_flagged_in_an_app():
    package = "name: lib\ndependencies:\n  loose: any\ndependency_overrides:\n  meta: 1.0.0\n"
    assert audit_project(source("pubspec.yaml", package)) == []
    assert len(by_rule(audit_project(source("pubspec.yaml", package), app=True),
                       "FLUTTER-PUB-004")) == 2
    # in a pub workspace the root constrains and locks the packages of its members
    member = package + "resolution: workspace\n"
    flagged = by_rule(audit_project(source("pubspec.yaml", member), app=True),
                      "FLUTTER-PUB-004")
    assert [f.title for f in flagged] == ["Dependency override: meta"]


def test_git_pinning_rules():
    spec = ("name: a\ndependencies:\n"
            "  by_tag:\n    git:\n      url: https://h/a.git\n      ref: v2.1.0\n"
            "  by_short_commit:\n    git:\n      url: https://h/b.git\n      ref: a1b2c3d\n"
            "  by_pattern:\n    git:\n      url: https://h/c.git\n      tag_pattern: v{{version}}\n"
            "  by_release_branch:\n    git:\n      url: https://h/d.git\n      ref: 1.x\n"
            "  by_branch_path:\n    git:\n      url: https://h/e.git\n      ref: release/2.0\n"
            "  by_default:\n    git: https://h/f.git\n"
            "  local_mirror:\n    git: http://localhost/g.git\n"
            "  over_ssh:\n    git: git@github.com:o/h.git\n")
    findings = audit_project(source("pubspec.yaml", spec))
    flagged = sorted(f.snippet for f in by_rule(findings, "FLUTTER-PUB-006"))
    assert flagged == ["by_branch_path:", "by_default:", "by_release_branch:", "local_mirror:",
                       "over_ssh:"]
    default = [f for f in findings if f.snippet == "by_default:"][0]
    assert "default branch" in default.description
    assert not by_rule(findings, "FLUTTER-PUB-003")        # https, ssh and localhost
    lock = ("packages:\n  p:\n    dependency: \"direct main\"\n    description:\n"
            "      path: \".\"\n      resolved-ref: \"3333333333333333333333333333333333333333\"\n"
            "      tag-pattern: \"v{{version}}\"\n      url: \"https://h/p.git\"\n"
            "    source: git\n    version: \"1.0.0\"\n")
    assert audit_project(source("pubspec.yaml", "name: a\n"), source("pubspec.lock", lock)) == []


def test_snippet_and_context_are_masked():
    spec = ("name: a\ndependencies:\n"
            "  private: {git: 'http://deploy:S3cretT0kenValue@git.example.com/p.git'}\n")
    findings = audit_project(source("pubspec.yaml", spec, ["S3cretT0kenValue"]))
    insecure = by_rule(findings, "FLUTTER-PUB-003")[0]
    assert "S3cretT0kenValue" not in insecure.snippet + insecure.context
    assert "S3cr" in insecure.snippet
    assert "S3cretT0kenValue" not in insecure.description and "deploy" not in insecure.description


def test_unfixed_vulnerability_is_reported_as_unmaintained_too():
    lock = "packages:\n" + locked("receive_sharing_intent", "1.9.0")
    findings = audit_project(source("pubspec.yaml", "name: a\n"), source("pubspec.lock", lock))
    line = line_of(lock, "  receive_sharing_intent:")
    vulnerable = at(findings, "FLUTTER-PUB-001", line)
    assert vulnerable.severity == "medium" and "No fixed release" in vulnerable.fix
    unfixed = at(findings, "FLUTTER-PUB-002", line)
    assert unfixed.title == "Package with an unfixed vulnerability: receive_sharing_intent"
    assert "CVE-2026-60117" in unfixed.description


def test_discontinued_replacement_chain_is_followed():
    lock = "packages:\n" + locked("flutter_sodium", "0.2.0")
    finding = audit_project(source("pubspec.yaml", "name: a\n"),
                            source("pubspec.lock", lock))[0]
    assert finding.fix == "Replace flutter_sodium with sodium. (sodium_libs is discontinued " \
                          "as well.)"


def test_upgrade_target_avoids_versions_other_advisories_affect():
    lock = "packages:\n" + locked("serverpod_auth_server", "1.2.0") + locked("serverpod",
                                                                             "1.2.7")
    findings = audit_project(source("pubspec.yaml", "name: a\n"), source("pubspec.lock", lock))
    auth = at(findings, "FLUTTER-PUB-001", line_of(lock, "  serverpod_auth_server:"))
    assert "2 known vulnerabilities" in auth.description and auth.severity == "critical"
    assert auth.fix.startswith("Upgrade serverpod_auth_server to 2.9.5 ")   # not 1.2.6
    server = at(findings, "FLUTTER-PUB-001", line_of(lock, "  serverpod:"))
    assert server.fix.startswith("Upgrade serverpod to 2.9.4 ")


# ------------------------------------------------------------------ app packages
def test_audit_packages_for_an_app_package():
    text = "http 0.13.1\ndio\nuni_links 0.5.1\nflutter\ngit_pkg 1.0.0\nlocal 1.0.0\n"
    sf = SourceFile(Path("_sca/packages.txt"), "_sca/packages.txt", "config", text,
                    origin="decoded")
    lines = {line.split()[0]: number for number, line in enumerate(text.splitlines(), 1)}
    packages = [{"name": "http", "version": "0.13.1", "source": "hosted"},
                {"name": "dio", "version": None, "source": "hosted"},
                {"name": "uni_links", "version": "0.5.1"},
                {"name": "flutter", "version": "0.0.0", "source": "sdk"},
                {"name": "git_pkg", "version": "1.0.0", "source": "git"},
                {"name": "local", "version": "1.0.0", "source": "path"},
                {"name": "http", "version": "2.0.0"}, "junk", {"version": "1.0.0"}]
    findings = audit_packages(packages, "_sca/packages.txt", lambda name: lines.get(name, 0),
                              sf)
    summary = sorted((f.rule_id, f.line, f.severity, f.confidence) for f in findings)
    assert summary == [("FLUTTER-PUB-001", 1, "medium", 0.9),
                       ("FLUTTER-PUB-001", 2, "info", pubspec.UNREAD_CONFIDENCE),
                       ("FLUTTER-PUB-002", 3, "low", 0.8)]
    assert pubspec.UNREAD_CONFIDENCE == 0.3
    assert all(f.file == "_sca/packages.txt" and f.engines == ["flutter"] for f in findings)
    dio = at(findings, "FLUTTER-PUB-001", 2)
    assert dio.title == "Possibly vulnerable dependency: dio (version could not be read from " \
                        "the app)"
    assert "could not be read from the app" in dio.description
    assert dio.snippet == "dio" and "GHSA-9324-jv53-9cc8 is fixed in 5.0.0" in dio.fix
    assert at(findings, "FLUTTER-PUB-001", 1).snippet == "http 0.13.1"


def test_audit_packages_without_a_source_file():
    findings = audit_packages([{"name": "serverpod_auth_server", "version": ""}],
                              "_sca/packages.txt", lambda name: 0)
    assert len(findings) == 1 and findings[0].line == 1
    assert findings[0].snippet == "serverpod_auth_server" and findings[0].confidence == 0.3
    assert "GHSA-m6hm-gg8r-43xx is fixed in 2.9.5, 3.4.13 and 4.0.0-rc.1" in findings[0].fix
    assert findings[0].severity == "info"     # the critical advisories affect only some versions


def test_audit_packages_keeps_the_severity_when_every_version_is_affected(monkeypatch):
    every = pubspec.Advisory(id="GHSA-every", aliases=[], package="leaky",
                             affected=[{"introduced": "0"}], severity="high", cwes=[],
                             summary="Leaks tokens.", url="", source="cve-only")
    some = pubspec.Advisory(id="GHSA-some", aliases=[], package="leaky",
                            affected=[{"introduced": "0", "fixed": "2.0.0"}], severity="critical",
                            cwes=[], summary="Runs code.", url="", source="cve-only")
    monkeypatch.setattr(pubspec, "advisories_for",
                        lambda name: [every, some] if name == "leaky" else [])
    unread = audit_packages([{"name": "leaky", "version": None}], "_sca/packages.txt",
                            lambda name: 1)
    assert [(f.severity, f.confidence) for f in unread] == [("high", 0.35)]
    assert unread[0].title == "Vulnerable dependency: leaky (every version is affected)"
    assert "GHSA-every affects every version" in unread[0].description
    assert "GHSA-some" in unread[0].description           # the possible one is still listed
    known = audit_packages([{"name": "leaky", "version": "1.0.0"}], "_sca/packages.txt",
                           lambda name: 1)
    assert [(f.severity, f.confidence) for f in known] == [("critical", 0.9)]
