"""Universal APKs retain application-library evidence from every packaged ABI."""
from io import BytesIO
from pathlib import Path
import zipfile

import flutter_kit as kit

from sca.engines import secrets
from sca.flutter import apk, inventory


def package(tmp_path, additions):
    buffer = BytesIO(kit.build_apk(mode="none"))
    with zipfile.ZipFile(buffer, "a") as archive:
        for name, payload in additions.items():
            archive.writestr(name, payload)
    path = tmp_path / "universal.apk"
    path.write_bytes(buffer.getvalue())
    return path


def test_unique_values_in_secondary_abi_are_detected_with_that_library_location(tmp_path):
    values = {"arm64-v8a": "AIza" + "A" * 35, "x86_64": "AIza" + "B" * 35}
    additions = {f"lib/{abi}/libconfig.so":
                 f"\x7fELF\0https://{abi.replace('_', '-')}.native.audit.example/v1/api\0{key}\0".encode()
                 for abi, key in values.items()}
    ctx = apk.load_app(package(tmp_path, additions))
    files = {sf.rel: sf for sf in ctx.files}
    findings = [finding for sf in ctx.files for finding in secrets.scan_file(sf, rules=[])]
    result = inventory.build(ctx, ctx.files, findings, reveal_values=True)
    keys = {item["value"]: item for item in result["keys"]}
    for abi, key in values.items():
        rel = f"lib/{abi}/libconfig.so"
        assert rel in files and key in files[rel].lines
        assert any(site["file"] == rel for site in keys[key]["locations"])
        assert any(item["url"] == f"https://{abi.replace('_', '-')}.native.audit.example/v1/api"
                   for item in result["endpoints"])
    assert ctx.facts["native_string_coverage"]["abis"] == ["arm64-v8a", "x86_64"]
    assert set(ctx.facts["native_string_coverage"]["libraries_read"]) == set(additions)


def test_native_library_count_budget_applies_across_all_abis(tmp_path, monkeypatch):
    monkeypatch.setattr(apk, "MAX_OTHER_LIBS", 1)
    additions = {f"lib/{abi}/libconfig.so": f"{abi} native fixture value".encode()
                 for abi in ("arm64-v8a", "armeabi-v7a", "x86_64")}
    ctx = apk.load_app(package(tmp_path, additions))
    coverage = ctx.facts["native_string_coverage"]
    assert coverage["libraries_present"] == 3
    assert len(coverage["libraries_read"]) == 1
    assert len(coverage["libraries_omitted"]) == 2
    assert all(row["reason"] == "Native library count limit reached" for row in coverage["libraries_omitted"])
    assert any("only the first 1" in warning for warning in ctx.warnings)


def test_engine_and_validation_scope_is_explicit(tmp_path):
    ctx = apk.load_app(package(tmp_path, {
        "lib/arm64-v8a/libflutter.so": b"engine metadata fixture",
        "lib/x86_64/libVkLayer_test.so": b"validation metadata fixture",
    }))
    coverage = ctx.facts["native_string_coverage"]
    assert coverage["metadata_only"] == ["lib/arm64-v8a/libflutter.so", "lib/x86_64/libVkLayer_test.so"]
    assert coverage["libraries_read"] == []
    assert "metadata only" in coverage["scope"]
