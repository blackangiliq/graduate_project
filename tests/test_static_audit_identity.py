from tools.audit_phone_apps import input_identity


def test_resume_identity_changes_when_input_detector_or_scope_changes(tmp_path):
    package = tmp_path / "base.apk"
    package.write_bytes(b"fixture-version-one")
    initial = input_identity(tmp_path, "detectors-one", False)
    assert initial == input_identity(tmp_path, "detectors-one", False)
    assert initial != input_identity(tmp_path, "detectors-two", False)
    assert initial != input_identity(tmp_path, "detectors-one", True)
    package.write_bytes(b"fixture-version-two")
    assert initial != input_identity(tmp_path, "detectors-one", False)
    (tmp_path / "split.apk").write_bytes(b"fixture-split")
    assert len(input_identity(tmp_path, "detectors-one", False)["input_apks"]) == 2
