from test_flutter_checks import android_project, run, PROVIDER_MANIFEST, line_of


PATHS = '''<resources>
  <paths>
    <root-path name="camera_photos" path="" />
    <external-files-path name="images" path="." />
  </paths>
</resources>'''


def test_custom_provider_wrapped_paths_follow_androidx_parsing(tmp_path):
    manifest = PROVIDER_MANIFEST.replace("androidx.core.content.FileProvider", "example.TakePhotoProvider")
    ctx, files = android_project(tmp_path, manifest, resources={"shared_paths": PATHS})
    found = [f for f in run(ctx, files) if f.rule_id == "ANDROID-FILEPROVIDER-001"]
    assert any(f.line == line_of(PATHS, "<root-path") and f.severity == "high" for f in found)


def test_unreferenced_wrapped_resource_is_not_a_provider_exposure(tmp_path):
    safe = '<paths><cache-path name="shared" path="images/" /></paths>'
    ctx, files = android_project(tmp_path, PROVIDER_MANIFEST,
                                 resources={"shared_paths": safe, "unreferenced": PATHS})
    assert not any(f.rule_id == "ANDROID-FILEPROVIDER-001" for f in run(ctx, files))
