import stat
import zipfile

import pytest

from sca import sourcearchive
from sca.pipeline import ScanOptions, run_scan
from sca.ui import hosted


@pytest.mark.parametrize("members", [
    ["../outside.txt"],
    ["/absolute.txt"],
    ["C:\\outside.txt"],
    ["folder/AUX.txt"],
    ["src/Review.java", "SRC/Other.java"],
    ["src/Review.java", "src/Review.java/file.txt"],
])
def test_source_zip_rejects_unsafe_members(tmp_path, members):
    target = tmp_path / "source.zip"
    with zipfile.ZipFile(target, "w") as archive:
        for name in members:
            archive.writestr(name, "text")
    with pytest.raises(sourcearchive.ArchiveError):
        with sourcearchive.source_root(target, tmp_path):
            pytest.fail("The unsafe archive was extracted.")
    assert list(tmp_path.iterdir()) == [target]


def test_source_zip_rejects_links(tmp_path):
    target = tmp_path / "source.zip"
    link = zipfile.ZipInfo("not-code.py")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr(link, "ordinary.py")
    with pytest.raises(sourcearchive.ArchiveError, match="link or a special file"):
        with sourcearchive.source_root(target, tmp_path):
            pytest.fail("The link was extracted.")


def test_source_zip_enforces_limits_and_cleans_up(tmp_path, monkeypatch):
    target = tmp_path / "source.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("my-project/first.py", "x" * 1_000)
        archive.writestr("my-project/second.py", "y" * 1_000)
    with sourcearchive.source_root(target, tmp_path) as root:
        assert root.name == "my-project"
        assert (root / "first.py").read_text() == "x" * 1_000
    assert not root.exists()
    monkeypatch.setattr(sourcearchive, "MAX_EXPANDED_BYTES", 1_500)
    with pytest.raises(sourcearchive.ArchiveError, match="expands beyond"):
        with sourcearchive.source_root(target, tmp_path):
            pytest.fail("The expansion limit was bypassed.")
    monkeypatch.setattr(sourcearchive, "MAX_DIRECTORY_BYTES", 90)
    with pytest.raises(sourcearchive.ArchiveError, match="directory is too large"):
        with sourcearchive.source_root(target, tmp_path):
            pytest.fail("The directory limit was bypassed.")
    assert list(tmp_path.iterdir()) == [target]


def test_source_zip_with_only_unreadable_content_returns_error(tmp_path):
    target = tmp_path / "source.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("binary.png", b"\x00\x01")
    with pytest.raises(sourcearchive.ArchiveError, match="no readable source"):
        run_scan(str(target), ScanOptions(save=False, use_feedback=False, work_dir=tmp_path))
    assert list(tmp_path.iterdir()) == [target]


def test_hosted_server_path_stays_in_scope(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "safe.py").write_text("print(42)\n", encoding="utf-8")
    outside = tmp_path / "another.py"
    outside.write_text("print(0)\n", encoding="utf-8")
    monkeypatch.setenv("SCA_SCAN_ROOT", str(projects))
    progress = lambda *_: None
    for name in ("../another.py", str(outside)):
        with pytest.raises(hosted.HostedInputError, match="inside the server project directory"):
            hosted.scan_path(name, ScanOptions(), progress)
    result = hosted.scan_path(str(projects / "safe.py"), ScanOptions(), progress)
    assert result.target == "safe.py"
    assert result.files_scanned == 1
    assert result.scan_id is None


def test_hosted_server_path_rejects_symlinks(tmp_path, monkeypatch):
    projects = tmp_path / "projects"
    projects.mkdir()
    outside = tmp_path / "another.py"
    outside.write_text("print(0)\n", encoding="utf-8")
    try:
        (projects / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("creating a symlink is unavailable")
    monkeypatch.setenv("SCA_SCAN_ROOT", str(projects))
    for location in ("link.py", "."):
        with pytest.raises(hosted.HostedInputError, match="links or special files"):
            hosted.scan_path(location, ScanOptions(), lambda *_: None)
