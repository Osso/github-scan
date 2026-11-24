"""Repository cloning and text selection for repository scans."""

import json

import pytest

from github_scan import cli, clone
from github_scan.errors import InjectionDetected, ScanError

URL = "https://github.com/o/r"


def fake_git(monkeypatch, calls, *, origin=URL, fail_on=None):
    def git(*args, cwd=None):
        calls.append((args, cwd))
        if fail_on and fail_on in args:
            raise ScanError("Repository clone failed")
        if args[0] == "-C" and len(args) > 2 and args[2] == "remote":
            return origin + "\n"
        if "clone" in args:
            destination = args[-1]
            import os

            os.makedirs(destination, exist_ok=True)
            with open(os.path.join(destination, "main.py"), "w") as handle:
                handle.write("print('hello')\n")
            return ""
        return ""

    monkeypatch.setattr(clone, "_git", git)


def test_repo_name_is_derived_and_validated():
    assert clone.repo_name("https://github.com/o/r") == "r"
    assert clone.repo_name("https://github.com/o/r.git") == "r"
    assert clone.repo_name("https://github.com/o/r/") == "r"
    for bad in ["https://github.com/o/..", "https://github.com/o/a b"]:
        with pytest.raises(ScanError, match="Invalid repository name"):
            clone.repo_name(bad)


def test_new_clone_returns_path_and_created_flag(monkeypatch, tmp_path):
    calls = []
    fake_git(monkeypatch, calls)

    path, created = clone.clone_repository(URL, root=tmp_path)

    assert path == tmp_path / "r"
    assert created is True
    assert (path / "main.py").is_file()


def test_existing_clone_is_updated_and_not_owned(monkeypatch, tmp_path):
    destination = tmp_path / "r"
    destination.mkdir()
    calls = []
    fake_git(monkeypatch, calls)

    path, created = clone.clone_repository(URL, ref="v1", root=tmp_path)

    assert path == destination
    assert created is False
    assert any("fetch" in args for args, _ in calls)
    assert any("checkout" in args for args, _ in calls)


def test_existing_clone_without_ref_sets_origin_head(monkeypatch, tmp_path):
    destination = tmp_path / "r"
    destination.mkdir()
    calls = []
    fake_git(monkeypatch, calls)

    path, created = clone.clone_repository(URL, root=tmp_path)

    assert path == destination
    assert created is False
    assert any("set-head" in args for args, _ in calls)
    assert any("origin/HEAD" in args and "checkout" in args for args, _ in calls)


def test_existing_clone_with_other_origin_is_rejected(monkeypatch, tmp_path):
    (tmp_path / "r").mkdir()
    fake_git(monkeypatch, [], origin="https://github.com/other/thing")

    with pytest.raises(ScanError, match="different origin"):
        clone.clone_repository(URL, root=tmp_path)


def test_read_repository_skips_binary_and_git_directories(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print(1)\n")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\x00binary")
    (tmp_path / "sticker.svg").write_text("<svg><text>hello</text></svg>")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("secret")

    payload = clone.read_repository(tmp_path, limit=10_000)

    assert [entry["path"] for entry in payload["files"]] == ["src/a.py"]
    assert payload["skipped"] == ["logo.png", "sticker.svg"]


def test_read_repository_enforces_the_combined_limit(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 500)

    with pytest.raises(ScanError, match="Content exceeds the scan limit"):
        clone.read_repository(tmp_path, limit=100)


def test_repo_url_releases_only_the_clone_path(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(clone, "REPO_ROOT", tmp_path)
    calls = []
    fake_git(monkeypatch, calls)
    scanned = []

    async def detect(files, *, api_key):
        scanned.extend(entry["content"] for entry in files)
        assert capsys.readouterr().out == ""

    monkeypatch.setattr(cli, "scan_files", detect)
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "key")
    (tmp_path / "key").write_text("test-key")

    assert cli.main([URL]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {
        "status": "passed",
        "path": str(tmp_path / "r"),
        "skipped": [],
    }
    assert scanned == ["print('hello')\n"]


def test_blocked_repo_scan_removes_the_new_clone(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(clone, "REPO_ROOT", tmp_path)
    fake_git(monkeypatch, [])

    async def detect(files, *, api_key):
        raise InjectionDetected("injected")

    monkeypatch.setattr(cli, "scan_files", detect)
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "key")
    (tmp_path / "key").write_text("test-key")

    assert cli.main([URL]) == 2
    assert capsys.readouterr().out == ""
    assert not (tmp_path / "r").exists()


def test_blocked_repo_scan_keeps_an_existing_clone(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(clone, "REPO_ROOT", tmp_path)
    (tmp_path / "r").mkdir()
    (tmp_path / "r" / "main.py").write_text("print('hello')\n")
    fake_git(monkeypatch, [])

    async def detect(files, *, api_key):
        raise InjectionDetected("injected")

    monkeypatch.setattr(cli, "scan_files", detect)
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "key")
    (tmp_path / "key").write_text("test-key")

    assert cli.main([URL]) == 2
    assert (tmp_path / "r").is_dir()


def test_ref_is_rejected_for_issue_urls(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "key")
    (tmp_path / "key").write_text("test-key")

    assert cli.main(["https://github.com/o/r/issues/1", "--ref", "main"]) == 1
    assert capsys.readouterr().out == ""


def test_repository_beyond_the_bundle_limit_is_scanned_whole(monkeypatch, tmp_path, capsys):
    """Repositories use their own bound: 11 MB of text passes the 10 MB bundle limit."""
    monkeypatch.setattr(clone, "REPO_ROOT", tmp_path)
    fake_git(monkeypatch, [])
    big = "x = 1\n" * 2_000_000
    original_clone = clone._git

    def git(*args, cwd=None):
        result = original_clone(*args, cwd=cwd)
        if "clone" in args:
            (tmp_path / "r" / "big.py").write_text(big)
        return result

    monkeypatch.setattr(clone, "_git", git)
    scanned = {}

    async def detect(files, *, api_key):
        scanned.update({entry["path"]: len(entry["content"]) for entry in files})

    monkeypatch.setattr(cli, "scan_files", detect)
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "key")
    (tmp_path / "key").write_text("test-key")

    assert len(big.encode()) > cli.MAX_BYTES
    assert cli.main([URL]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"
    assert scanned == {"big.py": len(big), "main.py": len("print('hello')\n")}
