"""Clone a repository into the local repository root and read its text files."""

import os
import subprocess
from pathlib import Path

from .errors import ScanError

REPO_ROOT = Path.home() / "Repos"
BINARY_SNIFF_BYTES = 8000
ASSET_SUFFIXES = {
    ".bmp",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".otf",
    ".pdf",
    ".png",
    ".so",
    ".svg",
    ".tar",
    ".ttf",
    ".wasm",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}


def repo_name(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    if not name or name in {".", ".."} or not all(c.isalnum() or c in "-_." for c in name):
        raise ScanError("Invalid repository name")
    return name


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=600,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        raise ScanError("Repository clone failed")
    return result.stdout


def clone_repository(
    url: str, ref: str | None = None, root: Path | None = None
) -> tuple[Path, bool]:
    """Clone into the repository root, or update an existing clone of the same origin.

    Returns the checkout path and whether this call created it.
    """
    root = root or REPO_ROOT
    destination = root / repo_name(url)
    if destination.exists():
        origin = _git("-C", str(destination), "remote", "get-url", "origin").strip()
        if origin.rstrip("/") != url.rstrip("/") and origin.rstrip("/") != url.rstrip("/") + ".git":
            raise ScanError("Repository path already exists with a different origin")
        _git("-C", str(destination), "fetch", "--all", "--tags", "--prune")
    else:
        root.mkdir(parents=True, exist_ok=True)
        args = ["clone", "--quiet"]
        if ref:
            args += ["--branch", ref]
        _git(*args, url, str(destination))
        return destination, True
    if ref:
        _git("-C", str(destination), "checkout", "--quiet", ref)
    else:
        _git("-C", str(destination), "remote", "set-head", "origin", "--auto")
        _git("-C", str(destination), "checkout", "--quiet", "origin/HEAD")
        _git("-C", str(destination), "reset", "--hard", "--quiet", "origin/HEAD")
    return destination, False


def _is_text(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(BINARY_SNIFF_BYTES)
    except OSError:
        return False
    return b"\x00" not in head


def iter_text_files(root: Path):
    """Yield (relative path, text) for UTF-8 files, skipping .git, assets and binaries."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        if path.suffix.lower() in ASSET_SUFFIXES:
            continue
        if not _is_text(path):
            continue
        try:
            yield str(path.relative_to(root)), path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue


def skipped_assets(root: Path) -> list[str]:
    """Relative paths of asset files that are not scanned."""
    return [
        str(path.relative_to(root))
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and ".git" not in path.relative_to(root).parts
        and path.suffix.lower() in ASSET_SUFFIXES
    ]


def read_repository(root: Path, limit: int) -> dict:
    """Serialize every text file, or fail when the combined content exceeds limit."""
    files = []
    total = 0
    for relative, text in iter_text_files(root):
        total += len(text.encode("utf-8"))
        if total > limit:
            raise ScanError("Content exceeds the scan limit; content withheld.")
        files.append({"path": relative, "content": text})
    return {"files": files, "skipped": skipped_assets(root)}
