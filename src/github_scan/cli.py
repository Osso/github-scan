"""Fetch, scan, then release content through one buffered output boundary."""

import argparse
import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

from github_scan.classifier import scan_content, scan_files
from github_scan.clone import clone_repository, read_repository
from github_scan.errors import InjectionDetected, ScanError
from github_scan.github import fetch_content, parse_repo_target, parse_target
from github_scan.limits import MAX_BYTES, REPO_MAX_BYTES

KEY_PATH = Path.home() / ".config/github-scan/openrouter-api-key"


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan GitHub content before releasing it. A pass is not a safety guarantee."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("url", nargs="?", help="GitHub issue, pull request, or repository URL")
    source.add_argument("--stdin", action="store_true", help="Scan UTF-8 text from standard input")
    parser.add_argument(
        "--no-diff",
        action="store_true",
        help="Read PR discussion only; do not fetch or release its diff",
    )
    parser.add_argument("--ref", help="Repository branch, tag, or commit to clone")
    return parser.parse_args(argv)


def load_key() -> str:
    try:
        key = KEY_PATH.read_text().strip()
    except OSError:
        raise ScanError("OpenRouter API key file is unavailable; content withheld.") from None
    if not key:
        raise ScanError("OpenRouter API key file is empty; content withheld.")
    return key


def read_content(args: argparse.Namespace) -> dict:
    """Return {"payload": scanned, "output": released, "cleanup": Path | None}."""
    if args.stdin:
        try:
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ScanError("Content exceeds the scan limit; content withheld.")
            text = raw.decode("utf-8")
        except UnicodeError:
            raise ScanError("Input must be UTF-8; content withheld.") from None
        return {"payload": text, "output": {"content": text}, "cleanup": None, "surface": "stdin"}
    try:
        parse_target(args.url)
    except ScanError:
        parse_repo_target(args.url)
    else:
        if args.ref is not None:
            raise ScanError("Repository options require a repository URL; content withheld.")
        content = fetch_content(
            args.url, include_diff=not args.no_diff, token=os.environ.get("GITHUB_TOKEN")
        )
        return {
            "payload": content,
            "output": {"content": content},
            "cleanup": None,
            "surface": "github_bundle",
        }
    if args.no_diff:
        raise ScanError("The no-diff option requires a GitHub URL; content withheld.")
    return clone_and_read(args.url, args.ref)


def clone_and_read(url: str, ref: str | None) -> dict:
    destination, created = clone_repository(url, ref)
    try:
        payload = read_repository(destination, REPO_MAX_BYTES)
    except ScanError:
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise
    return {
        "payload": payload,
        "output": {"path": str(destination), "skipped": payload["skipped"]},
        "cleanup": destination if created else None,
    }


def is_repository(payload: object) -> bool:
    return isinstance(payload, dict) and isinstance(payload.get("files"), list)


def scan_payload(payload: object, key: str, *, surface: str = "github_bundle") -> None:
    """Scan one blob, or every repository file concurrently so a block names its path."""
    if is_repository(payload):
        asyncio.run(scan_files(payload["files"], api_key=key))
        return
    asyncio.run(scan_content(json.dumps(payload, ensure_ascii=False), api_key=key, surface=surface))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cleanup: Path | None = None
    try:
        if args.stdin and (args.no_diff or args.ref is not None):
            raise ScanError("The no-diff option requires a GitHub URL; content withheld.")
        key = load_key()
        item = read_content(args)
        cleanup = item["cleanup"]
        payload = item["payload"]
        serialized = json.dumps(payload, ensure_ascii=False)
        if not is_repository(payload) and len(serialized.encode("utf-8")) > MAX_BYTES:
            raise ScanError("Content exceeds the scan limit; content withheld.")
        scan_payload(payload, key, surface=item.get("surface", "github_bundle"))
        output = json.dumps({"status": "passed", **item["output"]}, ensure_ascii=False)
    except InjectionDetected as error:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
        print(f"BLOCKED: {error}; content withheld.", file=sys.stderr)
        return 2
    except ScanError as error:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except Exception:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)
        print("ERROR: Scanner failed; content withheld.", file=sys.stderr)
        return 1
    print(output)
    return 0
