"""Fetch GitHub content without releasing it before scanning."""

import json
import random
import re
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, urlsplit

import httpx

from .errors import ScanError
from .limits import MAX_BYTES

API = "https://api.github.com"
TARGET = re.compile(
    r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/(issues|pull)/([1-9][0-9]*)/?(?:#[^\s]*)?\Z"
)
REPO_TARGET = re.compile(r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/?(?:#[^\s]*)?\Z")


def parse_target(url: str) -> dict:
    match = TARGET.fullmatch(url)
    if not match or match[2] in {".", ".."}:
        raise ScanError("Invalid GitHub target")
    try:
        number = int(match[4])
    except ValueError:
        raise ScanError("Invalid GitHub target") from None
    return {"owner": match[1], "repo": match[2], "kind": match[3], "number": number}


def parse_repo_target(url: str) -> dict:
    match = REPO_TARGET.fullmatch(url)
    if not match or match[2] in {".", ".."}:
        raise ScanError("Invalid GitHub target")
    return {"owner": match[1], "repo": match[2], "kind": "repo"}


def _check_size(value: object) -> None:
    try:
        size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
    except (ValueError, UnicodeError, TypeError):
        raise ScanError("Invalid GitHub response") from None
    if size > MAX_BYTES:
        raise ScanError("GitHub content exceeds size limit")


def _retry_delay(value: str | None, attempt: int) -> float:
    delay = 2**attempt + random.uniform(0, 0.5)
    if value:
        try:
            if value.isascii() and value.isdigit():
                requested = int(value)
            else:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    raise ValueError
                requested = max(0, (date - datetime.now(UTC)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            raise ScanError("Invalid GitHub retry delay") from None
        delay = max(delay, requested)
    if delay > 30:
        raise ScanError("GitHub retry delay exceeds limit")
    return delay


def _request(
    client: httpx.Client, path: str, *, params: dict | None = None, diff: bool = False
) -> tuple[bytes, str | None]:
    for attempt in range(4):
        try:
            with client.stream(
                "GET",
                API + path,
                params=params,
                headers={
                    "Accept": "application/vnd.github.diff"
                    if diff
                    else "application/vnd.github+json"
                },
            ) as response:
                if response.status_code == 429 or 500 <= response.status_code <= 599:
                    if attempt == 3:
                        raise ScanError("GitHub request failed")
                    delay = _retry_delay(response.headers.get("retry-after"), attempt)
                elif response.status_code != 200:
                    raise ScanError("GitHub request failed")
                else:
                    if diff and "json" in response.headers.get("content-type", "").lower():
                        raise ScanError("Invalid GitHub response")
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > MAX_BYTES:
                            raise ScanError("GitHub content exceeds size limit")
                    return bytes(content), response.headers.get("link")
        except httpx.TransportError:
            if attempt == 3:
                raise ScanError("GitHub request failed") from None
            delay = _retry_delay(None, attempt)
        time.sleep(delay)
    raise ScanError("GitHub request failed")


def _json(content: bytes, expected: type) -> object:
    try:
        value = json.loads(content)
    except (ValueError, UnicodeError, RecursionError):
        raise ScanError("Invalid GitHub response") from None
    if not isinstance(value, expected):
        raise ScanError("Invalid GitHub response")
    return value


def _pages(client: httpx.Client, path: str) -> list:
    result = []
    page = 1
    while True:
        content, link = _request(client, path, params={"per_page": 100, "page": page})
        items = _json(content, list)
        if len(items) > 100 or any(not isinstance(item, dict) for item in items):
            raise ScanError("Invalid GitHub response")
        result.extend(items)
        _check_size(result)
        next_url = None
        if link:
            try:
                links = httpx.Response(200, headers={"link": link}).links
                next_url = links.get("next", {}).get("url")
                if 'rel="next"' in link and not next_url:
                    raise ValueError
                if next_url:
                    parsed = urlsplit(next_url)
                    query = parse_qs(parsed.query, strict_parsing=True)
                    if (parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) != (
                        "https",
                        "api.github.com",
                        path,
                        "",
                    ) or query != {"per_page": ["100"], "page": [str(page + 1)]}:
                        raise ValueError
            except (ValueError, TypeError):
                raise ScanError("Invalid GitHub pagination") from None
        if not next_url and len(items) < 100:
            return result
        if not items:
            raise ScanError("Invalid GitHub pagination")
        page += 1


def fetch_content(url: str, *, include_diff: bool = True, token: str | None = None) -> dict:
    target = parse_target(url)
    base = f"/repos/{target['owner']}/{target['repo']}"
    number = target["number"]
    is_pr = target["kind"] == "pull"
    path = f"{base}/{'pulls' if is_pr else 'issues'}/{number}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(headers=headers, timeout=15.0, follow_redirects=False) as client:
            content, _ = _request(client, path)
            item = _json(content, dict)
            if not isinstance(item.get("title"), str) or not isinstance(
                item.get("body"), (str, type(None))
            ):
                raise ScanError("Invalid GitHub response")
            if not is_pr and "pull_request" in item:
                is_pr = True
                target["kind"] = "pull"
                path = f"{base}/pulls/{number}"
                content, _ = _request(client, path)
                item = _json(content, dict)
                if not isinstance(item.get("title"), str) or not isinstance(
                    item.get("body"), (str, type(None))
                ):
                    raise ScanError("Invalid GitHub response")
            result = {
                "target": target,
                "item": item,
                "comments": _pages(client, f"{base}/issues/{number}/comments"),
            }
            _check_size(result)
            if is_pr:
                result["reviews"] = _pages(client, f"{path}/reviews")
                _check_size(result)
                result["review_comments"] = _pages(client, f"{path}/comments")
                _check_size(result)
                if include_diff:
                    content, _ = _request(client, path, diff=True)
                    try:
                        result["diff"] = content.decode("utf-8")
                    except UnicodeError:
                        raise ScanError("Invalid GitHub response") from None
            _check_size(result)
            return result
    except (httpx.HTTPError, ValueError):
        raise ScanError("GitHub request failed") from None
