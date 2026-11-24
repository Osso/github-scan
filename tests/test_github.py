import httpx
import pytest

from github_scan import github
from github_scan.errors import ScanError


@pytest.fixture
def transport(monkeypatch):
    original = httpx.Client

    def install(handler):
        monkeypatch.setattr(
            github.httpx,
            "Client",
            lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
        )

    monkeypatch.setattr(github.time, "sleep", lambda _: None)
    return install


def test_parse_target():
    assert github.parse_target("https://github.com/org/repo/pull/12/#discussion") == {
        "owner": "org",
        "repo": "repo",
        "kind": "pull",
        "number": 12,
    }


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b/issues/1",
        "https://evil.test/a/b/issues/1",
        "https://github.com/a/b/issues/0",
        "https://github.com/a/b/issues/01",
        "https://github.com/a/b/issues/-1",
        "https://github.com/a/b/issues/1?secret=x",
        "https://github.com/a/../issues/1",
        "https://github.com/a/b/issues/1/extra",
    ],
)
def test_invalid_target_does_not_echo(url):
    with pytest.raises(ScanError) as error:
        github.parse_target(url)
    assert url not in str(error.value)


def test_issue_second_page_and_auth(transport):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/comments"):
            page = request.url.params["page"]
            assert request.url.params["per_page"] == "100"
            if page == "1":
                return httpx.Response(200, json=[{"id": n, "body": str(n)} for n in range(100)])
            return httpx.Response(200, json=[{"id": 100, "body": "last"}])
        return httpx.Response(200, json={"title": "issue", "body": "body", "state": "open"})

    transport(handler)
    result = github.fetch_content("https://github.com/o/r/issues/1", token="secret")
    assert len(result["comments"]) == 101
    assert result["comments"][-1]["body"] == "last"
    assert result["item"]["state"] == "open"
    assert all(r.headers["authorization"] == "Bearer secret" for r in calls)
    assert all(r.url.host == "api.github.com" for r in calls)


def test_pull_all_surfaces_and_diff(transport):
    calls = []

    def handler(request):
        calls.append(request)
        path = request.url.path
        if request.headers["accept"] == "application/vnd.github.diff":
            return httpx.Response(200, text="diff --git a/a b/a\n+hello\n")
        if path.endswith("/reviews"):
            return httpx.Response(200, json=[{"body": "review", "state": "APPROVED"}])
        if path.endswith("/pulls/2/comments"):
            return httpx.Response(200, json=[{"body": "inline", "path": "a"}])
        if path.endswith("/issues/2/comments"):
            return httpx.Response(200, json=[{"body": "discussion"}])
        return httpx.Response(200, json={"title": "PR", "body": "description"})

    transport(handler)
    result = github.fetch_content("https://github.com/o/r/pull/2")
    assert result["comments"][0]["body"] == "discussion"
    assert result["reviews"][0]["body"] == "review"
    assert result["review_comments"][0]["body"] == "inline"
    assert result["diff"].endswith("+hello\n")
    calls.clear()
    result = github.fetch_content("https://github.com/o/r/pull/2", include_diff=False)
    assert "diff" not in result
    assert all(r.headers["accept"] != "application/vnd.github.diff" for r in calls)


@pytest.mark.parametrize("surface", ["reviews", "comments"])
def test_pull_second_page_review_surfaces(transport, surface):
    paged_path = f"/repos/o/r/pulls/2/{surface}"

    def handler(request):
        if request.url.path == paged_path:
            if request.url.params["page"] == "1":
                return httpx.Response(200, json=[{"id": n, "body": str(n)} for n in range(100)])
            return httpx.Response(200, json=[{"id": 100, "body": "last review"}])
        if request.url.path.endswith(("/reviews", "/comments")):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"title": "PR", "body": "description"})

    transport(handler)
    result = github.fetch_content("https://github.com/o/r/pull/2", include_diff=False)
    entries = result["reviews" if surface == "reviews" else "review_comments"]
    assert len(entries) == 101
    assert [entry["id"] for entry in entries] == list(range(101))
    assert entries[-1]["body"] == "last review"


def test_parse_repo_target():
    assert github.parse_repo_target("https://github.com/org/repo") == {
        "owner": "org",
        "repo": "repo",
        "kind": "repo",
    }
    assert github.parse_repo_target("https://github.com/org/repo/") == {
        "owner": "org",
        "repo": "repo",
        "kind": "repo",
    }


def test_pull_requested_via_issue_url_includes_pull_surfaces(transport):
    def handler(request):
        path = request.url.path
        if path.endswith("/issues/2"):
            return httpx.Response(200, json={"title": "PR", "body": "body", "pull_request": {}})
        if request.headers["accept"] == "application/vnd.github.diff":
            return httpx.Response(200, text="diff --git a/x b/x\n+changed\n")
        if path.endswith("/reviews"):
            return httpx.Response(200, json=[{"body": "review"}])
        if path.endswith("/comments"):
            return httpx.Response(200, json=[{"body": "comment"}])
        return httpx.Response(200, json={"title": "canonical PR", "body": "body"})

    transport(handler)
    result = github.fetch_content("https://github.com/o/r/issues/2")
    assert result["target"]["kind"] == "pull"
    assert result["item"]["title"] == "canonical PR"
    assert result["reviews"][0]["body"] == "review"
    assert result["review_comments"][0]["body"] == "comment"
    assert result["diff"].endswith("+changed\n")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(301, headers={"location": "https://evil.test"}),
        httpx.Response(404, text="secret content"),
        httpx.Response(200, json=[]),
        httpx.Response(200, content=b"not json secret"),
    ],
)
def test_failure_is_static(transport, response):
    transport(lambda request: response)
    with pytest.raises(ScanError) as error:
        github.fetch_content("https://github.com/o/r/issues/1")
    assert "secret" not in str(error.value)


def test_combined_content_limit(transport, monkeypatch):
    monkeypatch.setattr(github, "MAX_BYTES", 1_000)

    def handler(request):
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json=[{"body": "é" * 200}])
        return httpx.Response(200, json={"title": "x", "body": "é" * 325})

    transport(handler)
    with pytest.raises(ScanError, match="size limit"):
        github.fetch_content("https://github.com/o/r/issues/1")


def test_large_pull_diff_is_preserved(transport):
    diff = "diff --git a/table b/table\n+" + "generated," * 25_000 + "é\n"

    class DiffStream(httpx.SyncByteStream):
        def __iter__(self):
            encoded = diff.encode("utf-8")
            yield encoded[:200_001]
            yield encoded[200_001:-2]
            yield encoded[-2:]

    def handler(request):
        if request.headers["accept"] == "application/vnd.github.diff":
            return httpx.Response(200, stream=DiffStream())
        if request.url.path.endswith(("/reviews", "/comments")):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"title": "PR", "body": "description"})

    transport(handler)
    result = github.fetch_content("https://github.com/o/r/pull/15")
    assert len(diff.encode("utf-8")) > 200_000
    assert result["diff"] == diff


def test_response_stream_exceeding_shared_limit_stops_without_exposing_content(transport):
    chunks_read = []

    class LargeStream(httpx.SyncByteStream):
        def __iter__(self):
            for chunk in (b"x" * 5_000_000, b"x" * 5_000_000, b"secret", b"unread"):
                chunks_read.append(len(chunk))
                yield chunk

    transport(lambda request: httpx.Response(200, stream=LargeStream()))
    with pytest.raises(ScanError, match="size limit") as error:
        github.fetch_content("https://github.com/o/r/issues/1")
    assert "secret" not in str(error.value)
    assert chunks_read == [5_000_000, 5_000_000, 6]


def test_transient_retry_and_retry_after(transport, monkeypatch):
    calls = []
    delays = []
    monkeypatch.setattr(github.time, "sleep", delays.append)

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("secret", request=request)
        if len(calls) == 2:
            return httpx.Response(429, headers={"retry-after": "4"})
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"title": "ok", "body": None})

    transport(handler)
    monkeypatch.setattr(github.time, "sleep", delays.append)
    assert github.fetch_content("https://github.com/o/r/issues/1")["item"]["title"] == "ok"
    assert len(calls) == 4
    assert delays[1] >= 4


def test_excessive_retry_after_blocks(transport):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503, headers={"retry-after": "1000"})

    transport(handler)
    with pytest.raises(ScanError, match="delay"):
        github.fetch_content("https://github.com/o/r/issues/1")
    assert len(calls) == 1


def test_bad_pagination_blocks(transport):
    def handler(request):
        if request.url.path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[{"body": "x"}],
                headers={"link": '<https://evil.test/steal?page=2>; rel="next"'},
            )
        return httpx.Response(200, json={"title": "x", "body": "x"})

    transport(handler)
    with pytest.raises(ScanError, match="pagination"):
        github.fetch_content("https://github.com/o/r/issues/1")
