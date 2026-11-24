import io
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from github_scan import classifier, cli
from github_scan.errors import InjectionDetected, ScanError


@pytest.fixture
def configured(monkeypatch, tmp_path):
    key = tmp_path / "key"
    key.write_text("private-test-api-key")
    monkeypatch.setattr(cli, "KEY_PATH", key)
    return key


def test_only_release_the_exact_content_that_passed(configured, monkeypatch, capsys):
    bundle = {"title": "Fix café rendering", "comments": ["A concrete reproduction"]}
    monkeypatch.setattr(cli, "fetch_content", lambda *a, **k: bundle)

    async def detect(content, *, api_key, surface="github_bundle"):
        assert json.loads(content) == bundle
        assert api_key == "private-test-api-key"
        assert surface == "github_bundle"
        assert capsys.readouterr().out == ""

    monkeypatch.setattr(cli, "scan_content", detect)
    assert cli.main(["https://github.com/org/repo/pull/12"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "passed", "content": bundle}
    assert output.err == ""


@pytest.mark.parametrize(
    "failure,expected",
    [
        (InjectionDetected("untrusted"), 2),
        (ScanError("Check failed"), 1),
        (RuntimeError("DO_NOT_RELEASE"), 1),
    ],
)
def test_blocked_or_failed_scan_releases_no_content(
    configured, monkeypatch, capsys, failure, expected
):
    monkeypatch.setattr(cli, "fetch_content", lambda *a, **k: {"body": "DO_NOT_RELEASE"})

    async def detect(*a, **k):
        raise failure

    monkeypatch.setattr(cli, "scan_content", detect)
    assert cli.main(["https://github.com/org/repo/issues/12"]) == expected
    output = capsys.readouterr()
    assert output.out == ""
    assert "DO_NOT_RELEASE" not in output.err
    assert "private-test-api-key" not in output.err


def test_fetch_error_cannot_echo_remote_content(configured, monkeypatch, capsys):
    def fail(*a, **k):
        raise RuntimeError("UNTRUSTED_ERROR_BODY")

    monkeypatch.setattr(cli, "fetch_content", fail)
    assert cli.main(["https://github.com/org/repo/issues/12"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "UNTRUSTED_ERROR_BODY" not in output.err


def test_missing_key_blocks_before_fetch(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "KEY_PATH", tmp_path / "missing")
    assert cli.main(["https://github.com/org/repo/issues/12"]) == 1
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "payload,diagnostic",
    [
        (b"x" * (cli.MAX_BYTES + 1), b"Content exceeds the scan limit"),
        (bytes([0xFF]), b"Input must be UTF-8"),
    ],
)
def test_process_stdin_failure_releases_nothing(tmp_path, payload, diagnostic):
    key = tmp_path / ".config/github-scan/openrouter-api-key"
    key.parent.mkdir(parents=True)
    key.write_text("private-test-api-key")
    result = subprocess.run(
        [str(Path(sys.executable).parent / "github-scan"), "--stdin"],
        input=payload,
        capture_output=True,
        env={**os.environ, "HOME": str(tmp_path)},
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert b"private-test-api-key" not in result.stderr
    assert diagnostic in result.stderr


@pytest.mark.parametrize("verdict,expected", [("safe", 0), ("flagged", 2), ("failure", 1)])
def test_long_content_is_only_released_after_all_checks(
    configured, monkeypatch, capsys, verdict, expected
):
    tail = "LATE_UNTRUSTED_TAIL"
    bundle = {"diff": "generated value café 🥑\n" * 15_000 + tail}
    assert len(json.dumps(bundle, ensure_ascii=False).encode()) > 200_000
    monkeypatch.setattr(cli, "fetch_content", lambda *a, **k: bundle)
    reached_tail = []

    def provider(request):
        assert capsys.readouterr().out == ""
        sent = json.loads(request.content)["state"]["content"]
        at_tail = tail in sent
        if at_tail:
            reached_tail.append(True)
        if at_tail and verdict == "failure":
            return httpx.Response(401, json={"error": {"message": tail}})
        score = 0.95 if at_tail and verdict == "flagged" else 0.01
        return httpx.Response(
            200,
            json={
                "answers": {
                    "hijacks_agent": {"type": "noul", "noul": score},
                    "unauthorized_secret_or_cmd": {"type": "noul", "noul": 0.01},
                }
            },
        )

    original_client = httpx.AsyncClient

    def client(**kwargs):
        return original_client(transport=httpx.MockTransport(provider), **kwargs)

    monkeypatch.setattr(classifier.httpx, "AsyncClient", client)
    assert cli.main(["https://github.com/org/repo/pull/15"]) == expected
    output = capsys.readouterr()
    assert reached_tail
    if expected == 0:
        assert json.loads(output.out) == {"status": "passed", "content": bundle}
        assert output.err == ""
    else:
        assert output.out == ""
        assert tail not in output.err
        assert "private-test-api-key" not in output.err


class FakeStdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def run_stdin_main(monkeypatch, capsys, payload: bytes, handler) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "stdin", FakeStdin(payload))
    original_client = httpx.AsyncClient

    def client(**kwargs):
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(classifier.httpx, "AsyncClient", client)
    code = cli.main(["--stdin"])
    output = capsys.readouterr()
    return code, output.out, output.err


def test_stdin_http402_withholds_content_with_actionable_diagnostic(
    configured, monkeypatch, capsys
):
    calls = []
    provider_body = {
        "error": {
            "message": "DO_NOT_RELEASE insufficient credits",
            "metadata": {"key": "private-test-api-key"},
        }
    }

    def handler(request):
        calls.append(1)
        return httpx.Response(402, json=provider_body)

    payload = b"UNTRUSTED_STDIN_BODY"
    code, out, err = run_stdin_main(monkeypatch, capsys, payload, handler)
    assert code == 1
    assert out == ""
    assert "HTTP 402" in err
    assert "credits" in err
    assert "UNTRUSTED_STDIN_BODY" not in err
    assert "DO_NOT_RELEASE" not in err
    assert "private-test-api-key" not in err
    assert len(calls) == 1


def test_stdin_pass_releases_exact_content(configured, monkeypatch, capsys):
    def handler(request):
        assert json.loads(request.content)["state"]["surface"] == "stdin"
        return httpx.Response(
            200,
            json={
                "answers": {
                    "hijacks_agent": {"type": "noul", "noul": 0.01},
                    "unauthorized_secret_or_cmd": {"type": "noul", "noul": 0.01},
                }
            },
        )

    payload = "plain café 🥑".encode()
    code, out, err = run_stdin_main(monkeypatch, capsys, payload, handler)
    assert code == 0
    assert err == ""
    assert json.loads(out) == {"status": "passed", "content": payload.decode()}


def test_stdin_late_chunk_402_releases_nothing(configured, monkeypatch, capsys):
    tail = "LATE_UNTRUSTED_TAIL"
    payload = ("x" * 40_000 + tail).encode()

    def handler(request):
        sent = json.loads(request.content)["state"]["content"]
        if tail in sent:
            return httpx.Response(402, json={"error": {"message": tail}})
        return httpx.Response(
            200,
            json={
                "answers": {
                    "hijacks_agent": {"type": "noul", "noul": 0.01},
                    "unauthorized_secret_or_cmd": {"type": "noul", "noul": 0.01},
                }
            },
        )

    code, out, err = run_stdin_main(monkeypatch, capsys, payload, handler)
    assert code == 1
    assert out == ""
    assert "HTTP 402" in err
    assert tail not in err
    assert "private-test-api-key" not in err


def test_oversized_bundle_is_not_partially_released(configured, monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_content", lambda *a, **k: {"body": "é" * cli.MAX_BYTES})
    assert cli.main(["https://github.com/org/repo/issues/12"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "limit" in output.err
