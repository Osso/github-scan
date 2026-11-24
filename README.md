# github-scan

Fetch GitHub issue, PR, or repository code content, classify it with `nace-ai/drex-max` through OpenRouter's Decisions API, and return the content only if the classification passes. A persistent rule on `aso` and `agent-server` requires this command instead of direct GitHub reads, except for repositories owned by the `Globalcomix` organization. This is a detection layer, not mandatory tool interception or a guarantee against injection.

## Use

```text
github-scan https://github.com/OWNER/REPO/issues/123
github-scan https://github.com/OWNER/REPO/pull/456
github-scan https://github.com/OWNER/REPO/pull/456 --no-diff
github-scan https://github.com/OWNER/REPO
github-scan https://github.com/OWNER/REPO --ref v2.1.0
github-scan --stdin
```

On `aso` and `agent-server`, use `/home/osso/.local/bin/github-scan` in place of the bare command above, as specified by the persistent rule.

Standard input accepts UTF-8 text only, not images or other binary data; capture fetched text without displaying it to the agent, then supply it to this mode. Stdin is checked as one input, not fetched or paginated by the scanner, and cannot be combined with `--no-diff`. Do not use another reader after a blocked scan. A pass does not make external instructions trusted.

Issue mode includes the item and all comments. PR mode also includes all reviews, inline review comments and the full diff. `--no-diff` omits the diff entirely; it does not approve later direct diff reads. Repository mode clones the repository into `~/Repos/<name>` (an existing clone of the same origin is fetched and reset to the requested ref) and scans every UTF-8 text file in the working tree. It accepts an optional branch, tag, or commit `--ref`; the default branch is used when omitted. On success the released output is the clone path, not the file contents: `{"status":"passed","path":"/home/osso/Repos/<name>"}`. A blocked or failed scan deletes a clone that this run created; an existing clone is left in place. Binary files, invalid UTF-8 and `.git` are skipped and are not scanned. This is text scanning, not file-format detection. Linked pages, attachments, images and other remote content outside the clone are not fetched; additional text must be scanned before reading.

Each GitHub response and the combined JSON-serialized content must fit within 10,000,000 UTF-8 bytes. Stdin has the same raw-byte limit and must also fit after JSON serialization; escaping and JSON quotation marks count toward that limit. Oversized content blocks rather than being truncated. Generated files and long lines are included, not filtered out.

The complete serialized content is checked in chunks of at most 32,000 Unicode characters with 1,000-character overlap, up to 16 chunks in flight. Every character is covered. The entire result is withheld until every chunk passes; a late detection or failure releases nothing. Long content requires more API calls and takes longer. Overlap reduces boundary splits, but separate checks do not preserve all cross-chunk context; detection remains imperfect.

Output is JSON containing `status: passed` and either `content` (issue, PR, stdin) or `path` (repository), emitted only after the whole check completes. Exit codes: `0` passed, `2` suspected injection, `1` fetch/configuration/detector failure. Argument errors use `2` with no content. Blocked/error scans produce no standard output. Standard error provides trusted, actionable diagnostic categories: HTTP 402 identifies a possible OpenRouter credit or API-key budget issue; other HTTP failures include the status code; transport, JSON and verdict failures have distinct categories. For HTTP 402, check the OpenRouter account credits and the API key's budget or spending limit. Raw input, provider response bodies and credentials are not printed. Diagnostics do not trigger automatic billing or a fallback detector.

## Credentials and data disclosure

Store the OpenRouter API key in `~/.config/github-scan/openrouter-api-key` with mode `0600` and its directory `0700`. Do not commit keys or put them in command arguments. Optional `GITHUB_TOKEN` is sent as a GitHub bearer token and can authorize access to private repositories when it has sufficient permissions. Public reads can be made without a token, subject to GitHub access and rate limits. There is no lookup through other credential stores.

**The content is sent to OpenRouter, which routes the Decisions request to `nace-ai/drex-max` and its provider.** Content includes fetched GitHub metadata, comments, diffs and repository code, or the supplied stdin text, including private material. Do not scan material that you are not authorized to disclose. OpenRouter API usage may incur charges; billing is separate from any subscription. Any promotional credits and their eligibility depend on the account's terms.

## Classifier and dependencies

The classifier sends each chunk as structured `state` (`surface`, optional `path`, and `content`) to OpenRouter's `/api/alpha/decisions` endpoint with `model: nace-ai/drex-max` and evaluates two `noul` checks (`hijacks_agent` and `unauthorized_secret_or_cmd`). Any check scoring `>= 0.5`, a malformed verdict, a non-200 response, malformed JSON, or an exhausted retry budget blocks the entire result, including when earlier chunks passed. Transient `429`/`5xx` and malformed JSON responses are retried up to three times with exponential backoff. No keyword classifier or second detector is used.

- `httpx`: GitHub and OpenRouter requests, and provider-boundary tests.
- Development only: `pytest` for tests and `ruff` for formatting/lint.

`uv.lock` records exact transitive versions. Updates require changing the declared constraints where applicable and regenerating the lock.

## Install and test

Python 3.13 and `uv` are used by the deployment script; `uv` can provision Python. Remote deployment also needs SSH and rsync. The scripts have Python shebangs despite their conventional `.sh` names.

```text
./run-tests.sh
./run-tests.sh tests/test_classifier.py tests/test_clone.py
./deploy.sh
./deploy.sh --host agent-server
```

Local installation uses a locked environment and links `~/.local/bin/github-scan` to its console script. Remote installation syncs this project to `/home/osso/Projects/cli/github-scan` and performs the same install. Keys and agent rules are installed separately; deployment never transfers credentials. See [the scanner contract](docs/specs/github-scan.md).
