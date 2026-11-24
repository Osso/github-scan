# GitHub scanning

`src/github_scan/` fetches and classifies GitHub content before releasing it to a reviewing agent. The [README](../../README.md) describes operation and deployment.

## What it must do

- [x] Fetch issue content and all comments; fetch PR reviews, inline comments and full diff unless discussion-only mode is requested.
- [x] Repository mode clones the repository into `~/Repos/<name>` (reusing a clone with the same origin), honours an optional `--ref`, and scans every UTF-8 text file in the working tree. Binary files, invalid UTF-8 and `.git` are skipped. On success it releases the clone path only; a blocked or failed scan deletes a clone created by that run.
- [x] Accept complete content beyond the previous 200,000-byte limit, including generated diffs and long lines, up to a shared 10,000,000-byte UTF-8 bound for each response and the serialized result.
- [x] Repository mode scans only text files up to 524,288 UTF-8 bytes each. Larger text files are not scanned, are deleted from the working tree before release and are listed under `excluded`, so every released text file was scanned; a reused clone restores them on the next checkout.
- [x] Repository mode has its own 50,000,000-byte bound on combined UTF-8 text, and classifies the chunks of all files concurrently under one shared request bound; a block still names the first injected file in path order.
- [x] Scan every character in bounded overlapping Unicode-safe chunks without truncation; release the entire result only after every chunk passes.
- [x] Complete pagination and block fetch errors or content beyond the shared limit instead of returning partial content.
- [x] Classify each chunk via OpenRouter's Decisions endpoint (`/api/alpha/decisions`) with `nace-ai/drex-max`, passing source `surface` and optional file `path` in `state`, and evaluate calibrated `noul` probabilities (`hijacks_agent`, `unauthorized_secret_or_cmd`) against the threshold.
- [x] Block suspected injection, skipped/failed checks, refusals and malformed responses, including in a late chunk after earlier chunks passed.
- [x] Release the scanned snapshot only after passing; return no raw content or credentials on blocked/error paths.
- [x] Report trusted, actionable classifier failure categories without exposing raw input, provider response bodies or credentials. HTTP 402 must identify a possible OpenRouter credit or API-key budget issue; other HTTP failures must include the status code; transport, JSON and verdict failures must be distinguishable. Do not trigger automatic billing or use a fallback detector.
- [x] Support UTF-8 standard input for additional fetched text without exposing it before classification.

## How it works

- [Operation, detector and deployment](../../README.md)

## Implementation inventory

- `src/github_scan/cli.py`: credential loading and buffered output boundary.
- `src/github_scan/github.py`: validated GitHub targets and complete REST fetching for issues and PRs.
- `src/github_scan/clone.py`: repository clone/update, text-file selection and the combined size bound.
- `src/github_scan/classifier.py`: `scan_content` for one blob, `scan_files` for a repository's files under one concurrency bound.
- `src/github_scan/classifier.py`: OpenRouter classifier call and fail-closed result handling.
- `src/github_scan/errors.py`: static failure categories.
- `src/github_scan/limits.py`: shared complete-content and chunk bounds.
- `deploy.sh`: local and SSH-host installation.

## Tests asserting this spec

- `tests/test_github.py`: fetch surfaces, pagination, request and size failures.
- `tests/test_classifier.py`: classifier request shape, verdict parsing, retries and fail-closed behavior.
- `tests/test_cli.py`: snapshot release and withholding at the CLI boundary.
- `tests/test_clone.py`: clone creation and reuse, binary skipping, oversized-file exclusion, size limits and cleanup on block.

## Verification history

Verified 2026-11-05 on the jev classifier replacement: 88 tests passed (Ruff lint and formatting included). Live scans through the installed copy returned `passed` for benign text, `BLOCKED` for direct and fake-policy injection text, and `passed` for a code comment quoting the phrase; the same benign input passed five consecutive runs. The classifier uses `typesafe/jev-router`, which routes to a cheap upstream model per request.

Verified 2026-11-04 on implementation `b3885d0`: independent verification passed all 94 tests, Ruff lint, and formatting (12 files). API-shaped tests cover refs, file/directory selection, wrapped Base64, response and bundle limits, incomplete blobs, and all-or-nothing release. A separate probe confirmed a shortened blob released no output and never reached the detector.

Installed-copy scans passed locally and on `agent-server`: default `octocat/Hello-World` resolved to `7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`; the remote file scan used that explicit commit. Local `pallets/markupsafe` at tag `3.0.3`, path `src/markupsafe`, resolved to `297fc8e356e6836a62087949245d09a28e9f1b13` and scanned five files containing 17,826 UTF-8 bytes. These exercised live GitHub acquisition and the real detector. A pass is not a safety guarantee.

The following evidence predates repository scanning.

Verified 2026-10-31 on production implementation `07cd65d`: 57 tests passed. A test-only lint correction at `151897d` passed the independent lint/format gate and all seven affected Unicode-coverage cases; production code was unchanged. Deployed source, rules and credentials permissions matched the checked state.

The installed scanner returned `passed` for wow-ui-sim PR #15 with 345,873 serialized bytes and a 314,857-byte diff, in 18.2 seconds. The running wow-ui-sim session confirmed adoption and its own successful normal retry. No direct-reader bypass or generated-file exclusion was used.

Earlier baseline `042a688` had 40 passing tests but did not support the longer PR #15 diff.

## Out of scope

- Hard enforcement against direct tool reads; the server rule requires use.
- Training a classifier or guaranteeing complete detection.
- Fetching linked pages, attachments, images or files outside the requested diff or repository selection.
