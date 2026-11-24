#!/usr/bin/env python3
"""Install locally, or transfer source and install on an SSH host."""

import argparse
import pathlib
import shlex
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="SSH host alias, for example agent-server")
    args = parser.parse_args()
    if args.host:
        remote = "/home/osso/Projects/cli/github-scan"
        setup = f"from pathlib import Path; Path({remote!r}).mkdir(parents=True, exist_ok=True)"
        run("ssh", args.host, shlex.join(["python3", "-c", setup]))
        run(
            "rsync",
            "-az",
            "--delete",
            "--exclude=.git",
            "--exclude=.venv",
            "--exclude=__pycache__",
            "--exclude=.pytest_cache",
            "--exclude=.ruff_cache",
            "--exclude=PLAN.md",
            f"{ROOT}/",
            f"{args.host}:{remote}/",
        )
        run("ssh", args.host, shlex.join(["python3", f"{remote}/deploy.sh"]))
        return
    run("uv", "sync", "--locked", "--no-dev", "--python", "3.13")
    link = pathlib.Path.home() / ".local/bin/github-scan"
    target = ROOT / ".venv/bin/github-scan"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        raise RuntimeError("Refusing to replace an existing non-symlink github-scan executable")
    link.symlink_to(target)
    run(str(link), "--help")


if __name__ == "__main__":
    main()
