#!/usr/bin/env python3
"""Run the full test suite or one pytest selection."""

import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent
raise SystemExit(
    subprocess.run(["uv", "run", "--locked", "pytest", *sys.argv[1:]], cwd=root).returncode
)
