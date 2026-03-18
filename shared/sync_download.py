#!/usr/bin/env python3
"""Backward-compatible wrapper for the packaged Python client."""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from syncd_client.cli import run


if __name__ == "__main__":
    run()
