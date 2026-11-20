"""Shared fixtures for the gcp-sa-key-auditor test suite."""

import sys
from pathlib import Path

# The tool lives at the repo root; make it importable from the tests dir.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
