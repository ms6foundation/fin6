"""pytest conftest: make the tests/ directory importable as a flat package.

After the project split the harness lives at tests/harness.py (no longer
ms6/tests/harness.py).  This file adds the tests/ directory to sys.path so
that every test module can `from harness import ...` without qualification.
"""
import sys
from pathlib import Path

# tests/ itself must be on sys.path so `from harness import ...` resolves.
sys.path.insert(0, str(Path(__file__).resolve().parent))
# repo root must be on sys.path so `from ms6 import ...` resolves.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
