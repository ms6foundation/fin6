"""Entry point: python3 -m tests  (cwd: repo root)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_all import main  # noqa: E402

raise SystemExit(main())
