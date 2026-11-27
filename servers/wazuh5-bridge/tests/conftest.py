import sys
from pathlib import Path

# The tests import fixtures.py from this directory (pytest runs with --import-mode=importlib).
sys.path.insert(0, str(Path(__file__).resolve().parent))
