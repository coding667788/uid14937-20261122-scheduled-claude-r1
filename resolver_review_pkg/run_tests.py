"""隔离模式下的 unittest 启动器：python -I run_tests.py"""

from __future__ import annotations

import os
import sys
import unittest

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
if _PACKAGE_DIR not in sys.path:
    sys.path.insert(0, _PACKAGE_DIR)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(
        start_dir=os.path.join(_PACKAGE_DIR, "tests"),
        pattern="test_*.py",
        top_level_dir=_PACKAGE_DIR,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
