"""
Ensure tests use an isolated, throwaway SQLite database instead of the
real forensics.db used by the running application. This module-level
code runs before test modules are imported (pytest loads conftest.py
first), so `app.database` picks up FORENSICS_DB_PATH on first import.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_tmp_dir = tempfile.mkdtemp(prefix="forensics_test_")
os.environ["FORENSICS_DB_PATH"] = os.path.join(_tmp_dir, "test_forensics.db")
