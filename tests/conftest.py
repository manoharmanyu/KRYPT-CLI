"""
Pytest configuration and shared fixtures for KRYPT CLI test suite.
"""

import os
from pathlib import Path
import pytest
import tempfile

# Set up temporary test KRYPT home directory
@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    test_dir = tempfile.mkdtemp(prefix="krypt_test_")
    os.environ["KRYPT_HOME"] = test_dir
    from krypt.utils.filesystem import ensure_krypt_dirs
    ensure_krypt_dirs()
    yield test_dir
