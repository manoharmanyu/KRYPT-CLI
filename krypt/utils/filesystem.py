"""
Filesystem utilities for KRYPT CLI.
Manages KRYPT home directory, storage paths, and log locations with robust fallback.
"""

from pathlib import Path
import os
import tempfile


def _determine_krypt_home() -> Path:
    """Determine the writable KRYPT_HOME directory."""
    # 1. Explicit env var
    env_dir = os.environ.get("KRYPT_HOME")
    if env_dir:
        p = Path(env_dir)
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            pass

    # 2. Standard ~/.krypt
    home_p = Path(os.path.expanduser("~/.krypt"))
    try:
        home_p.mkdir(parents=True, exist_ok=True)
        # Test writability
        test_file = home_p / ".write_test"
        test_file.touch()
        test_file.unlink()
        return home_p
    except Exception:
        pass

    # 3. Fallback to package root or current working directory .krypt
    cwd_p = Path.cwd() / ".krypt"
    try:
        cwd_p.mkdir(parents=True, exist_ok=True)
        return cwd_p
    except Exception:
        pass

    # 4. Fallback to tmp
    tmp_p = Path(tempfile.gettempdir()) / "krypt_cli"
    tmp_p.mkdir(parents=True, exist_ok=True)
    return tmp_p


KRYPT_HOME = _determine_krypt_home()
KRYPT_CONFIG_FILE = KRYPT_HOME / "config.yaml"
KRYPT_DB_FILE = KRYPT_HOME / "krypt.db"
KRYPT_RESULTS_DIR = KRYPT_HOME / "results"
KRYPT_REPORTS_DIR = KRYPT_HOME / "reports"
KRYPT_LOGS_DIR = KRYPT_HOME / "logs"
KRYPT_LOG_FILE = KRYPT_LOGS_DIR / "krypt.log"
KRYPT_LAB_PID_FILE = KRYPT_HOME / "lab.pid"


def ensure_krypt_dirs() -> None:
    """Ensure all KRYPT directories exist on the filesystem."""
    global KRYPT_HOME, KRYPT_CONFIG_FILE, KRYPT_DB_FILE, KRYPT_RESULTS_DIR, KRYPT_REPORTS_DIR, KRYPT_LOGS_DIR, KRYPT_LOG_FILE, KRYPT_LAB_PID_FILE
    
    try:
        KRYPT_HOME.mkdir(parents=True, exist_ok=True)
        KRYPT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        KRYPT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        KRYPT_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Re-evaluate home
        KRYPT_HOME = _determine_krypt_home()
        KRYPT_CONFIG_FILE = KRYPT_HOME / "config.yaml"
        KRYPT_DB_FILE = KRYPT_HOME / "krypt.db"
        KRYPT_RESULTS_DIR = KRYPT_HOME / "results"
        KRYPT_REPORTS_DIR = KRYPT_HOME / "reports"
        KRYPT_LOGS_DIR = KRYPT_HOME / "logs"
        KRYPT_LOG_FILE = KRYPT_LOGS_DIR / "krypt.log"
        KRYPT_LAB_PID_FILE = KRYPT_HOME / "lab.pid"
        
        KRYPT_HOME.mkdir(parents=True, exist_ok=True)
        KRYPT_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        KRYPT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        KRYPT_LOGS_DIR.mkdir(parents=True, exist_ok=True)


def get_results_path(filename: str) -> Path:
    """Get path inside results directory."""
    ensure_krypt_dirs()
    return KRYPT_RESULTS_DIR / filename


def get_reports_path(filename: str) -> Path:
    """Get path inside reports directory."""
    ensure_krypt_dirs()
    return KRYPT_REPORTS_DIR / filename
