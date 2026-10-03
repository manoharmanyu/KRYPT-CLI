"""
Configuration management for KRYPT CLI.
Handles reading, writing, and updating ~/.krypt/config.yaml.
"""

from typing import Any, Dict, Optional
from pathlib import Path
import yaml
import os

from krypt.utils.filesystem import KRYPT_CONFIG_FILE, ensure_krypt_dirs

DEFAULT_CONFIG: Dict[str, Any] = {
    "request": {
        "timeout": 10,
        "rate_limit": 5.0,
        "user_agent": "KRYPT-CLI/0.1 (OSINT & Security Assessment)",
        "verify_ssl": False,
        "max_redirects": 5,
    },
    "crawler": {
        "max_depth": 3,
        "max_pages": 500,
        "threads": 5,
        "rate": 10.0,
        "timeout": 10.0,
    },
    "socks5": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 9050,
    },
    "safety": {
        "require_registered_target": True,
        "lab_mode": False,
    },
    "reporting": {
        "default_format": "terminal",
        "auto_save": True,
    },
}


class ConfigManager:
    """Manages YAML configuration file for KRYPT."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or KRYPT_CONFIG_FILE
        ensure_krypt_dirs()
        self._config: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load configuration from disk or create default if not present."""
        if not self.config_path.exists():
            self._save_default()
            return DEFAULT_CONFIG.copy()
        
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    # Merge with default to ensure all keys exist
                    config = DEFAULT_CONFIG.copy()
                    for k, v in loaded.items():
                        if isinstance(v, dict) and k in config and isinstance(config[k], dict):
                            config[k].update(v)
                        else:
                            config[k] = v
                    return config
                return DEFAULT_CONFIG.copy()
        except Exception:
            return DEFAULT_CONFIG.copy()

    def _save_default(self) -> None:
        """Write default configuration to disk."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)
        except Exception:
            pass

    def save(self) -> None:
        """Save current configuration to disk."""
        ensure_krypt_dirs()
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get config value using dot notation (e.g. 'socks5.enabled')."""
        parts = key_path.split(".")
        current = self._config
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def set(self, key_path: str, value: Any) -> None:
        """Set config value using dot notation and persist to disk."""
        parts = key_path.split(".")
        current = self._config
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        
        # Cast boolean/integer strings if applicable
        if isinstance(value, str):
            if value.lower() in ("true", "yes", "1", "on"):
                value = True
            elif value.lower() in ("false", "no", "0", "off"):
                value = False
            elif value.isdigit():
                value = int(value)
            else:
                try:
                    value = float(value)
                except ValueError:
                    pass

        current[parts[-1]] = value
        self.save()

    @property
    def data(self) -> Dict[str, Any]:
        """Return raw configuration dictionary."""
        return self._config


# Global singleton instance
config = ConfigManager()
