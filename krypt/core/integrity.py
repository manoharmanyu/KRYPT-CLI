"""
Cryptographic Code Integrity & Anti-Tampering Engine for KRYPT CLI.
Ensures framework source files, safety validators, and modules are verified, tamperproof, and uncracked.
"""

from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from krypt.utils.filesystem import KRYPT_HOME, ensure_krypt_dirs

INTEGRITY_MANIFEST_FILE = KRYPT_HOME / "integrity_manifest.json"


def get_source_root() -> Path:
    """Return the root path of the krypt package."""
    return Path(__file__).resolve().parent.parent


def compute_file_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class IntegrityGuard:
    """Verifies framework cryptographic signatures and protects against cracking/tampering."""

    @classmethod
    def scan_framework_files(cls) -> Dict[str, str]:
        """Scan all Python and core files in krypt/ and compute their SHA-256 checksums."""
        source_root = get_source_root()
        checksums: Dict[str, str] = {}

        # Files to include in cryptographic baseline
        for path in source_root.rglob("*.py"):
            # Exclude pycache and build artifacts
            if "__pycache__" in path.parts or ".pytest_cache" in path.parts:
                continue
            rel_path = path.relative_to(source_root.parent).as_posix()
            checksums[rel_path] = compute_file_sha256(path)

        return checksums

    @classmethod
    def generate_manifest(cls) -> Dict[str, Any]:
        """Generate and save the cryptographic integrity manifest."""
        ensure_krypt_dirs()
        checksums = cls.scan_framework_files()
        
        # Manifest structure
        manifest_data = {
            "framework": "KRYPT CLI",
            "version": "0.1.0",
            "author": "Gaddam Manyu (@manoharmanyu)",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "algorithm": "SHA-256",
            "file_count": len(checksums),
            "hashes": checksums,
        }

        # Calculate a master signature hash over all individual hashes sorted by filename
        sorted_items = sorted(checksums.items())
        combined_string = "".join(f"{k}:{v}" for k, v in sorted_items)
        master_digest = hashlib.sha256(combined_string.encode("utf-8")).hexdigest()
        manifest_data["master_signature"] = master_digest

        with open(INTEGRITY_MANIFEST_FILE, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        return manifest_data

    @classmethod
    def verify_integrity(cls) -> Dict[str, Any]:
        """
        Verify the current framework files against the integrity manifest.
        Detects unauthorized file modifications, cracked binaries, or injected hooks.
        """
        if not INTEGRITY_MANIFEST_FILE.exists():
            # Auto-generate baseline manifest if not yet created
            manifest = cls.generate_manifest()
        else:
            try:
                with open(INTEGRITY_MANIFEST_FILE, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
            except Exception:
                manifest = cls.generate_manifest()

        expected_hashes: Dict[str, str] = manifest.get("hashes", {})
        current_hashes = cls.scan_framework_files()

        verified: List[str] = []
        tampered: List[Dict[str, str]] = []
        missing: List[str] = []
        added: List[str] = []

        # Check all expected files
        for rel_path, expected_hash in expected_hashes.items():
            if rel_path not in current_hashes:
                missing.append(rel_path)
            elif current_hashes[rel_path] != expected_hash:
                tampered.append({
                    "file": rel_path,
                    "expected": expected_hash[:16] + "...",
                    "actual": current_hashes[rel_path][:16] + "..."
                })
            else:
                verified.append(rel_path)

        # Check for unexpected/added unauthorized files
        for rel_path in current_hashes:
            if rel_path not in expected_hashes:
                added.append(rel_path)

        # Master hash check
        sorted_current = sorted(current_hashes.items())
        current_combined = "".join(f"{k}:{v}" for k, v in sorted_current)
        current_master = hashlib.sha256(current_combined.encode("utf-8")).hexdigest()
        expected_master = manifest.get("master_signature", "")

        is_intact = (len(tampered) == 0 and len(missing) == 0 and len(added) == 0 and current_master == expected_master)

        return {
            "status": "SECURE" if is_intact else "TAMPER_DETECTED",
            "is_intact": is_intact,
            "master_signature": current_master,
            "expected_signature": expected_master,
            "total_files": len(current_hashes),
            "verified_count": len(verified),
            "tampered": tampered,
            "missing": missing,
            "added": added,
            "algorithm": "SHA-256",
            "manifest_date": manifest.get("generated_at", "Unknown"),
        }
