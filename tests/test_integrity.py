"""
Tests for Cryptographic Code Integrity & Anti-Tamper Engine (krypt integrity).
"""

from krypt.core.integrity import IntegrityGuard, compute_file_sha256, get_source_root


def test_integrity_scan_framework_files():
    """Verify that scan_framework_files detects all python files with valid SHA-256 hashes."""
    checksums = IntegrityGuard.scan_framework_files()
    assert len(checksums) >= 40
    # Every hash must be a 64-character lowercase hex string
    for path, digest in checksums.items():
        assert len(digest) == 64
        assert path.endswith(".py")
        int(digest, 16)  # valid hex


def test_integrity_manifest_generation_and_verification():
    """Verify that generating and checking the manifest passes 100%."""
    manifest = IntegrityGuard.generate_manifest()
    assert manifest["algorithm"] == "SHA-256"
    assert manifest["file_count"] >= 40
    assert len(manifest["master_signature"]) == 64

    stat = IntegrityGuard.verify_integrity()
    assert stat["is_intact"] is True
    assert stat["status"] == "SECURE"
    assert len(stat["tampered"]) == 0
    assert len(stat["missing"]) == 0
