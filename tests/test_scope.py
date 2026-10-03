"""
Unit tests for fail-closed Target Scope Engine.
"""

import pytest
from krypt.database.db import db
from krypt.safety.scope import ScopeEngine, TargetNotRegisteredException, enforce_scope


def test_scope_blocks_unregistered_target():
    """Unregistered targets must fail-closed and raise TargetNotRegisteredException."""
    unregistered = "http://unauthorized.evil-external-domain-xyz.com"
    with pytest.raises(TargetNotRegisteredException):
        enforce_scope(unregistered, is_active=True)


def test_scope_allows_registered_target():
    """Registered targets must pass scope validation."""
    target_url = "http://authorized-test-company.com"
    db.add_target(target_url, notes="Engagement 2026")
    
    assert ScopeEngine.check_scope(target_url, is_active_assessment=True) is True
    assert ScopeEngine.check_scope("authorized-test-company.com", is_active_assessment=True) is True


def test_scope_normalization():
    """Verify target normalization logic."""
    canonical, host, port, scheme = ScopeEngine.normalize_target("example.com")
    assert canonical == "http://example.com"
    assert host == "example.com"
    assert port == 80
    assert scheme == "http"

    canonical, host, port, scheme = ScopeEngine.normalize_target("https://secure.example.com:8443")
    assert canonical == "https://secure.example.com:8443"
    assert host == "secure.example.com"
    assert port == 8443
    assert scheme == "https"
