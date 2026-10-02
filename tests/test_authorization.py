"""Tests for the scope/authorization guard — the safety-critical core."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.authorization import (
    Authorization,
    AuthorizationError,
    Scope,
    ScopeGuard,
)


def _guard(**scope_kw) -> ScopeGuard:
    scope = Scope(
        in_scope=scope_kw.pop("in_scope", ["example.com", "*.example.com", "203.0.113.0/24"]),
        out_of_scope=scope_kw.pop("out_of_scope", ["status.example.com"]),
        allow_active=scope_kw.pop("allow_active", True),
        allow_intrusive=scope_kw.pop("allow_intrusive", False),
        **scope_kw,
    )
    now = datetime.now(timezone.utc)
    auth = Authorization(
        client="Example",
        authorized_by="CISO",
        contact="sec@example.com",
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1),
        scope_hash=scope.hash(),
    )
    return ScopeGuard(authorization=auth, scope=scope)


def test_valid_engagement_has_no_problems():
    assert _guard().validate() == []


def test_exact_host_in_scope():
    g = _guard()
    assert g.is_authorized("example.com")


def test_wildcard_subdomain_in_scope():
    g = _guard()
    assert g.is_authorized("app.example.com")


def test_out_of_scope_wins_over_wildcard():
    g = _guard()
    assert not g.is_authorized("status.example.com")
    assert "out of scope" in g.target_reason("status.example.com")


def test_unlisted_host_rejected():
    g = _guard()
    assert not g.is_authorized("evil.test")


def test_scope_hash_tamper_detected():
    g = _guard()
    # Mutate scope after "signing" — hash no longer matches.
    g.scope.in_scope.append("newly-added.com")
    problems = g.validate()
    assert any("scope_hash mismatch" in p for p in problems)


def test_expired_authorization_rejected():
    g = _guard()
    g.authorization.valid_until = datetime.now(timezone.utc) - timedelta(hours=1)
    # hash still matches (we didn't touch scope), but window is closed
    problems = g.validate()
    assert any("expired" in p for p in problems)
    with pytest.raises(AuthorizationError):
        g.assert_valid()


def test_activity_gate_blocks_intrusive_by_default():
    g = _guard(allow_intrusive=False)
    assert g.check_activity(active=True, intrusive=False) is None
    assert g.check_activity(active=True, intrusive=True) is not None


def test_cidr_membership():
    g = _guard()
    assert g.is_authorized("203.0.113.42")
    assert not g.is_authorized("203.0.114.1")


def test_empty_scope_is_invalid():
    g = _guard(in_scope=[])
    problems = g.validate()
    assert any("in_scope is empty" in p for p in problems)
