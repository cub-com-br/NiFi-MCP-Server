"""Tests for KnoxAuthFactory routing — browser branch and existing branches."""

from __future__ import annotations

import pytest

from nifi_mcp_server.auth import (
    BrowserAuthSession,
    KnoxAuthFactory,
)


def _factory(**overrides):
    defaults = dict(
        gateway_url="",
        token=None,
        cookie=None,
        user=None,
        password=None,
        token_endpoint=None,
        passcode_token=None,
        verify=True,
        auth_source="",
        browser="auto",
        cookie_domain=None,
    )
    defaults.update(overrides)
    return KnoxAuthFactory(**defaults)


def test_browser_returns_browser_session():
    f = _factory(auth_source="browser", cookie_domain="nifi.example.com")
    s = f.build_session()
    assert isinstance(s, BrowserAuthSession)


def test_browser_precedence_over_token():
    f = _factory(auth_source="browser", cookie_domain="nifi.example.com", token="abc")
    s = f.build_session()
    assert isinstance(s, BrowserAuthSession)


def test_browser_without_domain_raises():
    f = _factory(auth_source="browser", cookie_domain=None)
    with pytest.raises(ValueError):
        f.build_session()


def test_default_with_token_returns_plain_session():
    f = _factory(token="abc")
    s = f.build_session()
    assert not isinstance(s, BrowserAuthSession)
    assert s.headers["Cookie"] == "hadoop-jwt=abc"


def test_default_with_explicit_cookie():
    f = _factory(cookie="x=1")
    s = f.build_session()
    assert not isinstance(s, BrowserAuthSession)
    assert s.headers["Cookie"] == "x=1"
