"""Tests for ServerConfig — browser auth opt-in fields."""

from __future__ import annotations

import pytest

from nifi_mcp_server.config import ServerConfig


def test_browser_auth_off_by_default():
    cfg = ServerConfig(knox_auth_source="")
    assert cfg.is_browser_auth() is False


def test_browser_auth_enabled_lowercase():
    cfg = ServerConfig(knox_auth_source="browser")
    assert cfg.is_browser_auth() is True


def test_browser_auth_case_insensitive():
    cfg = ServerConfig(knox_auth_source="Browser")
    assert cfg.is_browser_auth() is True


def test_browser_default_is_auto():
    cfg = ServerConfig()
    assert cfg.knox_browser == "auto"


def test_cookie_domain_from_nifi_api_base():
    cfg = ServerConfig(nifi_api_base="https://nifi.example.com/x/nifi-api")
    assert cfg.build_cookie_domain() == "nifi.example.com"


def test_cookie_domain_fallback_to_gateway_url():
    cfg = ServerConfig(nifi_api_base=None, knox_gateway_url="https://gw.example.com/x")
    assert cfg.build_cookie_domain() == "gw.example.com"


def test_cookie_domain_missing_both_raises():
    cfg = ServerConfig(nifi_api_base=None, knox_gateway_url="")
    with pytest.raises(ValueError):
        cfg.build_cookie_domain()


def test_cookie_domain_unparseable_raises():
    cfg = ServerConfig(nifi_api_base="not-a-url")
    with pytest.raises(ValueError):
        cfg.build_cookie_domain()
