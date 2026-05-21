"""Tests for BrowserCookieSource.load() — exercises the auto / chrome / firefox paths."""

from __future__ import annotations

import http.cookiejar

import pytest

from nifi_mcp_server.auth import BrowserCookieError, BrowserCookieSource
from tests.conftest import make_jar


def test_chrome_explicit_returns_jar(monkeypatch):
    import browser_cookie3 as bc3

    expected = make_jar({"k": "v"}, domain="nifi.example.com")
    monkeypatch.setattr(bc3, "chrome", lambda domain_name: expected)

    src = BrowserCookieSource("chrome", "nifi.example.com")
    assert src.load() is expected


def test_firefox_explicit_returns_jar(monkeypatch):
    import browser_cookie3 as bc3

    expected = make_jar({"k": "v"}, domain="nifi.example.com")
    monkeypatch.setattr(bc3, "firefox", lambda domain_name: expected)

    src = BrowserCookieSource("firefox", "nifi.example.com")
    assert src.load() is expected


def test_auto_chrome_empty_firefox_wins(monkeypatch):
    import browser_cookie3 as bc3

    expected = make_jar({"k": "v"}, domain="nifi.example.com")
    monkeypatch.setattr(bc3, "chrome", lambda domain_name: http.cookiejar.CookieJar())
    monkeypatch.setattr(bc3, "firefox", lambda domain_name: expected)

    src = BrowserCookieSource("auto", "nifi.example.com")
    assert src.load() is expected


def test_auto_chrome_raises_firefox_wins(monkeypatch):
    import browser_cookie3 as bc3

    expected = make_jar({"k": "v"}, domain="nifi.example.com")

    def chrome_raises(domain_name):
        raise bc3.BrowserCookieError("locked")

    monkeypatch.setattr(bc3, "chrome", chrome_raises)
    monkeypatch.setattr(bc3, "firefox", lambda domain_name: expected)

    src = BrowserCookieSource("auto", "nifi.example.com")
    assert src.load() is expected


def test_auto_both_fail_lists_reasons(monkeypatch):
    import browser_cookie3 as bc3

    def chrome_raises(domain_name):
        raise bc3.BrowserCookieError("chrome-broken")

    def firefox_raises(domain_name):
        raise bc3.BrowserCookieError("firefox-broken")

    monkeypatch.setattr(bc3, "chrome", chrome_raises)
    monkeypatch.setattr(bc3, "firefox", firefox_raises)

    src = BrowserCookieSource("auto", "nifi.example.com")
    with pytest.raises(BrowserCookieError) as ei:
        src.load()
    msg = str(ei.value)
    assert "chrome-broken" in msg
    assert "firefox-broken" in msg
    assert "nifi.example.com" in msg


def test_auto_both_empty_raises(monkeypatch):
    import browser_cookie3 as bc3

    monkeypatch.setattr(bc3, "chrome", lambda domain_name: http.cookiejar.CookieJar())
    monkeypatch.setattr(bc3, "firefox", lambda domain_name: http.cookiejar.CookieJar())

    src = BrowserCookieSource("auto", "nifi.example.com")
    with pytest.raises(BrowserCookieError):
        src.load()
