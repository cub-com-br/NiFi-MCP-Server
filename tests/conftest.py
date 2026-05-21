"""Shared fixtures for nifi-mcp-server tests."""

from __future__ import annotations

import http.cookiejar
from typing import Mapping


def make_jar(cookies: Mapping[str, str], domain: str = "127.0.0.1") -> http.cookiejar.CookieJar:
    """Build an http.cookiejar.CookieJar populated with the given name=value pairs.

    Used by tests that need to stand in for a real browser cookie store.
    Domain defaults to 127.0.0.1 so cookies attach to pytest-httpserver requests.
    """
    jar = http.cookiejar.CookieJar()
    for name, value in cookies.items():
        cookie = http.cookiejar.Cookie(
            version=0,
            name=name,
            value=value,
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=False,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
        jar.set_cookie(cookie)
    return jar
