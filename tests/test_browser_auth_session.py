"""Tests for BrowserAuthSession — lazy cookie load, XSRF echo, 401-refresh retry."""

from __future__ import annotations

import http.cookiejar
from typing import List

import pytest

from nifi_mcp_server.auth import BrowserAuthSession, BrowserCookieError
from tests.conftest import make_jar


class StubSource:
    """In-memory stand-in for BrowserCookieSource. Returns prepared jars in order."""

    def __init__(self, jars: List[http.cookiejar.CookieJar]):
        self._jars = list(jars)
        self.calls = 0

    def load(self) -> http.cookiejar.CookieJar:
        self.calls += 1
        if not self._jars:
            raise BrowserCookieError("no more stub jars")
        return self._jars.pop(0)


def test_get_lazy_loads_jar_once(httpserver):
    # httpserver uses localhost, but default cookie domain is 127.0.0.1
    # Force httpserver to listen on 127.0.0.1
    httpserver.host = "127.0.0.1"

    src = StubSource([make_jar({"Authorization-Bearer": "abc"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x").respond_with_data("ok")
    resp = sess.get(httpserver.url_for("/x"))

    assert resp.status_code == 200
    assert src.calls == 1


def test_get_reuses_jar_on_subsequent_calls(httpserver):
    # httpserver uses localhost, but default cookie domain is 127.0.0.1
    # Force httpserver to listen on 127.0.0.1
    httpserver.host = "127.0.0.1"

    src = StubSource([make_jar({"Authorization-Bearer": "abc"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x").respond_with_data("ok")
    httpserver.expect_request("/y").respond_with_data("ok")
    sess.get(httpserver.url_for("/x"))
    sess.get(httpserver.url_for("/y"))

    assert src.calls == 1


def test_cookie_sent_in_request(httpserver):
    # httpserver uses localhost, but default cookie domain is 127.0.0.1
    # Force httpserver to listen on 127.0.0.1
    httpserver.host = "127.0.0.1"

    src = StubSource([make_jar({"Authorization-Bearer": "abc"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x").respond_with_data("ok")
    sess.get(httpserver.url_for("/x"))

    request, _ = httpserver.log[-1]
    cookie_header = request.headers.get("Cookie") or ""
    assert "Authorization-Bearer=abc" in cookie_header


def test_post_attaches_request_token_header(httpserver):
    src = StubSource([make_jar({
        "__Secure-Authorization-Bearer": "bearer",
        "__Secure-Request-Token": "xsrf-1",
    })])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x", method="POST").respond_with_data("ok")
    resp = sess.post(httpserver.url_for("/x"), json={})

    assert resp.status_code == 200
    request, _ = httpserver.log[-1]
    assert request.headers.get("Request-Token") == "xsrf-1"


def test_get_does_not_attach_request_token_header(httpserver):
    src = StubSource([make_jar({"__Secure-Request-Token": "xsrf-1"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x").respond_with_data("ok")
    sess.get(httpserver.url_for("/x"))

    request, _ = httpserver.log[-1]
    assert "Request-Token" not in request.headers


def test_post_without_xsrf_cookie_omits_header(httpserver):
    src = StubSource([make_jar({"__Secure-Authorization-Bearer": "bearer"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x", method="POST").respond_with_data("ok")
    sess.post(httpserver.url_for("/x"), json={})

    request, _ = httpserver.log[-1]
    assert "Request-Token" not in request.headers


def test_put_and_delete_also_attach_request_token(httpserver):
    src = StubSource([make_jar({"__Secure-Request-Token": "xsrf-1"}) for _ in range(2)])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x", method="PUT").respond_with_data("ok")
    httpserver.expect_request("/y", method="DELETE").respond_with_data("ok")
    sess.put(httpserver.url_for("/x"), json={})
    sess.delete(httpserver.url_for("/y"))

    put_req, _ = httpserver.log[-2]
    del_req, _ = httpserver.log[-1]
    assert put_req.headers.get("Request-Token") == "xsrf-1"
    assert del_req.headers.get("Request-Token") == "xsrf-1"


def test_401_triggers_refresh_and_retry_succeeds(httpserver):
    src = StubSource([
        make_jar({"__Secure-Authorization-Bearer": "old"}),
        make_jar({"__Secure-Authorization-Bearer": "new"}),
    ])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_ordered_request("/x").respond_with_data("nope", status=401)
    httpserver.expect_ordered_request("/x").respond_with_data("ok", status=200)
    resp = sess.get(httpserver.url_for("/x"))

    assert resp.status_code == 200
    assert src.calls == 2
    assert len(httpserver.log) == 2


def test_403_triggers_refresh_and_retry_succeeds(httpserver):
    src = StubSource([
        make_jar({"__Secure-Authorization-Bearer": "old"}),
        make_jar({"__Secure-Authorization-Bearer": "new"}),
    ])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_ordered_request("/x").respond_with_data("nope", status=403)
    httpserver.expect_ordered_request("/x").respond_with_data("ok", status=200)
    resp = sess.get(httpserver.url_for("/x"))

    assert resp.status_code == 200
    assert src.calls == 2


def test_still_401_after_refresh_only_two_attempts(httpserver):
    src = StubSource([
        make_jar({"__Secure-Authorization-Bearer": "old"}),
        make_jar({"__Secure-Authorization-Bearer": "still-bad"}),
    ])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_ordered_request("/x").respond_with_data("nope", status=401)
    httpserver.expect_ordered_request("/x").respond_with_data("still-nope", status=401)
    resp = sess.get(httpserver.url_for("/x"))

    assert resp.status_code == 401
    assert src.calls == 2
    assert len(httpserver.log) == 2


def test_refresh_raises_propagates(httpserver):
    src = StubSource([make_jar({"__Secure-Authorization-Bearer": "old"})])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_request("/x").respond_with_data("nope", status=401)
    with pytest.raises(BrowserCookieError):
        sess.get(httpserver.url_for("/x"))


def test_xsrf_reattached_after_refresh(httpserver):
    src = StubSource([
        make_jar({"__Secure-Request-Token": "t1"}),
        make_jar({"__Secure-Request-Token": "t2"}),
    ])
    sess = BrowserAuthSession(source=src, verify=False)

    httpserver.expect_ordered_request("/x", method="POST").respond_with_data("nope", status=401)
    httpserver.expect_ordered_request("/x", method="POST").respond_with_data("ok", status=200)
    resp = sess.post(httpserver.url_for("/x"), json={})

    assert resp.status_code == 200
    first_req, _ = httpserver.log[0]
    second_req, _ = httpserver.log[1]
    assert first_req.headers.get("Request-Token") == "t1"
    assert second_req.headers.get("Request-Token") == "t2"
