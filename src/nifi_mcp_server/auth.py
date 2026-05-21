from __future__ import annotations

import base64
from typing import Optional

import requests

import http.cookiejar
from typing import Literal


BrowserName = Literal["auto", "chrome", "firefox"]


class BrowserCookieError(RuntimeError):
	"""Raised when browser cookies cannot be obtained."""


class BrowserCookieSource:
	"""Loads browser cookies scoped to a single domain. Stateless re-read on demand."""

	def __init__(self, browser: BrowserName, domain: str):
		self.browser = browser
		self.domain = domain

	def load(self) -> http.cookiejar.CookieJar:
		try:
			import browser_cookie3 as bc3
		except ImportError as e:
			raise BrowserCookieError(
				"browser-cookie3 not installed. pip install browser-cookie3."
			) from e

		attempts = []
		for name, fn in self._browser_fns():
			try:
				jar = fn(domain_name=self.domain)
				if any(True for _ in jar):
					return jar
				attempts.append(f"{name}: no cookies for domain {self.domain}")
			except bc3.BrowserCookieError as e:
				attempts.append(f"{name}: {e}")
			except Exception as e:
				attempts.append(f"{name}: {type(e).__name__}: {e}")

		raise BrowserCookieError(
			f"No usable cookies for {self.domain}. Tried:\n  - "
			+ "\n  - ".join(attempts)
			+ f"\nLog in to NiFi at https://{self.domain}/ in your browser first."
		)

	def _browser_fns(self):
		import browser_cookie3 as bc3
		if self.browser == "chrome":
			return [("chrome", bc3.chrome)]
		if self.browser == "firefox":
			return [("firefox", bc3.firefox)]
		return [("chrome", bc3.chrome), ("firefox", bc3.firefox)]


XSRF_COOKIE = "__Secure-Request-Token"
XSRF_HEADER = "Request-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class BrowserAuthSession(requests.Session):
	"""requests.Session with browser-cookie auto-load + XSRF echo on non-GET requests."""

	def __init__(self, source, verify):
		super().__init__()
		self.verify = verify
		self._source = source
		self._loaded = False

	def _refresh_jar(self) -> None:
		jar = self._source.load()
		self.cookies.clear()
		for c in jar:
			self.cookies.set_cookie(c)
		self._loaded = True

	def _ensure_jar(self) -> None:
		if not self._loaded:
			self._refresh_jar()

	def _xsrf_value(self):
		for c in self.cookies:
			if c.name == XSRF_COOKIE:
				return c.value
		return None

	def _attach_xsrf(self, method: str, kwargs: dict) -> None:
		if method.upper() in SAFE_METHODS:
			return
		token = self._xsrf_value()
		if token is None:
			return
		headers = dict(kwargs.get("headers") or {})
		headers[XSRF_HEADER] = token
		kwargs["headers"] = headers

	def request(self, method, url, **kwargs):  # type: ignore[override]
		self._ensure_jar()
		self._attach_xsrf(method, kwargs)
		resp = super().request(method, url, **kwargs)
		if resp.status_code in (401, 403):
			self._refresh_jar()
			self._attach_xsrf(method, kwargs)
			resp = super().request(method, url, **kwargs)  # one retry only
		return resp


class KnoxAuthFactory:
	def __init__(
		self,
		gateway_url: str,
		token: Optional[str],
		cookie: Optional[str],
		user: Optional[str],
		password: Optional[str],
		token_endpoint: Optional[str],
		passcode_token: Optional[str],
		verify: bool | str,
		auth_source: str = "",
		browser: str = "auto",
		cookie_domain: Optional[str] = None,
	):
		self.gateway_url = gateway_url.rstrip("/") if gateway_url else ""
		self.token = token
		self.cookie = cookie
		self.user = user
		self.password = password
		self.token_endpoint = token_endpoint or (
			f"{self.gateway_url}/knoxtoken/api/v1/token" if self.gateway_url else None
		)
		self.passcode_token = passcode_token
		self.verify = verify
		self.auth_source = (auth_source or "").lower()
		self.browser = (browser or "auto").lower()
		self.cookie_domain = cookie_domain

	def build_session(self) -> requests.Session:
		if self.auth_source == "browser":
			if not self.cookie_domain:
				raise ValueError(
					"auth_source='browser' requires cookie_domain (derived from NIFI_API_BASE host)"
				)
			return BrowserAuthSession(
				source=BrowserCookieSource(self.browser, self.cookie_domain),
				verify=self.verify,
			)

		session = requests.Session()
		session.verify = self.verify

		# Priority: Explicit Cookie -> Knox token (as cookie for CDP) -> Passcode token -> Basic creds token exchange
		if self.cookie:
			session.headers["Cookie"] = self.cookie
			return session
		
		if self.token:
			# For CDP NiFi, Knox JWT tokens must be sent as cookies, not Bearer headers
			session.headers["Cookie"] = f"hadoop-jwt={self.token}"
			return session


		if self.passcode_token:
			# Prefer exchanging passcode for JWT via knoxtoken endpoint when available
			if self.token_endpoint:
				jwt = self._exchange_passcode_for_jwt()
				session.headers["Authorization"] = f"Bearer {jwt}"
				return session
			# Fallback: send passcode as header (may not work on all deployments)
			session.headers["X-Knox-Passcode"] = self.passcode_token
			return session

		if self.user and self.password and self.token_endpoint:
			jwt = self._fetch_knox_token()
			session.headers["Authorization"] = f"Bearer {jwt}"
			return session

		return session

	def _fetch_knox_token(self) -> str:
		# Default Knox token endpoint returns raw JWT or JSON with token fields
		resp = requests.get(
			self.token_endpoint,
			auth=(self.user, self.password),
			verify=self.verify,
			timeout=15,
		)
		resp.raise_for_status()
		try:
			data = resp.json()
			return data.get("access_token") or data.get("token") or data.get("accessToken")
		except ValueError:
			text = resp.text.strip()
			# Some envs return Base64-encoded token; detect and decode if needed
			try:
				decoded = base64.b64decode(text).decode("utf-8")
				if decoded.count(".") == 2:
					return decoded
			except Exception:
				pass
			return text

	def _exchange_passcode_for_jwt(self) -> str:
		"""Exchange Knox passcode token for JWT using Basic auth pattern passcode:<token>."""
		if not (self.passcode_token and self.token_endpoint):
			raise RuntimeError("Passcode token exchange requires token_endpoint and passcode token")
		import base64
		header = {
			"Authorization": "Basic " + base64.b64encode(f"passcode:{self.passcode_token}".encode()).decode(),
			"X-Requested-By": "nifi-mcp-server",
		}
		resp = requests.get(self.token_endpoint, headers=header, verify=self.verify, timeout=15)
		resp.raise_for_status()
		try:
			data = resp.json()
			return data.get("access_token") or data.get("token") or data.get("accessToken")
		except ValueError:
			return resp.text.strip()


