"""Rate-limited, robots.txt-respecting HTTP client with retry/backoff."""

from __future__ import annotations

import time
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

DEFAULT_USER_AGENT = "AutonomousOSINTResearchBot/0.1 (+https://github.com/local/autonomous-osint; ethical-public-research)"


class PoliteHTTPClient:
    """HTTP client enforcing per-host rate limits, retries, and robots.txt."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        min_delay_seconds: float = 0.75,
        timeout_seconds: float = 15.0,
        max_retries: int = 2,
        respect_robots: bool = True,
    ) -> None:
        self.user_agent = user_agent
        self.min_delay_seconds = min_delay_seconds
        self.max_retries = max_retries
        self.respect_robots = respect_robots
        self._last_request_by_host: dict[str, float] = {}
        self._robots_cache: dict[str, RobotFileParser | None] = {}
        self._client = httpx.Client(
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            timeout=timeout_seconds,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PoliteHTTPClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _wait_for_rate_limit(self, host: str) -> None:
        now = time.monotonic()
        last = self._last_request_by_host.get(host)
        if last is not None:
            elapsed = now - last
            if elapsed < self.min_delay_seconds:
                time.sleep(self.min_delay_seconds - elapsed)
        self._last_request_by_host[host] = time.monotonic()

    def is_allowed_by_robots(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._robots_cache:
            rp = RobotFileParser()
            robots_url = f"{base}/robots.txt"
            try:
                self._wait_for_rate_limit(parsed.netloc)
                resp = self._client.get(robots_url, timeout=5.0)
                if resp.status_code == 200:
                    rp.parse(resp.text.splitlines())
                    self._robots_cache[base] = rp
                else:
                    self._robots_cache[base] = None
            except Exception:
                self._robots_cache[base] = None

        cached = self._robots_cache.get(base)
        if cached is None:
            return True
        return cached.can_fetch(self.user_agent, url)

    def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        check_robots: bool = False,
    ) -> httpx.Response:
        if check_robots and not self.is_allowed_by_robots(url):
            raise PermissionError(f"Blocked by robots.txt: {url}")

        host = urlparse(url).netloc
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._wait_for_rate_limit(host)
            try:
                resp = self._client.get(url, params=params, headers=headers)
                if resp.status_code in (429, 502, 503, 504) and attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                return resp
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < self.max_retries:
                    time.sleep(1.0 * (attempt + 1))
                else:
                    raise
        assert last_exc is not None
        raise last_exc
