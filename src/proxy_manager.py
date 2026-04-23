"""
proxy_manager.py
----------------
Centralized proxy rotation manager.

Proxy format:  ip:port:username:password
Example:       31.59.20.176:6754:kgvjlmdj:qi7ddtttyhzm

The rotation counter tracks how many requests have used the current proxy.
When the counter reaches the configured rotation number, the next proxy
in the list is selected (round-robin).
"""

import threading
import csv
import ipaddress
import re
import subprocess
from typing import Optional

DEFAULT_PROXIES: list[str] = [
    "socks5h://103.118.85.146:1080",
    "socks4://162.255.108.5:5678",
    "socks4://162.255.110.52:5678",
    "socks5h://37.49.224.243:1080",
    "socks5h://187.63.9.62:63253",
]


class ProxyManager:
    """Thread-safe proxy list with round-robin rotation."""

    def __init__(self):
        self._lock = threading.Lock()
        # Start with the pre-tested proxy list provided by the project.
        self._proxies: list[str] = list(DEFAULT_PROXIES)
        self._rotate_every: int = 1         # rotate after N uses
        self._current_idx: int = 0          # index in _proxies
        self._use_count: int = 0            # uses since last rotation
        self._enabled: bool = False

    # ── Configuration ─────────────────────────────────────────────────

    def set_proxies(self, lines: list[str]):
        """Replace the proxy list.  Each line: ip:port:user:pass"""
        with self._lock:
            self._proxies = [l.strip() for l in lines if l.strip()]
            self._current_idx = 0
            self._use_count = 0

    def set_rotate_every(self, n: int):
        with self._lock:
            self._rotate_every = max(1, n)

    def set_enabled(self, enabled: bool):
        with self._lock:
            self._enabled = enabled

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    @property
    def rotate_every(self) -> int:
        with self._lock:
            return self._rotate_every

    @property
    def proxy_count(self) -> int:
        with self._lock:
            return len(self._proxies)

    @property
    def proxies(self) -> list[str]:
        with self._lock:
            return list(self._proxies)

    # ── Core: get next proxy ──────────────────────────────────────────

    def get_proxy(self) -> Optional[dict]:
        """Return a Playwright-compatible proxy dict, or None if disabled/empty.

        Automatically rotates after `rotate_every` calls.
        """
        with self._lock:
            if not self._enabled or not self._proxies:
                return None

            proxy_line = self._proxies[self._current_idx % len(self._proxies)]

            self._use_count += 1
            if self._use_count >= self._rotate_every:
                self._use_count = 0
                self._current_idx = (self._current_idx + 1) % len(self._proxies)

            return self._parse_proxy(proxy_line)

    def current_proxy_display(self) -> str:
        """Return a human-readable string of the current proxy (no credentials)."""
        with self._lock:
            if not self._enabled or not self._proxies:
                return "No proxy"
            line = self._proxies[self._current_idx % len(self._proxies)]
            parts = line.split(":")
            if len(parts) >= 2:
                return f"{parts[0]}:{parts[1]}"
            return line

    def current_proxy_full(self) -> str:
        """Return the full current proxy line."""
        with self._lock:
            if not self._enabled or not self._proxies:
                return ""
            return self._proxies[self._current_idx % len(self._proxies)]

    def reset_rotation(self):
        """Reset to the first proxy."""
        with self._lock:
            self._current_idx = 0
            self._use_count = 0

    # ── Parsing ───────────────────────────────────────────────────────

    _IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    @staticmethod
    def _normalize_protocol(value: str | None) -> str:
        text = (value or "").strip().lower()
        if "socks5" in text:
            return "socks5"
        if "socks4" in text:
            return "socks4"
        if text.startswith("http"):
            return "http"
        # Default to socks5 when protocol is unspecified.
        return "socks5"

    @classmethod
    def _extract_proxy_parts(
        cls, line: str
    ) -> tuple[str, str, str | None, str | None, str]:
        """Parse supported proxy formats into normalized pieces.

        Supported:
          - ip:port
          - ip:port:user:pass
          - csv row with ip,port,protocols fields
        """
        raw = line.strip()
        if not raw or raw.startswith("#"):
            raise ValueError("empty/comment line")

        # CSV-style row:
        # ip,anonymityLevel,...,port,protocols,...
        if "," in raw:
            row = next(csv.reader([raw]))
            if not row:
                raise ValueError("empty csv row")
            first = row[0].strip().strip('"').lower() if row else ""
            if first == "ip":
                raise ValueError("header row")
            if len(row) >= 8:
                host = row[0].strip().strip('"')
                port = row[6].strip().strip('"')
                protocol = cls._normalize_protocol(row[7].strip().strip('"'))
                if cls._IPV4_RE.match(host) and port.isdigit():
                    return host, port, None, None, protocol

        # URL proxy format (with optional auth)
        if "://" in raw:
            # tiny parser without importing urllib for perf reasons
            scheme, _, rest = raw.partition("://")
            auth_part, at, host_part = rest.rpartition("@")
            if not at:
                auth_part = ""
                host_part = rest
            host, sep, port = host_part.partition(":")
            if not sep or not port.isdigit():
                raise ValueError("invalid host:port in proxy url")
            user = pwd = None
            if auth_part:
                user, sep2, pwd = auth_part.partition(":")
                if not sep2:
                    pwd = ""
            return host, port, user or None, pwd or None, cls._normalize_protocol(scheme)

        parts = raw.split(":")
        if len(parts) == 2:
            host, port = parts
            if port.isdigit():
                return host, port, None, None, "http"
        if len(parts) == 4:
            host, port, user, pwd = parts
            if port.isdigit():
                return host, port, user, pwd, "http"

        raise ValueError("unsupported proxy format")

    @classmethod
    def validate_proxy_line(cls, line: str, timeout_sec: int = 8) -> tuple[bool, str]:
        """Check proxy live state with curl + api.ipify.org."""
        try:
            host, port, user, pwd, protocol = cls._extract_proxy_parts(line)
        except Exception as exc:
            return False, f"invalid format: {exc}"

        endpoint = "https://api.ipify.org"
        cmd = ["curl", "--silent", "--show-error", "--max-time", str(max(1, timeout_sec))]
        addr = f"{host}:{port}"

        if protocol == "socks4":
            cmd.extend(["--socks4", addr])
        elif protocol == "socks5":
            cmd.extend(["--socks5", addr])
        else:
            cmd.extend(["--proxy", f"http://{addr}"])

        if user is not None:
            cmd.extend(["--proxy-user", f"{user}:{pwd or ''}"])

        cmd.append(endpoint)

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(2, timeout_sec + 2),
                check=False,
            )
        except Exception as exc:
            return False, f"curl failed: {exc}"

        if res.returncode != 0:
            err = (res.stderr or res.stdout or "").strip()[:220]
            return False, err or f"curl exit {res.returncode}"

        ip_text = (res.stdout or "").strip()
        if not ip_text:
            return False, "empty ipify response"

        try:
            ipaddress.ip_address(ip_text)
        except ValueError:
            return False, f"unexpected response: {ip_text[:120]}"
        return True, ip_text

    @classmethod
    def validate_proxy_list(
        cls, lines: list[str], timeout_sec: int = 8
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """Return (working, failed) from raw proxy lines."""
        working: list[str] = []
        failed: list[tuple[str, str]] = []

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            ok, info = cls.validate_proxy_line(line, timeout_sec=timeout_sec)
            if not ok and "header row" in info.lower():
                continue
            if ok:
                working.append(line)
            else:
                failed.append((line, info))

        return working, failed

    @staticmethod
    def _parse_proxy(line: str) -> dict:
        """Parse supported proxy formats into Playwright proxy dict."""
        host, port, user, pwd, protocol = ProxyManager._extract_proxy_parts(line)
        result = {"server": f"{protocol}://{host}:{port}"}
        if user is not None:
            result["username"] = user
            result["password"] = pwd or ""
        return result


# ── Global singleton ──────────────────────────────────────────────────

_global_proxy_manager = ProxyManager()


def get_proxy_manager() -> ProxyManager:
    return _global_proxy_manager
