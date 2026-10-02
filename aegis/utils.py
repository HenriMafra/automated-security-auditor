"""Small shared helpers: logging, rate limiting, tool detection, timing."""

from __future__ import annotations

import ipaddress
import shutil
import socket
import threading
import time
from collections import deque
from typing import Iterable

try:  # rich is a declared dependency, but degrade gracefully if absent
    from rich.console import Console

    _console = Console()

    def log(msg: str, style: str = "") -> None:
        _console.print(msg, style=style)
except Exception:  # pragma: no cover - fallback path

    def log(msg: str, style: str = "") -> None:  # type: ignore[misc]
        print(msg)


def info(msg: str) -> None:
    log(f"[*] {msg}", style="cyan")


def good(msg: str) -> None:
    log(f"[+] {msg}", style="green")


def warn(msg: str) -> None:
    log(f"[!] {msg}", style="yellow")


def err(msg: str) -> None:
    log(f"[x] {msg}", style="bold red")


def have_tool(name: str) -> bool:
    """True if an external binary is available on PATH."""
    return shutil.which(name) is not None


class RateLimiter:
    """Thread-safe token-bucket-ish limiter: at most ``rps`` actions/second.

    Keeps engagements polite and within the rules-of-engagement rate cap.
    """

    def __init__(self, rps: float) -> None:
        self.rps = max(0.1, float(rps))
        self._lock = threading.Lock()
        self._times: deque[float] = deque()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            window_start = now - 1.0
            while self._times and self._times[0] < window_start:
                self._times.popleft()
            if len(self._times) >= self.rps:
                sleep_for = 1.0 - (now - self._times[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._times.append(time.monotonic())


def resolve_host(host: str) -> list[str]:
    """Resolve a hostname to a de-duplicated list of IP strings."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips: list[str] = []
    for family, *_rest, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def ip_in_networks(ip: str, networks: Iterable[str]) -> bool:
    """True if ``ip`` falls inside any CIDR / plain-IP in ``networks``."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        try:
            if "/" in net:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            elif str(addr) == net:
                return True
        except ValueError:
            continue
    return False


def host_matches(host: str, pattern: str) -> bool:
    """Match a hostname against an exact or wildcard (``*.example.com``) pattern."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


class Timer:
    def __enter__(self) -> "Timer":
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed = time.monotonic() - self._start
