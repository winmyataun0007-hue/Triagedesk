"""Small shared helpers: IDs, time, IP classification."""

from __future__ import annotations

import ipaddress
import time
import uuid


def now() -> float:
    return time.time()


def new_id(prefix: str = "") -> str:
    return (prefix + uuid.uuid4().hex[:10]) if prefix else uuid.uuid4().hex[:12]


def is_internal_ip(ip: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses (our own network)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"{h}h {m}m"
