"""
Rate Limiter
Token bucket rate limiter for API calls and RPC requests.
"""

from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    requests_per_second: float = 5.0
    burst_size: int = 10
    cooldown_seconds: float = 1.0


class RateLimiter:
    """
    Token bucket rate limiter for controlling API request rates.
    Supports both sync and async usage.
    """

    def __init__(
        self,
        requests_per_second: float = 5.0,
        burst_size: int = 10,
        name: str = "default",
    ) -> None:
        self.name = name
        self.rate = requests_per_second
        self.burst_size = burst_size
        self._tokens = float(burst_size)
        self._last_refill = time.monotonic()
        self._total_requests = 0
        self._total_waited = 0.0

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.burst_size, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def acquire(self) -> bool:
        """Try to acquire a token. Returns True if available."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            self._total_requests += 1
            return True
        return False

    def wait(self, timeout: float = 30.0) -> bool:
        """Wait until a token is available or timeout."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.acquire():
                wait_time = time.monotonic() - start
                self._total_waited += wait_time
                return True
            time.sleep(1.0 / self.rate)
        logger.warning(f"Rate limiter '{self.name}' timed out after {timeout}s")
        return False

    async def async_acquire(self, timeout: float = 30.0) -> bool:
        """Async version of wait()."""
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.acquire():
                return True
            await asyncio.sleep(1.0 / self.rate)
        return False

    def get_stats(self) -> dict:
        """Return rate limiter statistics."""
        return {
            "name": self.name,
            "total_requests": self._total_requests,
            "total_waited_seconds": round(self._total_waited, 2),
            "available_tokens": round(self._tokens, 1),
            "rate": self.rate,
            "burst_size": self.burst_size,
        }

    def reset(self) -> None:
        """Reset the rate limiter state."""
        self._tokens = float(self.burst_size)
        self._last_refill = time.monotonic()
        self._total_requests = 0
        self._total_waited = 0.0

    def __repr__(self) -> str:
        return f"RateLimiter(name={self.name}, rate={self.rate}/s, tokens={self._tokens:.1f})"


# Pre-configured rate limiters for common services
def etherscan_limiter() -> RateLimiter:
    """Rate limiter for Etherscan API (5 req/s free tier)."""
    return RateLimiter(requests_per_second=5.0, burst_size=5, name="etherscan")

def bscscan_limiter() -> RateLimiter:
    """Rate limiter for BSCScan API."""
    return RateLimiter(requests_per_second=5.0, burst_size=5, name="bscscan")

def rpc_limiter() -> RateLimiter:
    """Rate limiter for generic RPC calls."""
    return RateLimiter(requests_per_second=10.0, burst_size=20, name="rpc")
