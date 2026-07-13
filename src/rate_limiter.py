import time
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.config import RATE_LIMITS


class TokenBucket:
    def __init__(self, rate_per_minute: int, rate_per_day: Optional[int] = None):
        self.rate_per_minute = rate_per_minute
        self.rate_per_day = rate_per_day
        self.tokens = float(rate_per_minute)
        self.max_tokens = float(rate_per_minute)
        self.last_refill = time.time()
        self.day_count = 0
        self.day_start = datetime.utcnow()
        self._lock = threading.Lock()

    def restore(self, tokens: float, last_refill: float, day_count: int, day_start_iso: str):
        self.tokens = tokens
        self.last_refill = last_refill
        self.day_count = day_count
        self.day_start = datetime.fromisoformat(day_start_iso)

    def get_state(self) -> dict:
        with self._lock:
            return {
                "tokens": self.tokens,
                "max_tokens": self.max_tokens,
                "last_refill": self.last_refill,
                "day_count": self.day_count,
                "day_start": self.day_start.isoformat(),
                "rate_per_minute": self.rate_per_minute,
                "rate_per_day": self.rate_per_day,
            }

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        refill = elapsed * (self.rate_per_minute / 60.0)
        self.tokens = min(self.max_tokens, self.tokens + refill)
        self.last_refill = now

    def acquire(self) -> bool:
        with self._lock:
            now_dt = datetime.utcnow()
            if self.rate_per_day:
                if now_dt - self.day_start > timedelta(days=1):
                    self.day_count = 0
                    self.day_start = now_dt
                if self.day_count >= self.rate_per_day:
                    return False

            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                if self.rate_per_day:
                    self.day_count += 1
                return True
            return False

    def get_status(self) -> dict:
        with self._lock:
            self._refill()
            deficit = self.max_tokens - self.tokens
            sec_until_full = deficit * 60.0 / self.rate_per_minute if deficit > 0 else 0
            daily_reset = (self.day_start + timedelta(days=1)).isoformat() if self.rate_per_day else None
            return {
                "tokens_remaining": round(self.tokens, 1),
                "max_tokens": self.max_tokens,
                "day_count": self.day_count,
                "rate_per_minute": self.rate_per_minute,
                "rate_per_day": self.rate_per_day,
                "seconds_until_full": round(sec_until_full, 1),
                "daily_reset_at": daily_reset,
            }

    def wait_and_acquire(self, timeout: int = 30) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.acquire():
                return True
            time.sleep(0.5)
        return False


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}

    def get_bucket(self, tool_name: str) -> TokenBucket:
        if tool_name not in self._buckets:
            limits = RATE_LIMITS.get(tool_name, {"requests_per_minute": 10})
            self._buckets[tool_name] = TokenBucket(
                rate_per_minute=limits.get("requests_per_minute", 10),
                rate_per_day=limits.get("requests_per_day"),
            )
        return self._buckets[tool_name]

    def can_call(self, tool_name: str) -> bool:
        return self.get_bucket(tool_name).acquire()

    def get_all_status(self) -> dict[str, dict]:
        return {name: self.get_bucket(name).get_status() for name in RATE_LIMITS}

    def wait_and_call(self, tool_name: str, timeout: int = 30) -> bool:
        return self.get_bucket(tool_name).wait_and_acquire(timeout)

    def get_persistable_state(self) -> dict[str, dict]:
        return {name: self.get_bucket(name).get_state() for name in RATE_LIMITS}

    def restore_state(self, state: dict[str, dict]):
        for name, data in state.items():
            limits = RATE_LIMITS.get(name, {"requests_per_minute": 10})
            bucket = TokenBucket(
                rate_per_minute=limits.get("requests_per_minute", 10),
                rate_per_day=limits.get("requests_per_day"),
            )
            bucket.restore(
                tokens=data.get("tokens", float(limits.get("requests_per_minute", 10))),
                last_refill=data.get("last_refill", time.time()),
                day_count=data.get("day_count", 0),
                day_start_iso=data.get("day_start", datetime.utcnow().isoformat()),
            )
            self._buckets[name] = bucket


_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
