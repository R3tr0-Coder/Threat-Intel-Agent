import time
from typing import Any, Optional


class TTLCache:
    def __init__(self, default_ttl: int = 300):
        self._store: dict[str, tuple[float, Any]] = {}
        self.default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        ttl = ttl if ttl is not None else self.default_ttl
        self._store[key] = (time.time() + ttl, value)

    def clear(self):
        self._store.clear()

    def _key(self, tool: str, **kwargs) -> str:
        items = sorted(kwargs.items())
        return f"{tool}:{'&'.join(f'{k}={v}' for k, v in items if v is not None)}"


_cache: Optional[TTLCache] = None


def get_cache() -> TTLCache:
    global _cache
    if _cache is None:
        _cache = TTLCache()
    return _cache
