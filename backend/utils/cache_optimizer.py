"""
High-Performance TTL Cache Optimizer & Memory Acceleration Layer
Phase 30 - Comprehensive Testing & Optimization Subsystem
"""

import time
import functools
import threading
from typing import Dict, Any, Optional, Callable, Tuple


class TTLCache:
    """
    Thread-safe in-memory cache with configurable Time-To-Live (TTL).
    Eliminates redundant database and psutil I/O calls for hot query paths.
    """

    def __init__(self, default_ttl: int = 30):
        self._default_ttl = default_ttl
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Retrieve unexpired value from cache."""
        now = time.time()
        with self._lock:
            if key in self._store:
                value, expires_at = self._store[key]
                if now < expires_at:
                    self._hits += 1
                    return value
                else:
                    del self._store[key]
            self._misses += 1
            return None

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Store value with expiration timestamp."""
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = time.time() + ttl
        with self._lock:
            self._store[key] = (value, expires_at)

    def invalidate(self, prefix: str) -> int:
        """Remove all keys starting with prefix."""
        with self._lock:
            keys_to_del = [k for k in self._store if k.startswith(prefix)]
            for k in keys_to_del:
                del self._store[k]
            return len(keys_to_del)

    def clear(self) -> None:
        """Wipe entire cache."""
        with self._lock:
            self._store.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return cache hit ratio and size."""
        with self._lock:
            total = self._hits + self._misses
            ratio = round((self._hits / total) * 100, 1) if total > 0 else 0.0
            return {
                "cached_entries_count": len(self._store),
                "cache_hits": self._hits,
                "cache_misses": self._misses,
                "hit_ratio_percent": ratio
            }


# Global optimizer cache instance
global_cache = TTLCache(default_ttl=30)


def cached(ttl_seconds: int = 30, key_prefix: str = ""):
    """
    Decorator for memoizing slow endpoint outputs.
    """
    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"{key_prefix}:{fn.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            cached_val = global_cache.get(key)
            if cached_val is not None:
                return cached_val
            result = fn(*args, **kwargs)
            global_cache.set(key, result, ttl_seconds=ttl_seconds)
            return result
        return wrapper
    return decorator
