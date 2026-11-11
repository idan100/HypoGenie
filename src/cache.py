"""
Disk-based LLM response cache.

Keyed by SHA-256 of (provider, model, system_prompt, user_prompt).
Stored as JSON files under HYPOGENIE_CACHE_DIR (default: .hypogenie_cache/).
Set HYPOGENIE_CACHE_ENABLED=0 to disable.
"""

import hashlib
import json
import os
from pathlib import Path

_CACHE_DIR = Path(os.environ.get("HYPOGENIE_CACHE_DIR", ".hypogenie_cache"))
_ENABLED = os.environ.get("HYPOGENIE_CACHE_ENABLED", "1").lower() not in (
    "0", "false", "no", "off", "disable",
)


def _cache_key(provider: str, model: str, system: str, user: str) -> str:
    raw = json.dumps([provider, model, system, user], ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def get(provider: str, model: str, system: str, user: str) -> str | None:
    """Return cached response or None if not cached."""
    if not _ENABLED:
        return None
    key = _cache_key(provider, model, system, user)
    path = _CACHE_DIR / f"{key}.json"
    if path.exists():
        try:
            data = json.loads(path.read_text())
            return data.get("response")
        except Exception:
            return None
    return None


def put(provider: str, model: str, system: str, user: str, response: str) -> None:
    """Store a response in the cache."""
    if not _ENABLED:
        return
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = _cache_key(provider, model, system, user)
    path = _CACHE_DIR / f"{key}.json"
    try:
        path.write_text(
            json.dumps({"provider": provider, "model": model, "response": response},
                       ensure_ascii=False, indent=2)
        )
    except Exception:
        pass


def invalidate(provider: str, model: str, system: str, user: str) -> bool:
    """Remove a cached entry. Returns True if it existed."""
    key = _cache_key(provider, model, system, user)
    path = _CACHE_DIR / f"{key}.json"
    if path.exists():
        path.unlink()
        return True
    return False
