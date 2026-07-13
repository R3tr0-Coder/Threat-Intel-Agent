import json
import logging
import time
from datetime import datetime
from functools import wraps
from typing import Any, Optional

from src.config import LOG_FILE

logger = logging.getLogger("threat_agent")
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
))
logger.addHandler(handler)
logger.setLevel(logging.INFO)

_session_log: list[dict] = []


def log_event(event_type: str, data: dict):
    entry = {"timestamp": datetime.utcnow().isoformat(), "type": event_type, **data}
    logger.info(json.dumps(entry))
    _session_log.append(entry)


def trace_tool(func):
    @wraps(func)
    def wrapper(self, **kwargs):
        tool_name = self.name if hasattr(self, "name") else func.__name__
        start = time.time()
        start_ts = datetime.utcnow().isoformat()
        log_event("tool_call", {"tool": tool_name, "params": _safe_kwargs(kwargs), "status": "started"})
        try:
            result = func(self, **kwargs)
            duration_ms = int((time.time() - start) * 1000)
            summary = str(result.data)[:200] if result.data else (result.error or "")[:200]
            log_event("tool_result", {
                "tool": tool_name,
                "duration_ms": duration_ms,
                "status": "error" if result.error else "success",
                "summary": summary,
            })
            return result
        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)
            log_event("tool_error", {"tool": tool_name, "duration_ms": duration_ms, "error": str(e)[:300]})
            raise
    return wrapper


def _safe_kwargs(kwargs: dict) -> dict:
    safe_keys = {"ip", "domain", "hash_val", "url_val", "actor", "cve_id", "software", "version", "keyword", "max_age_days"}
    return {k: v for k, v in kwargs.items() if k in safe_keys and v is not None}


def get_session_log():
    return list(_session_log)


def clear_session_log():
    _session_log.clear()
