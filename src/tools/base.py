from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional
import time
import requests

from src.models import ToolResult
from src.observability import trace_tool


class ToolABC(ABC):
    name: str = ""
    api_key: str = ""
    base_url: str = ""

    def __init__(self):
        self.quota_remaining: Optional[int] = None
        self.quota_reset: Optional[datetime] = None
        self._last_request = 0.0

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        ...

    def _rate_limit_delay(self, min_interval: float = 1.0):
        elapsed = time.time() - self._last_request
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

    def _request(
        self,
        method: str,
        endpoint: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
        data: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> tuple[dict, Optional[str]]:
        url = f"{self.base_url}{endpoint}"
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    params=params,
                    json=json_body,
                    data=data,
                    timeout=timeout,
                )
                self._last_request = time.time()
                if resp.status_code == 429:
                    if attempt < max_retries:
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                    return {}, f"Rate limited (429): {resp.text[:200]}"
                if resp.status_code in (503, 504):
                    if attempt < max_retries:
                        wait = 2 ** attempt
                        time.sleep(wait)
                        continue
                    return {}, f"Service unavailable ({resp.status_code}): {resp.text[:200]}"
                if resp.status_code == 403:
                    return {}, f"Forbidden (403) — check API key: {resp.text[:200]}"
                if resp.status_code == 404:
                    return {}, f"Not found (404): {resp.text[:200]}"
                resp.raise_for_status()
                return resp.json(), None
            except requests.exceptions.Timeout:
                last_error = f"Request timed out after {timeout}s (attempt {attempt + 1})"
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return {}, last_error
            except requests.exceptions.ConnectionError:
                last_error = f"Connection error — host unreachable: {url}"
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return {}, last_error
            except requests.exceptions.RequestException as e:
                last_error = f"Request failed: {str(e)[:300]}"
                if attempt < max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return {}, last_error
        return {}, last_error or "Max retries exceeded"

    @trace_tool
    def safe_execute(self, **kwargs) -> ToolResult:
        try:
            result = self.execute(**kwargs)
            return result
        except Exception as e:
            return ToolResult(
                source=self.name,
                error=f"Unexpected error in {self.name}.execute: {str(e)[:300]}",
                data={},
            )
