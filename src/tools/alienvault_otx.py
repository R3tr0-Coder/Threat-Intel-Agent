import urllib.parse
from typing import Optional
from src.config import OTX_API_KEY
from src.models import ToolResult
from src.tools.base import ToolABC
from src.ttp_resolver import resolve_tags


class AlienVaultOTX(ToolABC):
    name = "otx"
    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self):
        super().__init__()
        self.api_key = OTX_API_KEY

    def _headers(self):
        return {"X-OTX-API-KEY": self.api_key}

    def execute(self, ip: Optional[str] = None, domain: Optional[str] = None,
                hash_val: Optional[str] = None, url_val: Optional[str] = None,
                actor: Optional[str] = None) -> ToolResult:
        if not self.api_key:
            return ToolResult(source=self.name, error="OTX_API_KEY not configured", data={})

        if ip:
            data, err = self._request("GET", f"/indicators/IPv4/{ip}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return ToolResult(
                source=self.name,
                data={
                    "type": "ip",
                    "value": ip,
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_code", ""),
                    "asn": data.get("asn", ""),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [self._pulse_with_techniques(p) for p in pulses[:5]],
                },
            )

        if domain:
            data, err = self._request("GET", f"/indicators/domain/{domain}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return ToolResult(
                source=self.name,
                data={
                    "type": "domain",
                    "value": domain,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [self._pulse_with_techniques(p) for p in pulses[:5]],
                },
            )

        if hash_val:
            indicator_type = self._detect_hash_type(hash_val)
            data, err = self._request("GET", f"/indicators/file/{hash_val}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return ToolResult(
                source=self.name,
                data={
                    "type": "hash",
                    "value": hash_val,
                    "hash_type": indicator_type,
                    "md5": data.get("md5", ""),
                    "sha1": data.get("sha1", ""),
                    "sha256": data.get("sha256", ""),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [self._pulse_with_techniques(p) for p in pulses[:5]],
                },
            )

        if url_val:
            data, err = self._request("GET", f"/indicators/url/{urllib.parse.quote(url_val, safe='')}", headers=self._headers())
            if err:
                if "Not found (404)" in err:
                    return ToolResult(source=self.name, data={"type": "url", "value": url_val, "pulse_count": 0, "pulses": []})
                return ToolResult(source=self.name, error=err, data={})
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return ToolResult(
                source=self.name,
                data={
                    "type": "url",
                    "value": url_val,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [self._pulse_with_techniques(p) for p in pulses[:5]],
                },
            )

        if actor:
            data, err = self._request("GET", "/search/pulses", headers=self._headers(),
                                      params={"q": actor})
            if err:
                return ToolResult(source=self.name, error=err, data={})
            results = data.get("results", [])
            actor_pulses = []
            for p in results:
                adv = (p.get("adversary") or "").lower()
                name = (p.get("name") or "").lower()
                if actor.lower() in adv or actor.lower() in name:
                    actor_pulses.append(self._pulse_with_techniques(p))
            return ToolResult(
                source=self.name,
                data={"actor": actor, "pulses": actor_pulses[:10], "count": len(actor_pulses)},
            )

        return ToolResult(source=self.name, error="No indicator provided", data={})

    def _pulse_with_techniques(self, pulse: dict, max_desc: int = 300) -> dict:
        p = {
            "name": pulse.get("name", ""),
            "tags": pulse.get("tags", []),
            "description": (pulse.get("description") or "")[:max_desc],
            "created": pulse.get("created", ""),
            "adversary": pulse.get("adversary", ""),
        }
        techniques = resolve_tags(pulse.get("tags", []))
        if techniques:
            p["techniques"] = techniques
        return p

    def _detect_hash_type(self, h: str) -> str:
        length = len(h)
        if length == 32:
            return "MD5"
        if length == 40:
            return "SHA1"
        if length == 64:
            return "SHA256"
        if length == 128:
            return "SHA512"
        return "unknown"
