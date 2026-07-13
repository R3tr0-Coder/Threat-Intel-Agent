import urllib.parse
import time
from typing import Optional
from src.config import VIRUSTOTAL_API_KEY
from src.models import ToolResult
from src.tools.base import ToolABC


class VirusTotal(ToolABC):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self):
        super().__init__()
        self.api_key = VIRUSTOTAL_API_KEY

    def _headers(self):
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    def execute(self, ip: Optional[str] = None, domain: Optional[str] = None,
                hash_val: Optional[str] = None, url_val: Optional[str] = None) -> ToolResult:
        if not self.api_key:
            return ToolResult(source=self.name, error="VIRUSTOTAL_API_KEY not configured", data={})

        if ip:
            data, err = self._request("GET", f"/ip_addresses/{ip}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            return ToolResult(
                source=self.name,
                data={
                    "type": "ip",
                    "value": ip,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total,
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "country": data.get("data", {}).get("attributes", {}).get("country", ""),
                    "asn": data.get("data", {}).get("attributes", {}).get("asn", ""),
                    "as_owner": data.get("data", {}).get("attributes", {}).get("as_owner", ""),
                    "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                },
            )

        if domain:
            data, err = self._request("GET", f"/domains/{domain}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return ToolResult(
                source=self.name,
                data={
                    "type": "domain",
                    "value": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "registrar": data.get("data", {}).get("attributes", {}).get("registrar", ""),
                    "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                },
            )

        if hash_val:
            data, err = self._request("GET", f"/files/{hash_val}", headers=self._headers())
            if err:
                return ToolResult(source=self.name, error=err, data={})
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return ToolResult(
                source=self.name,
                data={
                    "type": "hash",
                    "value": hash_val,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "names": data.get("data", {}).get("attributes", {}).get("names", []),
                    "type_description": data.get("data", {}).get("attributes", {}).get("type_description", ""),
                    "last_analysis_date": data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                },
            )

        if url_val:
            encoded = urllib.parse.quote(url_val, safe="")
            data, err = self._request("GET", f"/urls/{encoded}", headers=self._headers())
            if err and "Not found (404)" in err:
                form_body = urllib.parse.urlencode({"url": url_val})
                scan_data, scan_err = self._request(
                    "POST", "/urls",
                    headers={**self._headers(), "Content-Type": "application/x-www-form-urlencoded"},
                    data=form_body,
                )
                if scan_err:
                    return ToolResult(source=self.name, error=scan_err, data={})
                analysis_id = scan_data.get("data", {}).get("id", "")
                if analysis_id:
                    for attempt in range(5):
                        time.sleep(10)
                        data, err = self._request("GET", f"/analyses/{analysis_id}", headers=self._headers())
                        if err:
                            break
                        status = data.get("data", {}).get("attributes", {}).get("status", "")
                        if status == "completed":
                            break
            if err:
                return ToolResult(source=self.name, error=err, data={})
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
            return ToolResult(
                source=self.name,
                data={
                    "type": "url",
                    "value": url_val,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "last_analysis_date": attrs.get("last_analysis_date") or attrs.get("date"),
                },
            )

        return ToolResult(source=self.name, error="No indicator provided (ip, domain, hash, or url)", data={})

    def get_related_domains(self, ip: str) -> ToolResult:
        if not self.api_key:
            return ToolResult(source=self.name, error="API key not configured", data={})
        data, err = self._request(
            "GET", f"/ip_addresses/{ip}/resolutions",
            headers=self._headers(), params={"limit": 40}
        )
        if err:
            return ToolResult(source=self.name, error=err, data={})
        resolutions = data.get("data", [])
        domains = []
        for r in resolutions:
            attrs = r.get("attributes", {})
            host = attrs.get("host_name", "")
            if host:
                domains.append({"host": host, "last_resolved": attrs.get("date")})
        return ToolResult(
            source=self.name,
            data={"ip": ip, "resolutions": domains, "count": len(domains)},
        )
