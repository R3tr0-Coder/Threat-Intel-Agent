from src.config import ABUSEIPDB_API_KEY
from src.models import ToolResult
from src.tools.base import ToolABC


class AbuseIPDB(ToolABC):
    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        super().__init__()
        self.api_key = ABUSEIPDB_API_KEY

    def _headers(self):
        return {"Key": self.api_key, "Accept": "application/json"}

    def execute(self, ip: str = "", max_age_days: int = 90) -> ToolResult:
        if not self.api_key:
            return ToolResult(source=self.name, error="ABUSEIPDB_API_KEY not configured", data={})
        if not ip:
            return ToolResult(source=self.name, error="No IP address provided", data={})

        data, err = self._request(
            "GET", "/check",
            headers=self._headers(),
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
        )
        if err:
            return ToolResult(source=self.name, error=err, data={})

        d = data.get("data", {})
        return ToolResult(
            source=self.name,
            data={
                "ip": ip,
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", ""),
                "country_name": d.get("countryName", ""),
                "domain": d.get("domain", ""),
                "isp": d.get("isp", ""),
                "usage_type": d.get("usageType", ""),
                "total_reports": d.get("totalReports", 0),
                "last_reported_at": d.get("lastReportedAt", ""),
                "is_whitelisted": d.get("isWhitelisted", False),
                "is_tor": d.get("isTor", False),
                "reports": [
                    {"date": r.get("reportedAt"), "category": r.get("category"),
                     "comment": (r.get("comment") or "")[:200]}
                    for r in (d.get("reports") or [])[:5]
                ],
            },
        )
