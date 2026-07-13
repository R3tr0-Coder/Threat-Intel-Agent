from typing import Optional
from src.config import NVD_API_KEY
from src.models import ToolResult
from src.tools.base import ToolABC


class NVD(ToolABC):
    name = "nvd"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        super().__init__()
        self.api_key = NVD_API_KEY

    def _headers(self):
        h = {}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def execute(self, cve_id: Optional[str] = None,
                software: Optional[str] = None, version: Optional[str] = None,
                keyword: Optional[str] = None) -> ToolResult:
        params = {}

        if cve_id:
            params["cveId"] = cve_id.upper().strip()
        elif keyword:
            params["keywordSearch"] = keyword
            params["keywordExactMatch"] = False
        elif software:
            cpe = self._build_cpe(software, version)
            params["cpeName"] = cpe
        else:
            return ToolResult(source=self.name, error="No search criteria provided (cve_id, keyword, or software)", data={})

        data, err = self._request("GET", "", headers=self._headers(), params=params)
        if err:
            return ToolResult(source=self.name, error=err, data={})

        vulns = data.get("vulnerabilities", [])
        cves = []
        for v in vulns[:10]:
            cve = v.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
            cvss30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV30") else {}
            cvss2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV2") else {}

            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")[:500]
                    break

            refs = [r.get("url", "") for r in (cve.get("references") or [])[:5]]

            cves.append({
                "id": cve.get("id", ""),
                "description": description,
                "cvss_v31_score": cvss31.get("baseScore"),
                "cvss_v31_severity": cvss31.get("baseSeverity"),
                "cvss_v30_score": cvss30.get("baseScore"),
                "cvss_v30_severity": cvss30.get("baseSeverity"),
                "cvss_v2_score": cvss2.get("baseScore"),
                "cvss_v2_severity": cvss2.get("baseSeverity"),
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "references": refs,
                "cwe_ids": [w.get("value", "") for w in
                            (cve.get("weaknesses") or [{}])[0].get("description", [])] if cve.get("weaknesses") else [],
            })

        return ToolResult(
            source=self.name,
            data={
                "total_results": data.get("totalResults", 0),
                "results_per_page": data.get("resultsPerPage", 0),
                "cves": cves,
                "search_params": {"cve_id": cve_id, "keyword": keyword, "software": software, "version": version},
            },
        )

    CPE_ALIASES = {
        "confluence": ("atlassian", "confluence"),
        "jira": ("atlassian", "jira"),
        "exchange": ("microsoft", "exchange_server"),
        "apache": ("apache", "apache"),
        "nginx": ("nginx", "nginx"),
        "iis": ("microsoft", "internet_information_services"),
        "tomcat": ("apache", "tomcat"),
        "weblogic": ("oracle", "weblogic_server"),
        "websphere": ("ibm", "websphere_application_server"),
        "jenkins": ("jenkins", "jenkins"),
        "gitlab": ("gitlab", "gitlab"),
        "wordpress": ("wordpress", "wordpress"),
        "drupal": ("drupal", "drupal"),
        "mysql": ("oracle", "mysql"),
        "elasticsearch": ("elastic", "elasticsearch"),
        "kubernetes": ("kubernetes", "kubernetes"),
        "docker": ("docker", "docker"),
        "vmware": ("vmware", "vmware"),
        "citrix": ("citrix", "citrix"),
        "fortinet": ("fortinet", "fortinet"),
        "struts": ("apache", "struts"),
        "vcenter": ("vmware", "vcenter_server"),
        "esxi": ("vmware", "esxi"),
    }

    def _build_cpe(self, software: str, version: Optional[str] = None) -> str:
        sw = software.lower().strip()
        alias = self.CPE_ALIASES.get(sw)
        if alias:
            vendor, product = alias
        else:
            vendor = sw.replace(" ", "_")
            product = sw.replace(" ", "_")
        ver = version if version else "*"
        return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
