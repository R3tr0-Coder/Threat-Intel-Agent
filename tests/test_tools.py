import pytest
from src.tools.virus_total import VirusTotal
from src.tools.abuse_ipdb import AbuseIPDB
from src.tools.alienvault_otx import AlienVaultOTX
from src.tools.nvd_tool import NVD
from src.ttp_resolver import resolve_technique, resolve_tags, find_techniques_in_text, all_techniques, get_all_tactics
from tests.conftest import mock_vt_get, mock_abuseipdb, mock_otx, mock_nvd, mock_mitre


class TestVirusTotal:
    def test_ip_lookup(self, mock_vt_get):
        vt = VirusTotal()
        vt.api_key = "test_key"
        result = vt.execute(ip="45.83.122.10")
        assert not result.error
        assert result.data.get("malicious") == 12
        assert result.data.get("total_engines") == 70

    def test_domain_lookup(self, mock_vt_get):
        vt = VirusTotal()
        vt.api_key = "test_key"
        result = vt.execute(domain="evil.example.com")
        assert not result.error
        assert result.data.get("type") == "domain"

    def test_hash_lookup(self, mock_vt_get):
        vt = VirusTotal()
        vt.api_key = "test_key"
        result = vt.execute(hash_val="a" * 64)
        assert not result.error
        assert result.data.get("type") == "hash"

    def test_no_api_key(self):
        vt = VirusTotal()
        vt.api_key = ""
        result = vt.execute(ip="1.2.3.4")
        assert result.error and "not configured" in result.error

    def test_no_indicator(self):
        vt = VirusTotal()
        vt.api_key = "test_key"
        result = vt.execute()
        assert result.error and "No indicator" in result.error


class TestAbuseIPDB:
    def test_ip_check(self, mock_abuseipdb):
        ab = AbuseIPDB()
        ab.api_key = "test_key"
        result = ab.execute(ip="45.83.122.10")
        assert not result.error
        assert result.data.get("abuse_confidence_score") == 95
        assert result.data.get("total_reports") == 150

    def test_no_api_key(self):
        ab = AbuseIPDB()
        ab.api_key = ""
        result = ab.execute(ip="1.2.3.4")
        assert result.error and "not configured" in result.error

    def test_no_ip(self):
        ab = AbuseIPDB()
        ab.api_key = "test_key"
        result = ab.execute()
        assert result.error and "No IP" in result.error


class TestAlienVaultOTX:
    def test_ip_lookup(self, mock_otx):
        otx = AlienVaultOTX()
        otx.api_key = "test_key"
        result = otx.execute(ip="45.83.122.10")
        assert not result.error
        assert result.data.get("type") == "ip"
        assert len(result.data.get("pulses", [])) > 0

    def test_actor_lookup(self, mock_otx):
        otx = AlienVaultOTX()
        otx.api_key = "test_key"
        result = otx.execute(actor="APT29")
        assert not result.error
        assert result.data.get("actor") == "APT29"
        assert result.data.get("count", 0) == 2
        assert len(result.data.get("pulses", [])) == 2
        assert "tags" in result.data["pulses"][0]
        assert result.data["pulses"][0]["adversary"] == "APT29"

    def test_no_api_key(self):
        otx = AlienVaultOTX()
        otx.api_key = ""
        result = otx.execute(ip="1.2.3.4")
        assert result.error and "not configured" in result.error


class TestNVD:
    def test_cve_lookup(self, mock_nvd):
        nvd = NVD()
        nvd.api_key = "test_key"
        result = nvd.execute(cve_id="CVE-2023-22527")
        assert not result.error
        assert len(result.data.get("cves", [])) == 2
        assert result.data["cves"][0]["id"] == "CVE-2023-22527"

    def test_software_search(self, mock_nvd):
        nvd = NVD()
        nvd.api_key = "test_key"
        result = nvd.execute(software="Confluence", version="7.13")
        assert not result.error
        assert result.data["cves"][0]["cvss_v31_score"] == 9.8

    def test_no_criteria(self):
        nvd = NVD()
        nvd.api_key = "test_key"
        result = nvd.execute()
        assert result.error and "No search criteria" in result.error



class TestTTPResolver:
    def test_resolve_by_id(self, mock_mitre):
        r = resolve_technique("T1574.002")
        assert r is not None
        assert r["name"] == "DLL Side-Loading"
        assert "Defense Evasion" in r["tactics"]

    def test_resolve_case_insensitive(self, mock_mitre):
        r = resolve_technique("t1574.002")
        assert r is not None
        assert r["name"] == "DLL Side-Loading"

    def test_resolve_not_found(self, mock_mitre):
        r = resolve_technique("T9999.999")
        assert r is None

    def test_resolve_tags_finds_techniques(self, mock_mitre):
        tags = ["apt29", "t1574.002", "dll-side-loading", "t1566.001"]
        results = resolve_tags(tags)
        assert len(results) == 2
        ids = [r["id"] for r in results]
        assert "T1574.002" in ids
        assert "T1566.001" in ids

    def test_resolve_tags_no_match(self, mock_mitre):
        tags = ["apt29", "phishing", "c2"]
        results = resolve_tags(tags)
        assert len(results) == 0

    def test_find_techniques_in_text(self, mock_mitre):
        text = "The actor uses T1574.002 for DLL side-loading and T1003 for credential dumping."
        results = find_techniques_in_text(text)
        assert len(results) == 2
        ids = [r["id"] for r in results]
        assert "T1574.002" in ids
        assert "T1003" in ids

    def test_all_techniques(self, mock_mitre):
        all_t = all_techniques()
        assert len(all_t) == 4
        assert "T1574.002" in all_t

    def test_get_all_tactics(self, mock_mitre):
        tactics = get_all_tactics()
        assert "Defense Evasion" in tactics
        assert "Initial Access" in tactics
        assert "Credential Access" in tactics

    def test_otx_actor_lookup_resolves_techniques(self, mock_otx, mock_mitre):
        otx = AlienVaultOTX()
        otx.api_key = "test_key"
        result = otx.execute(actor="APT29")
        assert not result.error
        pulses = result.data.get("pulses", [])
        attack_pulses = [p for p in pulses if "techniques" in p]
        assert len(attack_pulses) > 0
        second = pulses[1]
        assert "techniques" in second
        tech_ids = [t["id"] for t in second["techniques"]]
        assert "T1574.002" in tech_ids
