import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock

from src.orchestrator import ThreatIntelAgent
from src.context_manager import ContextManager
from src.models import EntityContext, IntentClassification, IntentType, ConversationTurn, ToolResult, LLMUsage
from src.injection_guard import InjectionGuard
from src.confidence import score_confidence
from src.rate_limiter import RateLimiter
from tests.fixtures.mock_data import (
    MOCK_VT_IP_RESPONSE, MOCK_VT_DOMAIN_RESPONSE, MOCK_VT_HASH_RESPONSE,
    MOCK_ABUSEIPDB_RESPONSE, MOCK_OTX_IP_RESPONSE, MOCK_OTX_ACTOR_RESPONSE, MOCK_OTX_URL_RESPONSE,
    MOCK_NVD_RESPONSE, MOCK_VT_RESOLUTIONS_RESPONSE,
    MOCK_MITRE_TECHNIQUES,
)


@pytest.fixture
def agent():
    return ThreatIntelAgent()


@pytest.fixture
def context_manager():
    return ContextManager()


@pytest.fixture
def entity_context():
    ctx = EntityContext()
    ctx.ips["45.83.122.10"] = "2024-01-01T00:00:00"
    ctx.domains["evil.example.com"] = "2024-01-01T00:00:00"
    ctx.hashes["a" * 64] = "2024-01-01T00:00:00"
    ctx.actors["APT29"] = "2024-01-01T00:00:00"
    ctx.software["Confluence"] = "2024-01-01T00:00:00"
    ctx.last_topic = "45.83.122.10"
    return ctx


@pytest.fixture
def injection_guard():
    return InjectionGuard()


@pytest.fixture
def mock_vt_get(monkeypatch):
    def mock_request(self, method, url, **kwargs):
        if "resolutions" in url:
            return MOCK_VT_RESOLUTIONS_RESPONSE, None
        if "/ip_addresses/" in url:
            return MOCK_VT_IP_RESPONSE, None
        if "/domains/" in url:
            return MOCK_VT_DOMAIN_RESPONSE, None
        if "/files/" in url:
            return MOCK_VT_HASH_RESPONSE, None
        if "/analyses/" in url:
            return {"data": {"attributes": {"stats": {"malicious": 2, "suspicious": 1, "harmless": 50, "undetected": 17}, "status": "completed"}}}, None
        if "/urls/" in url:
            return {}, "Not found (404): Resource not found."
        if method == "POST" and "/urls" in url and "/urls/" not in url:
            return {"data": {"id": "analysis-123"}}, None
        return {}, "Not found"
    monkeypatch.setattr("src.tools.virus_total.VirusTotal._request", mock_request)


@pytest.fixture
def mock_abuseipdb(monkeypatch):
    def mock_request(self, method, url, **kwargs):
        return MOCK_ABUSEIPDB_RESPONSE, None
    monkeypatch.setattr("src.tools.abuse_ipdb.AbuseIPDB._request", mock_request)


@pytest.fixture
def mock_otx(monkeypatch):
    def mock_request(self, method, url, **kwargs):
        if "search/pulses" in url:
            return MOCK_OTX_ACTOR_RESPONSE, None
        if "/indicators/url/" in url:
            return MOCK_OTX_URL_RESPONSE, None
        return MOCK_OTX_IP_RESPONSE, None
    monkeypatch.setattr("src.tools.alienvault_otx.AlienVaultOTX._request", mock_request)


@pytest.fixture
def mock_nvd(monkeypatch):
    def mock_request(self, method, url, **kwargs):
        return MOCK_NVD_RESPONSE, None
    monkeypatch.setattr("src.tools.nvd_tool.NVD._request", mock_request)



@pytest.fixture
def mock_gemini_intent(monkeypatch):
    def _detect_hash(q):
        import re
        m = re.search(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b", q)
        return m.group() if m else None

    def mock_parse(query, context=None, model=None, provider=None):
        import re
        q = query.lower()
        entities = {}
        if _detect_hash(query):
            entities["hash"] = _detect_hash(query)
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
        if ip_m:
            entities["ip"] = ip_m.group()
        dom_m = re.search(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b", query)
        if dom_m:
            entities["domain"] = dom_m.group()
        cve_m = re.search(r"\bCVE-\d{4}-\d{4,}\b", query, re.IGNORECASE)
        if cve_m:
            entities["cve_id"] = cve_m.group().upper()
        if "lazarus" in q or "kimsuky" in q or "fancybear" in q:
            entities["actor"] = "lazarus" if "lazarus" in q else "kimsuky"
        ver_m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", q)
        if ver_m and not ip_m:
            entities["version"] = ver_m.group()

        def has_word(word):
            return bool(re.search(r'\b' + word, q))

        def _make_result(intent, entities=entities, confidence=0.9):
            return IntentClassification(intent=intent, entities=entities, confidence=confidence), LLMUsage()

        if entities.get("cve_id") or has_word("exposed") or has_word("vulnerab"):
            return _make_result(IntentType.exposure_check)
        if has_word("ttp") or has_word("technique") or has_word("actor") or has_word("apt") or has_word("profile") or has_word("group"):
            return _make_result(IntentType.actor_ttp)
        if has_word("pivot") or has_word("related") or has_word("resolve"):
            return _make_result(IntentType.pivot, confidence=0.9)
        if has_word("it") or has_word("its") or has_word("that") or "the domain" in q or "the ip" in q:
            return _make_result(IntentType.context_question, confidence=0.8)
        if entities:
            return _make_result(IntentType.ioc_lookup, confidence=0.95)
        return _make_result(IntentType.unknown, entities={}, confidence=0.3)
    monkeypatch.setattr("src.intent_parser.parse_intent", mock_parse)
    monkeypatch.setattr("src.orchestrator.parse_intent", mock_parse)


@pytest.fixture
def mock_gemini_response(monkeypatch):
    def mock_generate(query, intent, tool_results, context_summary, confidence, model=None, provider=None):
        text = f"**Analysis Result**\n\nConfidence: {confidence:.0%}\n\nFound malicious indicators."
        return text, LLMUsage()
    monkeypatch.setattr("src.response_generator.generate_response", mock_generate)
    monkeypatch.setattr("src.orchestrator.generate_response", mock_generate)


@pytest.fixture
def mock_mitre(monkeypatch):
    import src.ttp_resolver as tr
    monkeypatch.setattr(tr, "_techniques", dict(MOCK_MITRE_TECHNIQUES))


@pytest.fixture
def mock_all_apis(mock_vt_get, mock_abuseipdb, mock_otx, mock_nvd, mock_mitre):
    pass
