import pytest
from src.intent_parser import _rule_based_fallback
from src.models import IntentType


class TestRuleBasedFallback:
    def test_ioc_lookup_ip(self):
        result = _rule_based_fallback("Is 45.83.122.10 malicious?")
        assert result.intent == IntentType.ioc_lookup
        assert result.entities.get("ip") == "45.83.122.10"

    def test_ioc_lookup_domain(self):
        result = _rule_based_fallback("Check reputation of evil.example.com")
        assert result.intent == IntentType.ioc_lookup
        assert "evil.example.com" in result.entities.get("domain", "")

    def test_ioc_lookup_hash(self):
        h = "a" * 64
        result = _rule_based_fallback(f"Scan hash {h}")
        assert result.intent == IntentType.ioc_lookup
        assert result.entities.get("hash") == h

    def test_actor_ttp(self):
        result = _rule_based_fallback("What TTPs is APT29 known for?")
        assert result.intent == IntentType.actor_ttp

    def test_exposure_check(self):
        result = _rule_based_fallback("We run Confluence 7.13 — are we exposed?")
        assert result.intent == IntentType.exposure_check
        assert result.entities.get("version") == "7.13"

    def test_pivot_intent(self):
        result = _rule_based_fallback("Pivot from that IP to related domains")
        assert result.intent == IntentType.pivot

    def test_context_question_pronoun(self):
        result = _rule_based_fallback("and what's its ASN?")
        assert result.intent == IntentType.context_question

    def test_unknown_query(self):
        result = _rule_based_fallback("Hello, how are you?")
        assert result.intent == IntentType.unknown

    def test_ip_extraction(self):
        result = _rule_based_fallback("Check 192.168.1.1 for malicious activity")
        assert result.entities.get("ip") == "192.168.1.1"

    def test_domain_extraction(self):
        result = _rule_based_fallback("Is test.suspicious-domain.com bad?")
        assert "test.suspicious-domain.com" in result.entities.get("domain", "")

    def test_version_extraction(self):
        result = _rule_based_fallback("Check Apache Struts 2.5.33 vulnerability")
        assert result.entities.get("version") == "2.5.33"

    def test_cve_extraction_uses_cve_key(self):
        result = _rule_based_fallback("CVE-2023-22527 - what's the severity?")
        assert result.entities.get("cve") == "CVE-2023-22527"
        assert result.intent == IntentType.exposure_check

    def test_url_routed_to_ioc_lookup(self):
        result = _rule_based_fallback("Check this URL: https://phishing.example.com/login")
        assert result.entities.get("url") == "https://phishing.example.com/login"
        assert result.intent == IntentType.ioc_lookup

    def test_software_extraction_confluence(self):
        result = _rule_based_fallback("Is Confluence 7.13 exposed?")
        assert result.entities.get("software") == "confluence"
        assert result.intent == IntentType.exposure_check

    def test_software_extraction_nginx(self):
        result = _rule_based_fallback("Check nginx 1.24.0 for vulnerabilities")
        assert result.entities.get("software") == "nginx"
        assert result.intent == IntentType.exposure_check

    def test_actor_expanded_apt_pattern(self):
        result = _rule_based_fallback("What TTPs does APT33 use?")
        assert result.entities.get("actor") is not None
        assert "apt33" in result.entities.get("actor", "").lower()
        assert result.intent == IntentType.actor_ttp

    def test_actor_fin7(self):
        result = _rule_based_fallback("Profile the FIN7 group")
        assert result.entities.get("actor") is not None
        assert "fin7" in result.entities.get("actor", "").lower()

    def test_pivot_resolve_keyword(self):
        result = _rule_based_fallback("Resolve 45.83.122.10 to domains")
        assert result.intent == IntentType.pivot

    def test_pivot_find_keyword(self):
        result = _rule_based_fallback("Find related domains for 45.83.122.10")
        assert result.intent == IntentType.pivot

    def test_context_question_does_not_override_pivot(self):
        result = _rule_based_fallback("Pivot from that IP to related domains")
        assert result.intent == IntentType.pivot

    def test_cve_triggers_exposure_before_version_check(self):
        result = _rule_based_fallback("CVE-2024-1234 - what's the CVSS?")
        assert result.entities.get("cve") == "CVE-2024-1234"
        assert result.intent == IntentType.exposure_check

    def test_ioc_lookup_url_no_malicious_keyword(self):
        result = _rule_based_fallback("https://evil.com/shell.php")
        assert result.entities.get("url") is not None
        assert result.intent == IntentType.ioc_lookup


class TestIntentConfidence:
    def test_rule_based_default_confidence(self):
        result = _rule_based_fallback("Is 1.2.3.4 malicious?")
        assert result.confidence == 0.6
