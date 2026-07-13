import json
import re
from typing import Optional

from src.config import GEMINI_API_KEY, OPENROUTER_API_KEY
from src.models import IntentClassification, IntentType, EntityContext, LLMUsage
from src.observability import log_event
from src.llm_client import generate as llm_generate


INTENT_SYSTEM_PROMPT = """You are a threat intelligence query parser for a SOC analyst tool. Your job is to classify the user's natural-language query into one of these intents:

1. ioc_lookup — Checking the reputation of an IP address, file hash, domain, or URL (e.g. "Is 45.83.122.10 malicious?")
2. actor_ttp — Profiling a threat actor or their techniques (e.g. "What TTPs is APT29 known for?")
3. exposure_check — Mapping a software version to known vulnerabilities (e.g. "We run Confluence 7.13 — are we exposed?")
4. pivot — Moving from one entity to related entities (e.g. "Pivot from that IP to related domains")
5. context_question — A follow-up question that references prior context with pronouns like "it", "that IP", "its ASN", "the domain" (e.g. "and what's its ASN?")
6. unknown — Cannot determine the intent

Extract entities from the query:
- ip: IPv4 or IPv6 address
- domain: domain name
- hash: file hash (MD5, SHA1, SHA256)
- url: URL
- actor: threat actor name (e.g. APT29, Lazarus, Cozy Bear)
- software: software/product name (e.g. Confluence, Exchange, Apache)
- version: version string (e.g. 7.13, 2019, 1.2.3)

If the query uses pronouns (it, its, that, they, them, this), check the conversation context to resolve what entity is being referenced. Set resolved_reference to the entity value.

Respond with JSON only, no other text."""


def parse_intent(
    query: str,
    context: Optional[EntityContext] = None,
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> tuple[IntentClassification, LLMUsage]:
    if not GEMINI_API_KEY and not OPENROUTER_API_KEY:
        return _rule_based_fallback(query), LLMUsage()
    if not provider:
        from src.config import LLM_PROVIDER
        provider = LLM_PROVIDER

    context_str = _format_context(context)

    system_prompt = INTENT_SYSTEM_PROMPT
    user_prompt = f"""Conversation context:
{context_str}

User query: {query}

Return JSON:
{{
    "intent": "ioc_lookup | actor_ttp | exposure_check | pivot | context_question | unknown",
    "entities": {{
        "ip": null or "1.2.3.4",
        "domain": null or "example.com",
        "hash": null or "md5/sha1/sha256",
        "url": null or "https://...",
        "actor": null or "APT29",
        "software": null or "Confluence",
        "version": null or "7.13"
    }},
    "confidence": 0.0-1.0,
    "resolved_reference": null or "resolved entity value"
}}"""

    try:
        from src.config import GEMINI_MODEL, OPENROUTER_MODEL
        resolved_model = model or (OPENROUTER_MODEL if provider == "openrouter" else GEMINI_MODEL)
        config = {"temperature": 0.1}
        if provider != "openrouter":
            config["response_mime_type"] = "application/json"
        llm_resp = llm_generate(provider, resolved_model, system_prompt, user_prompt, config)
        usage = LLMUsage(
            provider=provider,
            model=resolved_model,
            prompt_tokens=llm_resp.prompt_tokens,
            completion_tokens=llm_resp.completion_tokens,
            total_tokens=llm_resp.total_tokens,
            cost=llm_resp.cost,
        )
        log_event("intent_parsed", {"query": query[:100], "raw_response": llm_resp.text[:200]})
        parsed = json.loads(llm_resp.text)
        return IntentClassification(
            intent=parsed.get("intent", "unknown"),
            entities=parsed.get("entities", {}),
            confidence=parsed.get("confidence", 0.5),
            resolved_reference=parsed.get("resolved_reference"),
        ), usage
    except Exception as e:
        log_event("intent_parse_error", {"query": query[:100], "error": str(e)[:200]})
        return _rule_based_fallback(query), LLMUsage()


def _format_context(ctx: Optional[EntityContext]) -> str:
    if not ctx:
        return "No prior context."
    parts = []
    if ctx.ips:
        parts.append(f"Known IPs: {', '.join(ctx.ips.keys())}")
    if ctx.domains:
        parts.append(f"Known domains: {', '.join(ctx.domains.keys())}")
    if ctx.hashes:
        parts.append(f"Known hashes: {', '.join(ctx.hashes.keys())}")
    if ctx.actors:
        parts.append(f"Known actors: {', '.join(ctx.actors.keys())}")
    if ctx.software:
        parts.append(f"Known software: {', '.join(ctx.software.keys())}")
    if ctx.urls:
        parts.append(f"Known URLs: {', '.join(ctx.urls.keys())}")
    if ctx.cves:
        parts.append(f"Known CVEs: {', '.join(ctx.cves.keys())}")
    if ctx.last_topic:
        parts.append(f"Last topic: {ctx.last_topic}")
    return "\n".join(parts) if parts else "No relevant entities in context."


def _rule_based_fallback(query: str) -> IntentClassification:
    q = query.lower()
    entities: dict = {}
    intent = "unknown"

    url_pattern = r"\bhttps?://[^\s]+"
    url_match = re.search(url_pattern, query)
    if url_match:
        entities["url"] = url_match.group()

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ip_match = re.search(ip_pattern, query)
    if ip_match:
        entities["ip"] = ip_match.group()

    domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    domain_match = re.search(domain_pattern, query)
    if domain_match:
        entities["domain"] = domain_match.group()

    hash_pattern = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    hash_match = re.search(hash_pattern, query)
    if hash_match:
        entities["hash"] = hash_match.group()

    cve_pattern = r"\bCVE-\d{4}-\d{4,}\b"
    cve_match = re.search(cve_pattern, query, re.IGNORECASE)
    if cve_match:
        entities["cve"] = cve_match.group().upper()

    KNOWN_SOFTWARE = [
        "confluence", "exchange", "apache", "nginx", "iis", "tomcat", "weblogic",
        "websphere", "jboss", "jenkins", "gitlab", "jira", "wordpress", "drupal",
        "joomla", "php", "mysql", "mariadb", "postgresql", "sql server", "oracle db",
        "mongodb", "redis", "elasticsearch", "kibana", "logstash", "kubernetes",
        "docker", "openshift", "vmware", "citrix", "pulse secure", "fortinet",
        "palo alto", "cisco", "juniper", "openssh", "openvpn", "python", "java",
        "node", "ruby", "go", "rust", "struts", "spring", "rails", "django",
        "laravel", "symfony", "vcenter", "esxi", "hyper-v", "azure", "aws",
    ]
    sw_lower = q.lower()
    for sw in KNOWN_SOFTWARE:
        if re.search(r'(?<![a-zA-Z./])' + re.escape(sw) + r'(?![a-zA-Z./])', sw_lower):
            entities["software"] = sw
            break

    actor_keywords = ["apt", "threat actor", "group", "ttps", "actor"]
    if any(k in q for k in actor_keywords):
        for word in q.split():
            word_clean = word.strip(",.?!;:")
            if re.match(r"apt\d+", word_clean, re.IGNORECASE) or word_clean.lower() in [
                "lazarus", "fancybear", "cozybear", "kimsuky", "wizard spider",
                "fin7", "carbanak", "silver fish", "menupass", "turla", "venomous bear",
                "apt29", "apt28", "apt1", "apt3", "apt33", "apt34", "apt41",
                "oilrig", "muddywater", "darkhotel", "gotiger", "rocke", "ta505",
            ]:
                entities["actor"] = word_clean

    if not entities.get("ip"):
        version_pattern = r"\b(\d+\.\d+(?:\.\d+)?)\b"
        version_match = re.search(version_pattern, query)
        if version_match:
            entities["version"] = version_match.group()

    if entities.get("cve"):
        intent = "exposure_check"
    elif entities.get("ip") or entities.get("hash") or entities.get("domain") or entities.get("url"):
        if any(k in q for k in ["pivot", "related", "connected", "also", "linked", "resolve", "find", "show"]):
            intent = "pivot"
        elif any(k in q for k in ["malicious", "reputation", "bad", "safe", "check", "lookup", "scan", "reputation"]):
            intent = "ioc_lookup"
        else:
            intent = "ioc_lookup"

    if entities.get("actor") or any(re.search(r'\b' + k, q) for k in ["ttp", "technique", "profile", "known for"]):
        intent = "actor_ttp"

    if entities.get("version") or any(k in q for k in ["exposed", "vulnerable", "vulnerability", "severity"]):
        if intent != "exposure_check":
            intent = "exposure_check"

    if any(k in q for k in ["pivot", "resolve"]):
        intent = "pivot"

    if any(k in q for k in ["it", "its", "that", "they", "them", "the domain", "the ip", "the hash"]):
        if intent == "unknown":
            intent = "context_question"

    return IntentClassification(
        intent=intent,
        entities=entities,
        confidence=0.6,
        resolved_reference=None,
    )
