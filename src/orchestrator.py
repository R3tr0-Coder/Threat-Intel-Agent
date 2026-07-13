from datetime import datetime
from typing import Optional
import time
import ipaddress
import re
import urllib.parse

from src.models import (
    ConversationTurn, EntityContext, IntentClassification, IntentType, ToolResult, TraceStep, LLMUsage,
)
from src.intent_parser import parse_intent
from src.context_manager import ContextManager
from src.injection_guard import InjectionGuard
from src.confidence import score_confidence
from src.response_generator import generate_response, TALKING_SYSTEM_PROMPT
from src.llm_client import generate as llm_generate
from src.rate_limiter import get_rate_limiter
from src.observability import log_event, clear_session_log
from src.cache import get_cache
from src.tools.virus_total import VirusTotal
from src.tools.abuse_ipdb import AbuseIPDB
from src.tools.alienvault_otx import AlienVaultOTX
from src.tools.nvd_tool import NVD



class ThreatIntelAgent:
    def __init__(self):
        self.context_manager = ContextManager()
        self.injection_guard = InjectionGuard()
        self.rate_limiter = get_rate_limiter()
        self.cache = get_cache()
        self.tools = {
            "virustotal": VirusTotal(),
            "abuseipdb": AbuseIPDB(),
            "otx": AlienVaultOTX(),
            "nvd": NVD(),
        }
        self._current_mode = "Analysis"
        clear_session_log()

    def process_query(self, query: str, model: Optional[str] = None, provider: Optional[str] = None, mode: str = "Analysis") -> ConversationTurn:
        self._current_mode = mode
        if mode == "Talking":
            return self._generate_talking_response(query, model=model, provider=provider)

        trace: list[TraceStep] = []
        start_time = datetime.utcnow().isoformat()

        step_injection = TraceStep(step="injection_check")
        inj_warning = self.injection_guard.check_query(query)
        if inj_warning:
            step_injection.status = "blocked"
            step_injection.result_summary = inj_warning
            step_injection.end_time = datetime.utcnow().isoformat()
            turn = ConversationTurn(
                query=query,
                intent=IntentClassification(intent=IntentType.unknown, entities={}, confidence=0.0),
                confidence=0.0,
                response=f"Query blocked: {inj_warning}",
                trace=[step_injection],
                injection_warning=inj_warning,
            )
            self.context_manager.add_turn(turn)
            return turn
        step_injection.status = "passed"
        step_injection.end_time = datetime.utcnow().isoformat()
        trace.append(step_injection)

        step_resolve = TraceStep(step="reference_resolution")
        resolved_query, resolved_ref = self.context_manager.resolve_references(query)
        step_resolve.result_summary = f"resolved: {resolved_query[:100]}" if resolved_ref else "no resolution needed"
        step_resolve.end_time = datetime.utcnow().isoformat()
        trace.append(step_resolve)

        step_intent = TraceStep(step="intent_parsing")
        llm_usage: list[LLMUsage] = []
        intent, intent_usage = parse_intent(resolved_query, self.context_manager.entity_context, model=model, provider=provider)
        llm_usage.append(intent_usage)
        if resolved_ref:
            intent.resolved_reference = resolved_ref
        if resolved_ref and intent.intent == IntentType.context_question:
            underlying, underlying_usage = parse_intent(resolved_query, None, model=model, provider=provider)
            llm_usage.append(underlying_usage)
            if underlying.intent != IntentType.context_question:
                intent = underlying
                intent.resolved_reference = resolved_ref
        step_intent.result_summary = f"intent={intent.intent.value}, confidence={intent.confidence:.2f}"
        step_intent.end_time = datetime.utcnow().isoformat()
        trace.append(step_intent)

        step_tools = TraceStep(step="tool_execution")
        tool_results = self._run_tools(intent)
        step_tools.result_summary = f"{len(tool_results)} tool(s) executed"
        step_tools.end_time = datetime.utcnow().isoformat()
        trace.append(step_tools)

        step_indirect_inj = TraceStep(step="indirect_injection_check")
        for r in tool_results:
            if r.error:
                continue
            if self._scan_for_injection(r.data):
                r.error = "Data flagged for potential injection"
                r.data = {}
                log_event("indirect_injection_blocked", {"source": r.source})
        step_indirect_inj.result_summary = "passed"
        step_indirect_inj.end_time = datetime.utcnow().isoformat()
        trace.append(step_indirect_inj)

        step_confidence = TraceStep(step="confidence_scoring")
        confidence = score_confidence(tool_results, intent.intent.value)
        step_confidence.result_summary = f"confidence={confidence:.2f}"
        step_confidence.end_time = datetime.utcnow().isoformat()
        trace.append(step_confidence)

        step_response = TraceStep(step="response_generation")
        context_summary = self._format_context_summary()
        response, response_usage = generate_response(resolved_query, intent, tool_results, context_summary, confidence, model=model, provider=provider)
        llm_usage.append(response_usage)
        step_response.result_summary = f"response length: {len(response)} chars"
        step_response.end_time = datetime.utcnow().isoformat()
        trace.append(step_response)

        step_finalize = TraceStep(step="finalize")
        turn = ConversationTurn(
            query=query,
            resolved_query=resolved_query if resolved_ref else None,
            intent=intent,
            tool_results=tool_results,
            confidence=confidence,
            response=response,
            trace=trace,
            llm_usage=llm_usage,
        )
        self.context_manager.add_turn(turn)
        step_finalize.end_time = datetime.utcnow().isoformat()
        trace.append(step_finalize)

        log_event("query_complete", {
            "query": query[:100],
            "intent": intent.intent.value,
            "confidence": confidence,
            "tool_count": len(tool_results),
        })
        return turn

    def _validate_ioc(self, ioc_type: str, value: str) -> Optional[str]:
        if not value:
            return None
        if ioc_type == "ip":
            try:
                addr = ipaddress.ip_address(value)
                if addr.is_private:
                    return f"IP {value} is a private address and cannot be looked up via external threat intel"
                if addr.is_multicast:
                    return f"IP {value} is a multicast address"
                if addr.is_loopback:
                    return f"IP {value} is a loopback address"
                if addr.is_unspecified:
                    return f"IP {value} is unspecified"
            except ValueError:
                return f"Invalid IP address: {value}"
        elif ioc_type == "hash":
            h = value.strip()
            valid_lengths = {32: "MD5", 40: "SHA1", 64: "SHA256"}
            if len(h) not in valid_lengths:
                return f"Invalid hash length {len(h)} (expected 32/40/64 for MD5/SHA1/SHA256)"
            if not re.match(r'^[a-fA-F0-9]+$', h):
                return f"Invalid hash format: contains non-hex characters"
        elif ioc_type == "domain":
            if len(value) > 253:
                return f"Domain too long ({len(value)} chars)"
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', value):
                return f"Invalid domain format: {value}"
        elif ioc_type == "url":
            if len(value) > 8192:
                return f"URL too long ({len(value)} chars)"
            if not re.match(r'^https?://', value):
                return f"URL must include a scheme (http:// or https://)"
        return None

    def _defang_url(self, url: str) -> str:
        return url.replace("http://", "hxxp://").replace("https://", "hxxps://")

    def _scan_for_injection(self, data, depth=0) -> bool:
        if depth > 5:
            return False
        if isinstance(data, str):
            return self.injection_guard.check_api_data(data[:500]) is not None
        if isinstance(data, dict):
            for v in data.values():
                if self._scan_for_injection(v, depth + 1):
                    return True
        if isinstance(data, list):
            for item in data:
                if self._scan_for_injection(item, depth + 1):
                    return True
        return False

    def _cached_tool_call(self, tool_name: str, method_name: str, **kwargs) -> ToolResult:
        cache_key = self.cache._key(tool_name, **kwargs)
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        if not self.rate_limiter.wait_and_call(tool_name):
            return ToolResult(source=tool_name, error=f"Rate limit exceeded for {tool_name}", data={})
        tool = self.tools[tool_name]
        method = getattr(tool, method_name)
        result = method(**kwargs)
        if not result.error:
            self.cache.set(cache_key, result)
        return result

    def _run_tools(self, intent: IntentClassification) -> list[ToolResult]:
        if self._current_mode == "Talking":
            return []
        results: list[ToolResult] = []
        entities = intent.entities
        intent_type = intent.intent

        if intent_type == IntentType.ioc_lookup:
            ip = entities.get("ip")
            domain = entities.get("domain")
            hash_val = entities.get("hash")
            url_val = entities.get("url")

            if ip:
                err = self._validate_ioc("ip", ip)
                if err:
                    results.append(ToolResult(source="validation", error=err, data={}))
                else:
                    results.append(self._cached_tool_call("virustotal", "safe_execute", ip=ip))
                    results.append(self._cached_tool_call("abuseipdb", "safe_execute", ip=ip))
                    results.append(self._cached_tool_call("otx", "safe_execute", ip=ip))

            if domain:
                err = self._validate_ioc("domain", domain)
                if err:
                    results.append(ToolResult(source="validation", error=err, data={}))
                else:
                    results.append(self._cached_tool_call("virustotal", "safe_execute", domain=domain))
                    results.append(self._cached_tool_call("otx", "safe_execute", domain=domain))

            if hash_val:
                err = self._validate_ioc("hash", hash_val)
                if err:
                    results.append(ToolResult(source="validation", error=err, data={}))
                else:
                    results.append(self._cached_tool_call("virustotal", "safe_execute", hash_val=hash_val))
                    results.append(self._cached_tool_call("otx", "safe_execute", hash_val=hash_val))

            if url_val:
                if not urllib.parse.urlparse(url_val).scheme:
                    url_val = "http://" + url_val
                err = self._validate_ioc("url", url_val)
                if err:
                    results.append(ToolResult(source="validation", error=err, data={}))
                else:
                    results.append(self._cached_tool_call("virustotal", "safe_execute", url_val=url_val))
                    results.append(self._cached_tool_call("otx", "safe_execute", url_val=url_val))
                    for r in results[-2:]:
                        if r.data and r.data.get("type") == "url":
                            r.data["value"] = self._defang_url(r.data["value"])

        elif intent_type == IntentType.actor_ttp:
            actor = entities.get("actor", "")
            if actor:
                results.append(self._cached_tool_call("otx", "safe_execute", actor=actor))

        elif intent_type == IntentType.exposure_check:
            software = entities.get("software", "")
            version = entities.get("version", "")
            results.append(self._cached_tool_call("nvd", "safe_execute", software=software, version=version))

        elif intent_type == IntentType.pivot:
            ip = entities.get("ip") or self.context_manager.entity_context.last_topic
            if ip:
                err = self._validate_ioc("ip", ip)
                if err:
                    results.append(ToolResult(source="validation", error=err, data={}))
                else:
                    results.append(self._cached_tool_call("virustotal", "get_related_domains", ip=ip))

        return results

    def _format_context_summary(self) -> str:
        ctx = self.context_manager.entity_context
        parts = []
        if ctx.ips:
            parts.append(f"IPs discussed: {', '.join(list(ctx.ips.keys())[-3:])}")
        if ctx.domains:
            parts.append(f"Domains discussed: {', '.join(list(ctx.domains.keys())[-3:])}")
        if ctx.hashes:
            parts.append(f"Hashes discussed: {', '.join(list(ctx.hashes.keys())[-3:])}")
        if ctx.urls:
            parts.append(f"URLs discussed: {', '.join(list(ctx.urls.keys())[-3:])}")
        if ctx.actors:
            parts.append(f"Actors discussed: {', '.join(list(ctx.actors.keys())[-3:])}")
        if ctx.software:
            parts.append(f"Software discussed: {', '.join(list(ctx.software.keys())[-3:])}")
        if ctx.cves:
            parts.append(f"CVEs discussed: {', '.join(list(ctx.cves.keys())[-3:])}")
        if ctx.relationships:
            parts.append(f"Entity relationships tracked: {len(ctx.relationships)} entities")
        return "\n".join(parts) if parts else "No prior context."

    def _generate_talking_response(self, query: str, model: Optional[str] = None, provider: Optional[str] = None) -> ConversationTurn:
        trace: list[TraceStep] = []
        start_time = datetime.utcnow().isoformat()

        step_injection = TraceStep(step="injection_check")
        inj_warning = self.injection_guard.check_query(query)
        if inj_warning:
            step_injection.status = "blocked"
            step_injection.result_summary = inj_warning
            step_injection.end_time = datetime.utcnow().isoformat()
            turn = ConversationTurn(
                query=query,
                intent=IntentClassification(intent=IntentType.unknown, entities={}, confidence=0.0),
                confidence=0.0,
                response=f"Query blocked: {inj_warning}",
                trace=[step_injection],
                injection_warning=inj_warning,
            )
            self.context_manager.add_turn(turn)
            return turn
        step_injection.status = "passed"
        step_injection.end_time = datetime.utcnow().isoformat()
        trace.append(step_injection)

        step_talking = TraceStep(step="talking_response")
        history_text = self._format_conversation_history()
        user_prompt = f"{history_text}\n\nUser: {query}\n\nAssistant:" if history_text else f"User: {query}\n\nAssistant:"
        config = {"temperature": 0.7, "max_output_tokens": 8192}

        llm_usage: list[LLMUsage] = []
        try:
            from src.config import GEMINI_MODEL, OPENROUTER_MODEL
            resolved_model = model or (OPENROUTER_MODEL if provider == "openrouter" else GEMINI_MODEL)
            resolved_provider = provider or "gemini"
            llm_resp = llm_generate(resolved_provider, resolved_model, TALKING_SYSTEM_PROMPT, user_prompt, config)
            response = llm_resp.text
            usage = LLMUsage(
                provider=resolved_provider,
                model=resolved_model,
                prompt_tokens=llm_resp.prompt_tokens,
                completion_tokens=llm_resp.completion_tokens,
                total_tokens=llm_resp.total_tokens,
                cost=llm_resp.cost,
            )
            llm_usage.append(usage)
        except Exception as e:
            from src.observability import log_event
            log_event("talking_response_error", {"query": query[:100], "error": str(e)[:200]})
            response = "I'm sorry, I encountered an error generating a response. Please try again."

        step_talking.result_summary = f"response length: {len(response)} chars"
        step_talking.end_time = datetime.utcnow().isoformat()
        trace.append(step_talking)

        step_finalize = TraceStep(step="finalize")
        turn = ConversationTurn(
            query=query,
            intent=IntentClassification(intent=IntentType.unknown, entities={}, confidence=0.0),
            confidence=0.0,
            response=response,
            trace=trace,
            llm_usage=llm_usage,
        )
        self.context_manager.add_turn(turn)
        step_finalize.end_time = datetime.utcnow().isoformat()
        trace.append(step_finalize)

        return turn

    def _format_conversation_history(self) -> str:
        turns = self.context_manager.history
        if not turns:
            return ""
        parts = ["Previous conversation:"]
        for t in turns[-20:]:
            parts.append(f"User: {t.query}")
            if t.response:
                parts.append(f"Assistant: {t.response}")
        return "\n\n".join(parts)

    def get_history(self):
        return self.context_manager.history

    def clear_history(self):
        self.context_manager = ContextManager()
        clear_session_log()
