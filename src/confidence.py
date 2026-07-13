from datetime import datetime
from typing import Optional

SOURCE_RELIABILITY = {
    "virustotal": 0.90,
    "abuseipdb": 0.78,
    "otx": 0.75,
    "nvd": 0.95,
}


def _calc_contradiction_penalty(tool_results: list, intent: str) -> float:
    if len(tool_results) < 2 or intent != "ioc_lookup":
        return 0.0
    malicious_scores = []
    for r in tool_results:
        if r.error or not r.data:
            continue
        d = r.data
        if "abuse_confidence_score" in d:
            malicious_scores.append(d["abuse_confidence_score"] / 100.0)
        elif "malicious" in d and "total_engines" in d and d["total_engines"] > 0:
            malicious_scores.append(d["malicious"] / d["total_engines"])
    if len(malicious_scores) < 2:
        return 0.0
    max_score = max(malicious_scores)
    min_score = min(malicious_scores)
    spread = max_score - min_score
    if spread > 0.5:
        return 0.25
    if spread > 0.3:
        return 0.10
    return 0.0


def score_confidence(tool_results: list, intent: str) -> float:
    if not tool_results:
        return 0.0

    has_error = any(r.error for r in tool_results)
    if has_error and len(tool_results) == 1:
        return 0.0

    scores = []
    for r in tool_results:
        if r.error:
            continue
        s = _score_single(r, intent)
        scores.append(s)

    if not scores:
        return 0.0

    base = sum(scores) / len(scores)
    multi_source_bonus = min(0.15, (len(scores) - 1) * 0.05)
    contradiction_penalty = _calc_contradiction_penalty(tool_results, intent)
    raw = base + multi_source_bonus - contradiction_penalty
    return max(0.0, min(1.0, raw))


def _score_single(result, intent: str) -> float:
    reliability = SOURCE_RELIABILITY.get(result.source, 0.7)
    freshness = _score_freshness(result)
    completeness = _score_completeness(result, intent)
    return reliability * 0.4 + freshness * 0.3 + completeness * 0.3


def _score_freshness(result) -> float:
    ts_str = result.data.get("last_analysis_date") or result.data.get("last_update") or result.data.get("last_reported_at") or result.data.get("published") or result.data.get("last_modified")
    if not ts_str:
        return 0.5
    try:
        if isinstance(ts_str, (int, float)):
            ts = datetime.fromtimestamp(ts_str)
        else:
            ts_str_clean = str(ts_str).replace("Z", "+00:00")[:19]
            ts = datetime.fromisoformat(ts_str_clean)
        days_ago = (datetime.utcnow() - ts).days
        if days_ago <= 1:
            return 1.0
        if days_ago <= 7:
            return 0.85
        if days_ago <= 30:
            return 0.65
        if days_ago <= 90:
            return 0.45
        return 0.3
    except (ValueError, TypeError):
        return 0.5


def _score_completeness(result, intent: str) -> float:
    d = result.data
    if not d:
        return 0.0

    if intent == "ioc_lookup":
        checks = ["malicious" in d or "abuse_confidence_score" in d, "total_engines" in d or "total_reports" in d]
    elif intent == "actor_ttp":
        checks = ["pulses" in d or "count" in d]
    elif intent == "exposure_check":
        checks = ["cves" in d, "total_results" in d]
    elif intent == "pivot":
        checks = ["resolutions" in d or "domains" in d or "hostnames" in d]
    else:
        checks = [bool(d)]

    if not checks:
        return 0.5
    return sum(1 for c in checks if c) / len(checks)
