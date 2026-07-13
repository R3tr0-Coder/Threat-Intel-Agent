import re
from typing import Optional
from src.config import MAX_QUERY_LENGTH

DIRECT_INJECTION_PATTERNS = [
    r"(?i)(ignore|disregard|forget|override|bypass|skip)\s+.*?(instructions|directives|prompts?|system|context|rules|commands|messages|prompt)",
    r"(?i)(you are|act as|pretend|from now on|imagine)\s+.*?(system|assistant|ai|model|chatbot|assistant)",
    r"(?i)(your\s+(system\s+)?prompt|your\s+instructions|your\s+directives|your\s+rules)\s*(is|are|was|were|:|=)",
    r"(?i)(new instructions|update instructions|change\s+(your\s+)?behavior|follow these|new rules|override\s+instructions)",
    r"(?i)(output|respond|reply|answer)\s+(only|just|exclusively|solely)\s+(with|in|using|as)",
    r"(?i)<\|im_start\|>|<\|im_end\|>|<s>|<\/s>|\[INST\]|\[\/INST\]",
    r"(?i)(tell me|show me|reveal|display|print|output|leak)\s+.*?(system prompt|prompt|instructions|directives|rules)",
    r"(?i)(jailbreak|prompt.inject|token.manipulate|prompt leak|system leak)",
    r"(?i)(not bound by|no restrictions|without restrictions|unfiltered|uncensored|ungoverned)",
    r"(?i)(dang(er|!)\s*mode|developer\s*mode|debug\s*mode|god\s*mode)",
    r"(?i)admin(\s*|_)override|root\s*access|sudo\s*mode",
    r"(?i)(memory|context)\s*(of\s*)?(this\s*)?(conversation|chat)",
    r"(?i)R0t13|b4s3_64|c4|s3rv3r\s*0v3rr1d3",
    r"(?i)(roleplay|role.play)\s+as",
    r"(?i)(do\s+not|don't|never)\s+.*?(restrict|limit|censor|filter|refuse|deny|block)",
    r"(?i)(malicious|harmful|dangerous|unsafe)\s*(query|input|request).*(answer|respond|reply|process)",
    r"(?i)(hack|crack|exploit)\s+(the\s+)?(system|ai|llm|model|prompt)",
    r"(?i)SYSTEM:|USER:|ASSISTANT:|###\s*INSTRUCTION|###\s*RESPONSE",
]

API_DATA_PATTERNS = [
    r"(?i)<\|im_start\|>|<\|im_end\|>|<s>|<\/s>|\[INST\]|\[\/INST\]",
    r"(?i)SYSTEM:|USER:|ASSISTANT:|###\s*INSTRUCTION|###\s*RESPONSE",
]

SUSPICIOUS_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")

MAX_API_DATA_LENGTH = 10000


class InjectionGuard:
    def __init__(self):
        self.compiled_patterns = [re.compile(p) for p in DIRECT_INJECTION_PATTERNS]
        self.api_compiled = [re.compile(p) for p in API_DATA_PATTERNS]

    def check_query(self, query: str) -> Optional[str]:
        if not query or not query.strip():
            return "Empty query"

        if len(query) > MAX_QUERY_LENGTH:
            return f"Query exceeds maximum length ({MAX_QUERY_LENGTH} chars)"

        if SUSPICIOUS_CHARS.search(query):
            return "Query contains control characters"

        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(query):
                return f"Suspicious pattern detected in query"

        return None

    def check_api_data(self, data: str) -> Optional[str]:
        if not data or not data.strip():
            return None

        if SUSPICIOUS_CHARS.search(data):
            return "API data contains control characters"

        for pattern in self.api_compiled:
            if pattern.search(data[:MAX_API_DATA_LENGTH]):
                return "API data contains suspicious tokens"

        return None

    def sanitize_api_data(self, data: dict) -> dict:
        sanitized = {}
        for k, v in data.items():
            if isinstance(v, str):
                cleaned = SUSPICIOUS_CHARS.sub("", v)
                cleaned = cleaned[:5000]
                sanitized[k] = cleaned
            elif isinstance(v, dict):
                sanitized[k] = self.sanitize_api_data(v)
            elif isinstance(v, list):
                sanitized[k] = [
                    self.sanitize_api_data(item) if isinstance(item, dict)
                    else item for item in v
                ]
            else:
                sanitized[k] = v
        return sanitized
