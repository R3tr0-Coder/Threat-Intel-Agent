import os
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")
OPENROUTER_MODELS = [
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "poolside/laguna-m.1:free",
]

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

RATE_LIMITS = {
    "virustotal": {"requests_per_day": 500, "requests_per_minute": 4},
    "abuseipdb": {"requests_per_day": 1000, "requests_per_minute": 60},
    "otx": {"requests_per_day": 500, "requests_per_minute": 10},
    "nvd": {"requests_per_minute": 5},
}

# Cost per 1,000 tokens (input / output) in USD — update as pricing changes
MODEL_PRICING: dict[str, dict[str, float]] = {
    "gemini-2.5-flash":      {"input_per_1k": 0.00015,  "output_per_1k": 0.00060},
    "gemini-2.0-flash":      {"input_per_1k": 0.00010,  "output_per_1k": 0.00040},
    "gemini-2.0-flash-lite": {"input_per_1k": 0.000075, "output_per_1k": 0.00030},
    "gemini-3.0-flash":      {"input_per_1k": 0.00015,  "output_per_1k": 0.00060},
}

CONVERSATIONS_DB = os.getenv("CONVERSATIONS_DB", "conversations.db")
MAX_QUERY_LENGTH = 2000
LOG_FILE = "threat_agent.log"

ALL_API_KEYS = {
    "GEMINI_API_KEY": GEMINI_API_KEY,
    "OPENROUTER_API_KEY": OPENROUTER_API_KEY,
    "VIRUSTOTAL_API_KEY": VIRUSTOTAL_API_KEY,
    "ABUSEIPDB_API_KEY": ABUSEIPDB_API_KEY,
    "OTX_API_KEY": OTX_API_KEY,
    "NVD_API_KEY": NVD_API_KEY,
}


def validate_config() -> list[str]:
    warnings = []
    if not GEMINI_API_KEY and not OPENROUTER_API_KEY:
        warnings.append("No LLM API key configured — rule-based fallback only")
    for name, key in ALL_API_KEYS.items():
        if not key:
            tool_name = name.replace("_API_KEY", "").lower()
            if tool_name not in ("gemini", "openrouter"):
                warnings.append(f"{name} not set — {tool_name} tool disabled")
    if LLM_PROVIDER not in ("gemini", "openrouter"):
        warnings.append(f"Unknown LLM_PROVIDER '{LLM_PROVIDER}' — expected 'gemini' or 'openrouter'")
    return warnings
