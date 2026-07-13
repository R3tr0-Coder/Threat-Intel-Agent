from dataclasses import dataclass
from typing import Optional
import requests

from src.config import GEMINI_API_KEY, OPENROUTER_API_KEY, MODEL_PRICING

OPENROUTER_BASE = "https://openrouter.ai/api/v1"


@dataclass
class LLMResponse:
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0


def generate(
    provider: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    config: Optional[dict] = None,
) -> LLMResponse:
    if provider == "openrouter":
        return _generate_openrouter(model, system_prompt, user_prompt, config or {})
    return _generate_gemini(model, system_prompt, user_prompt, config or {})


def _estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        return 0.0
    input_cost = (prompt_tokens / 1000) * pricing["input_per_1k"]
    output_cost = (completion_tokens / 1000) * pricing["output_per_1k"]
    return round(input_cost + output_cost, 6)


def _generate_gemini(model: str, system_prompt: str, user_prompt: str, config: dict) -> LLMResponse:
    from google import genai
    client = genai.Client(api_key=GEMINI_API_KEY)
    contents = f"{system_prompt}\n\n{user_prompt}" if system_prompt else user_prompt
    response = client.models.generate_content(
        model=model,
        contents=contents,
        config=config,
    )
    usage = response.usage_metadata
    pt = usage.prompt_token_count if usage else 0
    ct = usage.candidates_token_count if usage else 0
    tt = usage.total_token_count if usage else 0
    cost = _estimate_cost(model, pt, ct)
    text = response.text.strip() if response.text else ""
    return LLMResponse(
        text=text,
        prompt_tokens=pt,
        completion_tokens=ct,
        total_tokens=tt,
        cost=cost,
    )


def _generate_openrouter(model: str, system_prompt: str, user_prompt: str, config: dict) -> LLMResponse:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/your-org/threat-intel-agent",
    }
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    openrouter_config = {}
    if "temperature" in config:
        openrouter_config["temperature"] = config["temperature"]
    if "max_output_tokens" in config:
        openrouter_config["max_tokens"] = config["max_output_tokens"]

    payload = {
        "model": model,
        "messages": messages,
        **openrouter_config,
    }

    resp = requests.post(f"{OPENROUTER_BASE}/chat/completions", headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    text = data["choices"][0]["message"]["content"].strip()
    usage = data.get("usage", {})
    pt = usage.get("prompt_tokens", 0)
    ct = usage.get("completion_tokens", 0)
    tt = usage.get("total_tokens", 0)
    cost_str = resp.headers.get("x-request-cost", "0")
    cost = round(float(cost_str), 6) if cost_str else _estimate_cost(model, pt, ct)
    return LLMResponse(
        text=text,
        prompt_tokens=pt,
        completion_tokens=ct,
        total_tokens=tt,
        cost=cost,
    )
