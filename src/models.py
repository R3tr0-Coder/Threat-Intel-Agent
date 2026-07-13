from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class IntentType(str, Enum):
    ioc_lookup = "ioc_lookup"
    actor_ttp = "actor_ttp"
    exposure_check = "exposure_check"
    pivot = "pivot"
    context_question = "context_question"
    unknown = "unknown"


class IntentClassification(BaseModel):
    intent: IntentType
    entities: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    resolved_reference: Optional[str] = None


class ToolResult(BaseModel):
    source: str
    data: dict[str, Any] = Field(default_factory=dict)
    raw_response: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class TraceStep(BaseModel):
    step: str
    tool: Optional[str] = None
    params: Optional[dict] = None
    start_time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    duration_ms: Optional[int] = None
    status: str = "pending"
    result_summary: Optional[str] = None


class LLMUsage(BaseModel):
    provider: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0


class ConversationTurn(BaseModel):
    query: str
    resolved_query: Optional[str] = None
    intent: IntentClassification
    tool_results: list[ToolResult] = Field(default_factory=list)
    confidence: float = 0.0
    response: Optional[str] = None
    trace: list[TraceStep] = Field(default_factory=list)
    llm_usage: list[LLMUsage] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    injection_warning: Optional[str] = None
    mode: str = "Analysis"
    provider: str = ""
    model: str = ""


class EntityContext(BaseModel):
    ips: dict[str, str] = Field(default_factory=dict)
    domains: dict[str, str] = Field(default_factory=dict)
    hashes: dict[str, str] = Field(default_factory=dict)
    urls: dict[str, str] = Field(default_factory=dict)
    actors: dict[str, str] = Field(default_factory=dict)
    software: dict[str, str] = Field(default_factory=dict)
    cves: dict[str, str] = Field(default_factory=dict)
    last_topic: Optional[str] = None
    relationships: dict[str, list[str]] = Field(default_factory=dict)
