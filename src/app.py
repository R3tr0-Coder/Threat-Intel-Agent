import sys
import os
from pathlib import Path
from dotenv import set_key

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import streamlit as st
from src.orchestrator import ThreatIntelAgent
from src.context_manager import ContextManager
from src.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MODELS, OPENROUTER_API_KEY, OPENROUTER_MODEL, OPENROUTER_MODELS, LLM_PROVIDER, CONVERSATIONS_DB
from src.conversation_store import ConversationStore
from src.rate_limiter import get_rate_limiter
from src.config import RATE_LIMITS, ALL_API_KEYS

st.set_page_config(
    page_title="Threat Intelligence Analyst",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
/* Bottom padding so messages aren't hidden behind fixed form bar */
.main .block-container {
    padding-bottom: 110px !important;
}

/* Fixed bottom bar - centered container */
.chat-bottom-bar {
    position: fixed !important;
    bottom: 0 !important;
    left: 50% !important;
    transform: translateX(-50%) !important;
    width: 100% !important;
    max-width: 720px !important;
    z-index: 99999 !important;
    padding: 0 12px 12px 12px !important;
}

/* Form - rounded input box */
.main div[data-testid="stForm"] {
    border: 1px solid #444 !important;
    border-radius: 16px !important;
    background: #2a2a2a !important;
    padding: 10px 14px !important;
    margin: 0 !important;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3) !important;
}

.main div[data-testid="stForm"]:focus-within {
    border-color: #666 !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4) !important;
}

/* Horizontal block inside form */
.main div[data-testid="stForm"] [data-testid="stHorizontalBlock"] {
    gap: 8px !important;
    align-items: center !important;
}

/* Text input - transparent, blends into form */
.main div[data-testid="stForm"] .stTextInput input {
    background: transparent !important;
    border: none !important;
    border-radius: 0 !important;
    color: #e8eaed !important;
    font-size: 16px !important;
    padding: 6px 0 !important;
    height: auto !important;
    box-shadow: none !important;
}

.main div[data-testid="stForm"] .stTextInput input:focus {
    box-shadow: none !important;
    border: none !important;
}

.main div[data-testid="stForm"] .stTextInput input::placeholder {
    color: #888 !important;
}

/* Send button - circular */
.main div[data-testid="stForm"] .stFormSubmitButton {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
}

.main div[data-testid="stForm"] .stFormSubmitButton button {
    background: #555 !important;
    color: #e8eaed !important;
    border: none !important;
    border-radius: 50% !important;
    width: 32px !important;
    height: 32px !important;
    min-width: 0 !important;
    min-height: 0 !important;
    padding: 0 !important;
    font-size: 16px !important;
    line-height: 1 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    transition: background 0.15s ease !important;
}

.main div[data-testid="stForm"] .stFormSubmitButton button:hover {
    background: #777 !important;
}

/* Selectors row below input box */
.chat-selectors {
    display: flex !important;
    gap: 8px !important;
    justify-content: flex-start !important;
    padding: 8px 4px 0 4px !important;
    align-items: center !important;
}

.chat-selectors .stSelectbox {
    flex: 0 0 auto !important;
}

/* Model/selector pill styling */
.stSelectbox > label {
    display: none !important;
}

.stSelectbox [data-baseweb="select"] {
    background: #2d2d2d !important;
    border-radius: 14px !important;
    border: 1px solid #3c4043 !important;
    height: 30px !important;
    min-width: 0 !important;
    transition: all 0.2s ease !important;
}

.stSelectbox [data-baseweb="select"]:hover {
    border-color: #555 !important;
    background: #333 !important;
}

.stSelectbox [data-baseweb="select"] > div {
    padding: 0 10px !important;
}

.stSelectbox [data-baseweb="select"] span {
    color: #c4c7cc !important;
    font-size: 12px !important;
    font-weight: 500 !important;
}

.stSelectbox [data-baseweb="popover"] {
    z-index: 99999 !important;
}

.stSelectbox [data-baseweb="menu"] {
    background: #202124 !important;
    border: 1px solid #3c4043 !important;
    border-radius: 10px !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4) !important;
    margin-top: 6px !important;
    overflow: hidden !important;
}

.stSelectbox [data-baseweb="menu"] li {
    padding: 8px 14px !important;
    color: #e8eaed !important;
    font-size: 13px !important;
    transition: background 0.15s !important;
}

.stSelectbox [data-baseweb="menu"] li:hover {
    background: #2d2d2d !important;
}

.stSelectbox [data-baseweb="menu"] li[aria-selected="true"] {
    background: #2d2d2d !important;
    color: #8ab4f8 !important;
}

.stSelectbox [data-baseweb="select"] svg {
    color: #888 !important;
    width: 14px !important;
    height: 14px !important;
}

/* Empty state */
.empty-state {
    text-align: center;
    padding: 3rem 0 1rem 0;
}

.empty-state h3 {
    font-weight: 500;
    color: #e8eaed;
    margin-bottom: 0.5rem;
}

.empty-state p {
    font-size: 1.1rem;
    color: #888;
    margin-bottom: 2rem;
}

/* Example buttons */
.stButton > button {
    background: #2d2d2d !important;
    border: 1px solid #444 !important;
    border-radius: 16px !important;
    color: #e8eaed !important;
    padding: 16px !important;
    text-align: left !important;
    transition: all 0.2s ease !important;
    height: auto !important;
    white-space: pre-line !important;
    line-height: 1.5 !important;
}

.stButton > button:hover {
    background: #333 !important;
    border-color: #666 !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
}

.stButton > button:focus {
    box-shadow: 0 0 0 2px #8ab4f8 !important;
    border-color: #8ab4f8 !important;
}

/* Sidebar buttons - compact defaults */
section[data-testid="stSidebar"] .stButton > button {
    background: transparent !important;
    border: none !important;
    border-radius: 8px !important;
    color: #e8eaed !important;
    padding: 4px 10px !important;
    text-align: center !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    height: auto !important;
    line-height: inherit !important;
    min-height: 30px !important;
    font-size: 13px !important;
}

section[data-testid="stSidebar"] .stButton > button:hover {
    background: #2d2d2d !important;
    box-shadow: none !important;
}

section[data-testid="stSidebar"] .stButton > button:focus {
    box-shadow: none !important;
    border-color: #3c4043 !important;
}

/* Text inputs in sidebar */
section[data-testid="stSidebar"] .stTextInput input {
    background: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 6px !important;
    color: #e8eaed !important;
    font-size: 13px !important;
    padding: 4px 8px !important;
    min-height: 30px !important;
}

section[data-testid="stSidebar"] .stTextInput input:focus {
    border-color: #8ab4f8 !important;
    box-shadow: 0 0 0 2px rgba(138, 180, 248, 0.2) !important;
}

/* Primary button in sidebar */
section[data-testid="stSidebar"] button[kind="primary"] {
    background: #8ab4f8 !important;
    color: #000 !important;
    border: none !important;
    padding: 6px 16px !important;
    font-weight: 600 !important;
}

section[data-testid="stSidebar"] button[kind="primary"]:hover {
    background: #9cc5ff !important;
}

/* Three-dot popover trigger */
div[data-testid="stPopover"] button[data-testid="stPopoverButton"] {
    background: transparent !important;
    border: none !important;
    color: #888 !important;
    padding: 0 4px !important;
    min-height: 24px !important;
    height: auto !important;
    line-height: 1 !important;
    border-radius: 6px !important;
    min-width: 0 !important;
    gap: 0 !important;
    font-size: 18px !important;
    font-weight: bold !important;
    letter-spacing: 2px !important;
}
div[data-testid="stPopover"] button[data-testid="stPopoverButton"]:hover {
    color: #e8eaed !important;
    background: rgba(255,255,255,0.08) !important;
}
/* Hide the default label text and chevron SVG */
div[data-testid="stPopover"] button[data-testid="stPopoverButton"] > div {
    display: none !important;
}
div[data-testid="stPopover"] button[data-testid="stPopoverButton"] svg {
    display: none !important;
}
/* Show "..." via pseudo-element */
div[data-testid="stPopover"] button[data-testid="stPopoverButton"]::after {
    content: "..." !important;
}

/* Popover body (portalled to document.body) */
div[data-testid="stPopoverBody"] {
    background: #202124 !important;
    border: 1px solid #3c4043 !important;
    border-radius: 12px !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4) !important;
    padding: 4px !important;
    min-width: 130px !important;
}

/* Active conversation row */
.conv-row-active {
    background: rgba(138, 180, 248, 0.06) !important;
    border-radius: 8px !important;
    padding: 4px 10px !important;
    min-height: 30px !important;
    line-height: 1.4 !important;
    text-align: center !important;
}
.conv-row-active p {
    margin: 0 !important;
    padding: 0 !important;
    color: #e8eaed !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    line-height: 1.4 !important;
    text-align: center !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    white-space: nowrap !important;
}

/* Buttons inside popover body */
div[data-testid="stPopoverBody"] button {
    background: transparent !important;
    border: none !important;
    color: #e8eaed !important;
    text-align: left !important;
    padding: 8px 12px !important;
    font-size: 13px !important;
    border-radius: 6px !important;
    width: 100% !important;
    min-height: 0 !important;
    height: auto !important;
}
div[data-testid="stPopoverBody"] button:hover {
    background: #2d2d2d !important;
    border: none !important;
    box-shadow: none !important;
}

/* Source badges */
.sources-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 10px 0 6px 0;
    padding-top: 8px;
    border-top: 1px solid #2a2a2a;
}
.source-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 12px;
    line-height: 1.5;
    border: 1px solid #444;
}
.source-badge.source-ok {
    color: #4ade80;
    border-color: #1a4731;
    background: rgba(74, 222, 128, 0.06);
}
.source-badge.source-err {
    color: #f87171;
    border-color: #4a1a1a;
    background: rgba(248, 113, 113, 0.06);
}

/* Mobile responsive */
@media (max-width: 768px) {
    .chat-bottom-bar {
        max-width: 100% !important;
        padding: 0 8px 8px 8px !important;
    }
    .main div[data-testid="stForm"] {
        border-radius: 12px !important;
    }
    .main div[data-testid="stForm"] .stTextInput input {
        font-size: 14px !important;
    }
    .main div[data-testid="stForm"] .stFormSubmitButton button {
        width: 28px !important;
        height: 28px !important;
    }
    .stSelectbox [data-baseweb="select"] {
        min-width: 80px !important;
        height: 28px !important;
    }
}

/* Message action buttons - compact icons in chat */
div[data-testid="stChatMessage"] div[data-testid="stButton"] {
    min-width: unset !important;
    width: auto !important;
    display: inline-block !important;
}
div[data-testid="stChatMessage"] div[data-testid="stButton"] button {
    background: transparent !important;
    border: 1px solid transparent !important;
    color: #666 !important;
    font-size: 16px !important;
    padding: 4px 8px !important;
    min-width: unset !important;
    width: auto !important;
    height: 32px !important;
    line-height: 1.2 !important;
    border-radius: 6px !important;
    margin: 0 !important;
    transition: all 0.15s ease !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
}
div[data-testid="stChatMessage"] div[data-testid="stButton"] button:hover {
    background: rgba(255,255,255,0.08) !important;
    border-color: rgba(255,255,255,0.1) !important;
    color: #aaa !important;
}
div[data-testid="stChatMessage"] div[data-testid="stHorizontalBlock"] div[data-testid="stVerticalBlock"] div[data-testid="stHorizontalBlock"] {
    gap: 0 !important;
}
div[data-testid="stChatMessage"] .stColumns {
    gap: 4px !important;
}
/* Disable all clickable links throughout the app */
a {
    pointer-events: none !important;
    color: inherit !important;
    text-decoration: none !important;
}
a::after {
    content: none !important;
}
</style>
""", unsafe_allow_html=True)

MODEL_OPTIONS = (
    [("gemini", m) for m in GEMINI_MODELS] +
    [("openrouter", m) for m in OPENROUTER_MODELS]
)

# Short display names for model selector (like "Flash", "Pro" in Gemini UI)
MODEL_DISPLAY = {
    "gemini-2.5-flash": "Flash",
    "gemini-2.5-pro": "Pro",
    "gemini-2.0-flash": "Flash 2.0",
    "openai/gpt-oss-120b:free": "GPT-OSS 120B",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free": "Nemotron 3 Nano",
    "poolside/laguna-m.1:free": "Laguna M.1",
}

# Selectbox options: map short display name -> (provider, model)
MODEL_SELECT_OPTIONS = {
    f"{p} \u2014 {MODEL_DISPLAY.get(m, m)}": (p, m)
    for p, m in MODEL_OPTIONS
}

MODEL_LABELS = {f"{p} \u2014 {m}": (p, m) for p, m in MODEL_OPTIONS}

TOOL_DISPLAY_NAMES = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "otx": "AlienVault OTX",
    "nvd": "NVD",
    "validation": "Validation",
}


def _tool_summary(tr: dict) -> str:
    if tr.get("error"):
        return tr["error"]
    data = tr.get("data", {})
    if not data:
        return "No data returned"
    if "malicious" in data or "total_engines" in data:
        m = data.get("malicious", 0)
        s = data.get("suspicious", 0)
        t = data.get("total_engines", 0)
        result = f"{m}/{t} malicious"
        if s:
            result += f", {s} suspicious"
        return result
    if "abuse_confidence_score" in data:
        return f"{data['abuse_confidence_score']}% abuse confidence"
    if "pulse_count" in data:
        return f"{data['pulse_count']} threat pulses"
    if "total_results" in data:
        return f"{data['total_results']} vulnerabilities"
    if "ports" in data:
        ports = data.get("ports", [])
        return f"{len(ports)} open ports" if ports else "No open ports"
    if "ip" in data and "org" in data:
        return f"ISP: {data.get('org', data.get('isp', 'Unknown'))}"
    return "Data available"


EXAMPLE_PROMPTS = [
    ("Is 45.83.122.10 malicious?", "Check an IP reputation across multiple threat feeds"),
    ("What TTPs is APT29 known for?", "Profile a threat actor's techniques and tools"),
    ("We run Confluence 7.13 \u2014 are we exposed?", "Map a software version to known vulnerabilities"),
    ("Pivot from that IP to find related domains", "Discover relationships between entities"),
]


def _get_model_label(provider: str, model: str) -> str:
    short = MODEL_DISPLAY.get(model, model)
    return f"{provider} \u2014 {short}"


def _get_default_model_label() -> str:
    prov = st.session_state.llm_provider
    model = st.session_state.gemini_model if prov == "gemini" else st.session_state.openrouter_model
    return _get_model_label(prov, model)





if "agent" not in st.session_state:
    st.session_state.agent = ThreatIntelAgent()
if "messages" not in st.session_state:
    st.session_state.messages = []
if "llm_provider" not in st.session_state:
    st.session_state.llm_provider = LLM_PROVIDER
if "gemini_model" not in st.session_state:
    st.session_state.gemini_model = GEMINI_MODEL
if "openrouter_model" not in st.session_state:
    st.session_state.openrouter_model = OPENROUTER_MODEL
if "store" not in st.session_state:
    st.session_state.store = ConversationStore(CONVERSATIONS_DB)
if "renaming_conv_id" not in st.session_state:
    st.session_state.renaming_conv_id = None
if "confirm_delete_conv_id" not in st.session_state:
    st.session_state.confirm_delete_conv_id = None
if "_confirm_delete_msg_idx" not in st.session_state:
    st.session_state._confirm_delete_msg_idx = None
if "agent_mode_toolbar" not in st.session_state:
    st.session_state.agent_mode_toolbar = "Analysis"

def _sync_model_selection():
    label = st.session_state.get("selected_model_toolbar")
    if label is None:
        return
    p, m = MODEL_SELECT_OPTIONS[label]
    st.session_state.llm_provider = p
    if p == "gemini":
        st.session_state.gemini_model = m
    else:
        st.session_state.openrouter_model = m
    env_path = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / ".env"
    set_key(str(env_path), "LLM_PROVIDER", p)
    if p == "gemini":
        set_key(str(env_path), "GEMINI_MODEL", m)
    else:
        set_key(str(env_path), "OPENROUTER_MODEL", m)


def _sync_mode():
    st.session_state.current_mode = st.session_state.agent_mode_toolbar


if "current_mode" not in st.session_state:
    st.session_state.current_mode = "Analysis"

store: ConversationStore = st.session_state.store
agent: ThreatIntelAgent = st.session_state.agent

# Restore persistent metrics and rate limiter state from DB
if "llm_totals" not in st.session_state:
    saved = store.get_metrics()
    st.session_state.llm_totals = saved["llm_usage"] or {
        "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        "cost": 0.0, "calls": 0, "models": [],
    }
    st.session_state.call_count = saved["call_count"] or {}
    from src.conversation_store import migrate_metrics_table
    migrate_metrics_table(CONVERSATIONS_DB)
    try:
        rl_state = store.get_rate_limiter_state()
        if rl_state:
            get_rate_limiter().restore_state(rl_state)
    except (AttributeError, Exception):
        pass


def _defang_text(text: str) -> str:
    return text.replace("http://", "hxxp://").replace("https://", "hxxps://")


def _load_conversation(conv_id: str):
    messages = store.get_messages(conv_id)
    st.session_state.messages = []
    for m in messages:
        entry = {
            "role": m["role"], "content": _defang_text(m["content"]),
            "confidence": _extract_confidence(m),
            "trace": _extract_trace(m),
            "llm_usage": _extract_llm_usage(m),
            "mode": _extract_mode(m),
            "provider": _extract_provider(m),
            "model": _extract_model(m),
            "tool_results": _extract_tool_results(m),
        }
        if m.get("turn_data"):
            try:
                entry["turn_data"] = json.loads(m["turn_data"])
            except (json.JSONDecodeError, TypeError):
                pass
        st.session_state.messages.append(entry)
    turns = store.restore_turns(conv_id)
    agent.context_manager.history = turns


def _extract_confidence(msg: dict) -> float:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("confidence", 0.0)
        except (json.JSONDecodeError, TypeError):
            pass
    return 0.0


def _extract_trace(msg: dict) -> list:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("trace", [])
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def _extract_llm_usage(msg: dict) -> list:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("llm_usage", [])
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def _extract_mode(msg: dict) -> str:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("mode", "Analysis")
        except (json.JSONDecodeError, TypeError):
            pass
    return "Analysis"


def _extract_provider(msg: dict) -> str:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("provider", "")
        except (json.JSONDecodeError, TypeError):
            pass
    return ""


def _extract_model(msg: dict) -> str:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("model", "")
        except (json.JSONDecodeError, TypeError):
            pass
    return ""


def _extract_tool_results(msg: dict) -> list:
    if msg.get("turn_data"):
        try:
            import json
            data = json.loads(msg["turn_data"])
            return data.get("tool_results", [])
        except (json.JSONDecodeError, TypeError):
            pass
    return []


def _recompute_llm_totals():
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0, "calls": 0, "models": []}
    for msg in st.session_state.messages:
        for u in msg.get("llm_usage", []):
            totals["prompt_tokens"] += u.get("prompt_tokens", 0)
            totals["completion_tokens"] += u.get("completion_tokens", 0)
            totals["total_tokens"] += u.get("total_tokens", 0)
            totals["cost"] += u.get("cost", 0.0)
            totals["calls"] += 1
            model = u.get("model", "")
            if model and model not in totals["models"]:
                totals["models"].append(model)
    st.session_state.llm_totals = totals


convs = store.list_conversations()
if "current_conversation_id" not in st.session_state or not any(c["id"] == st.session_state.current_conversation_id for c in convs):
    if convs:
        st.session_state.current_conversation_id = convs[0]["id"]
        _load_conversation(st.session_state.current_conversation_id)
    else:
        conv_id = store.create_conversation()
        st.session_state.current_conversation_id = conv_id


def _switch_conversation(conv_id: str):
    st.session_state.current_conversation_id = conv_id
    st.session_state.confirm_delete_conv_id = None
    _load_conversation(conv_id)
    st.rerun()


def _new_conversation():
    conv_id = store.create_conversation()
    st.session_state.current_conversation_id = conv_id
    st.session_state.confirm_delete_conv_id = None
    st.session_state.renaming_conv_id = None
    st.session_state.messages = []
    agent.clear_history()


_pending_new = st.session_state.pop("_pending_new_chat", None)
if _pending_new:
    _new_conversation()


def _delete_conversation(conv_id: str):
    store.delete_conversation(conv_id)
    if st.session_state.current_conversation_id == conv_id:
        convs_remaining = store.list_conversations()
        if convs_remaining:
            st.session_state.current_conversation_id = convs_remaining[0]["id"]
            _load_conversation(convs_remaining[0]["id"])
        else:
            new_id = store.create_conversation()
            st.session_state.current_conversation_id = new_id
            st.session_state.messages = []
            agent.clear_history()
    st.rerun()


def _rename_conversation(conv_id: str):
    key = f"rn_{conv_id}"
    new_title = st.session_state.get(key, "").strip()
    if new_title:
        store.update_title(conv_id, new_title)
    st.session_state.renaming_conv_id = None


def _submit_query(prompt: str):
    st.session_state.messages.append({"role": "user", "content": _defang_text(prompt)})
    model_key = "gemini_model" if st.session_state.llm_provider == "gemini" else "openrouter_model"
    mode = st.session_state.get("current_mode", "Analysis")
    turn = agent.process_query(prompt, model=st.session_state[model_key], provider=st.session_state.llm_provider, mode=mode)
    turn.mode = mode
    turn.provider = st.session_state.llm_provider
    turn.model = st.session_state[model_key]
    llm_usage = [u.model_dump() for u in turn.llm_usage]
    st.session_state.messages.append({
        "role": "assistant",
        "content": _defang_text(turn.response),
        "confidence": turn.confidence,
        "trace": [t.model_dump() for t in turn.trace],
        "llm_usage": llm_usage,
        "mode": mode,
        "provider": st.session_state.llm_provider,
        "model": st.session_state[model_key],
        "tool_results": [t.model_dump() for t in turn.tool_results],
        "turn_data": turn.model_dump(),
    })
    if "call_count" not in st.session_state:
        st.session_state.call_count = {}
    st.session_state.call_count["_total"] = st.session_state.call_count.get("_total", 0) + len(turn.tool_results)
    for r in turn.tool_results:
        src = r.source
        st.session_state.call_count[src] = st.session_state.call_count.get(src, 0) + 1
    # Accumulate LLM usage incrementally (persists across page refreshes)
    totals = st.session_state.llm_totals
    for u in turn.llm_usage:
        totals["prompt_tokens"] += u.prompt_tokens
        totals["completion_tokens"] += u.completion_tokens
        totals["total_tokens"] += u.total_tokens
        totals["cost"] += u.cost
        totals["calls"] += 1
        if u.model and u.model not in totals["models"]:
            totals["models"].append(u.model)
    store.save_metrics(st.session_state.llm_totals, st.session_state.call_count, get_rate_limiter().get_persistable_state())
    conv_id = st.session_state.current_conversation_id
    store.save_turn(conv_id, prompt, turn)
    store.auto_title(conv_id, prompt)


def _rebuild_after_truncate(idx):
    st.session_state.messages = st.session_state.messages[:idx]
    conv_id = st.session_state.current_conversation_id
    store.sync_messages(conv_id, st.session_state.messages)
    agent.context_manager = ContextManager()
    turns = store.restore_turns(conv_id)
    for turn in turns:
        agent.context_manager.add_turn(turn)


_pending_delete = st.session_state.pop("_pending_delete_idx", None)
if _pending_delete is not None:
    _rebuild_after_truncate(_pending_delete)

_pending_retry = st.session_state.pop("_pending_retry_idx", None)
if _pending_retry is not None:
    idx, text = _pending_retry
    _rebuild_after_truncate(idx)
    _submit_query(text)

_pending_edit = st.session_state.pop("_pending_edit_idx", None)
if _pending_edit is not None:
    idx, text = _pending_edit
    _rebuild_after_truncate(idx)
    _submit_query(text)

_pending = st.session_state.pop("_pending_query", None)
if _pending:
    _submit_query(_pending)

if not GEMINI_API_KEY and not OPENROUTER_API_KEY:
    st.warning("No LLM API key set (Gemini or OpenRouter). Falling back to rule-based intent parsing.")

with st.sidebar:
    st.markdown("### Threat Intelligence Analyst")

    if st.button("+ New Chat", use_container_width=True, type="primary"):
        st.session_state._pending_new_chat = True
        st.rerun()

    search_query = st.text_input("Search chats", placeholder="Search chats...", label_visibility="collapsed", key="search_chats")

    st.divider()

    def _render_conv_row(c: dict, prefix: str):
        editing = st.session_state.renaming_conv_id == c["id"]
        confirming = st.session_state.confirm_delete_conv_id == c["id"]
        is_active = c["id"] == st.session_state.current_conversation_id

        if confirming:
            cols = st.columns([0.55, 0.25, 0.2])
            with cols[0]:
                st.markdown(f"**{c['title']}**")
            with cols[1]:
                if st.button("Yes", key=f"confirm_yes_{prefix}_{c['id']}"):
                    st.session_state.confirm_delete_conv_id = None
                    _delete_conversation(c["id"])
            with cols[2]:
                if st.button("No", key=f"confirm_no_{prefix}_{c['id']}"):
                    st.session_state.confirm_delete_conv_id = None
                    st.rerun()
        else:
            cols = st.columns([0.75, 0.25])
            with cols[0]:
                if editing:
                    st.text_input("Rename conversation", value=c["title"], key=f"rn_{c['id']}", label_visibility="collapsed", on_change=_rename_conversation, args=(c["id"],))
                elif is_active:
                    st.markdown(f'<div class="conv-row-active"><p>{c["title"]}</p></div>', unsafe_allow_html=True)
                else:
                    if st.button(c["title"], key=f"{prefix}_{c['id']}", use_container_width=True):
                        _switch_conversation(c["id"])
            with cols[1]:
                with st.popover("..."):
                    if st.button("Rename", key=f"re_{prefix}_{c['id']}", use_container_width=True):
                        st.session_state.renaming_conv_id = c["id"]
                        st.rerun()
                    if st.button("Delete", key=f"del_{prefix}_{c['id']}", use_container_width=True):
                        st.session_state.confirm_delete_conv_id = c["id"]
                        st.rerun()

    if search_query:
        filtered = store.search_conversations(search_query)
        if filtered:
            st.markdown(f"**Results** ({len(filtered)})")
            for c in filtered:
                _render_conv_row(c, "sr")
        else:
            st.caption("No conversations match your search.")
    else:
        with st.expander("**Recent**", icon="\U0001F4C4", expanded=True):
            recents = convs[:5]
            if recents:
                for c in recents:
                    _render_conv_row(c, "rc")
            else:
                st.caption("No conversations yet.")

        remaining = convs[5:]
        if remaining:
            with st.expander(f"**Older** ({len(remaining)})", icon="\U0001F4DA", expanded=False):
                for c in remaining:
                    _render_conv_row(c, "li")

    st.divider()

    with st.expander("\u2699\ufe0f Cost & Rate Limits"):
        rate_limiter = get_rate_limiter()
        tool_key_map = {
            "virustotal": "VIRUSTOTAL_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "otx": "OTX_API_KEY",
            "nvd": "NVD_API_KEY",
        }
        for tool, limits in RATE_LIMITS.items():
            bucket = rate_limiter.get_bucket(tool)
            status = bucket.get_status()
            tokens_remaining = status["tokens_remaining"]
            tokens_used = max(0, status["max_tokens"] - tokens_remaining)
            rate_min = status["rate_per_minute"]
            day_limit = limits.get("requests_per_day")
            day_used = status["day_count"]
            key_name = tool_key_map.get(tool, "")
            key_set = "\u2705" if ALL_API_KEYS.get(key_name) else "\u274c"

            st.markdown(f"**{tool}** {key_set}")
            usage_ratio = min(tokens_used / max(status["max_tokens"], 1), 1.0)
            st.progress(usage_ratio)

            sec_full = status.get("seconds_until_full", 0)
            m, s = divmod(int(sec_full), 60)
            h, m = divmod(m, 60)
            full_str = ""
            if h:
                full_str = f"{h}h {m}m"
            elif m:
                full_str = f"{m}m {s}s"
            else:
                full_str = f"{s}s"

            day_str = ""
            if day_limit:
                daily_reset_iso = status.get("daily_reset_at")
                if daily_reset_iso:
                    try:
                        from datetime import datetime
                        reset_dt = datetime.fromisoformat(daily_reset_iso)
                        now_dt = datetime.utcnow()
                        delta = reset_dt - now_dt
                        if delta.total_seconds() > 0:
                            dh, dr = divmod(int(delta.total_seconds()), 3600)
                            dm, ds = divmod(dr, 60)
                            day_str = f" | {day_used}/{day_limit} day \u2192 resets in {dh}h {dm}m"
                        else:
                            day_str = f" | {day_used}/{day_limit} day"
                    except Exception:
                        day_str = f" | {day_used}/{day_limit} day"
                else:
                    day_str = f" | {day_used}/{day_limit} day"

            st.caption(f"{round(tokens_used, 1)}/{rate_min} min used  \U0001f504 full in {full_str}{day_str}")
            if "call_count" in st.session_state:
                calls = st.session_state.call_count.get(tool, 0)
                if calls:
                    st.caption(f"\U0001f4ca {calls} session calls")

        st.divider()
        st.markdown("**LLM Usage** (session)")
        calls: list[dict] = []
        for msg in st.session_state.messages:
            for u in msg.get("llm_usage", []):
                calls.append(u)
        if calls:
            st.caption(f"**{len(calls)} total calls**")
            for i, u in enumerate(calls, 1):
                model = u.get("model", "?")
                prov = u.get("provider", "?")
                pt = u.get("prompt_tokens", 0)
                ct = u.get("completion_tokens", 0)
                tt = u.get("total_tokens", 0)
                cost = u.get("cost", 0.0)
                st.caption(f"#{i}  {model}  ({prov})  \u2192 {pt} + {ct} = {tt} tokens  ${cost:.6f}")
        else:
            st.caption("No LLM calls yet")

for i, msg in enumerate(st.session_state.messages):
    with st.chat_message(msg["role"]):
        if msg["role"] == "user" and st.session_state.get("editing_idx") == i:
            edited = st.text_input("Edit message", value=msg["content"], key=f"edit_input_{i}", label_visibility="collapsed")
            ec1, ec2 = st.columns([1, 1])
            with ec1:
                if st.button("Save", key=f"edit_save_{i}", use_container_width=True):
                    st.session_state.editing_idx = None
                    st.session_state._pending_edit_idx = (i, edited)
                    st.rerun()
            with ec2:
                if st.button("Cancel", key=f"edit_cancel_{i}", use_container_width=True):
                    st.session_state.editing_idx = None
                    st.rerun()
        else:
            st.markdown(msg["content"])

        if msg["role"] == "assistant":
            m = msg.get("model", "")
            if m:
                st.caption(f"Model: {MODEL_DISPLAY.get(m, m)}  ·  Mode: {msg.get('mode', 'Analysis')}")
        if msg["role"] == "assistant" and "confidence" in msg and msg.get("mode") != "Talking":
            conf = msg["confidence"]
            color = "#4ade80" if conf >= 0.7 else ("#fbbf24" if conf >= 0.4 else "#f87171")
            st.markdown(
                f"<span class='confidence-badge' style='color: {color};'>\u25cf {conf:.0%} confidence</span>",
                unsafe_allow_html=True
            )
        if msg["role"] == "assistant" and msg.get("tool_results") and msg.get("mode") != "Talking":
            source_parts = []
            for tr in msg["tool_results"]:
                name = TOOL_DISPLAY_NAMES.get(tr["source"], tr["source"].title())
                summary = _tool_summary(tr)
                icon = "\u2714\ufe0f" if not tr.get("error") else "\u274c"
                source_parts.append(
                    f"<span class='source-badge source-{'ok' if not tr.get('error') else 'err'}'>"
                    f"{icon} {name} \u2014 {summary}</span>"
                )
            if source_parts:
                st.markdown(
                    "<div class='sources-row'>" + "".join(source_parts) + "</div>",
                    unsafe_allow_html=True,
                )
        if "trace" in msg and msg["trace"] and msg.get("mode") != "Talking":
            with st.expander(f"\u2699\ufe0f Trace ({len(msg['trace'])} steps)", expanded=False):
                for step in msg["trace"]:
                    icons = {"passed": "\u2705", "blocked": "\ud83d\udeab", "pending": "\u23f3", "error": "\u274c"}
                    icon = icons.get(step.get("status", ""), "\u2b1c")
                    dur = step.get("duration_ms")
                    if not dur and step.get("start_time") and step.get("end_time"):
                        try:
                            from datetime import datetime
                            sd = datetime.fromisoformat(step["start_time"])
                            ed = datetime.fromisoformat(step["end_time"])
                            dur = int((ed - sd).total_seconds() * 1000)
                        except Exception:
                            dur = None
                    dur_str = f" \u2014 {dur}ms" if dur else ""
                    st.markdown(f"{icon} **{step['step']}**{dur_str}")
                    if step.get("result_summary"):
                        st.caption(step["result_summary"])

        # Action buttons
        if st.session_state.get("editing_idx") != i:
            if st.session_state.get("_confirm_delete_msg_idx") == i:
                confirm_cols = st.columns([6, 0.3, 0.3, 0.4])
                with confirm_cols[1]:
                    if st.button("Yes", key=f"confirm_yes_{i}"):
                        st.session_state._pending_delete_idx = i
                        st.session_state._confirm_delete_msg_idx = None
                        st.rerun()
                with confirm_cols[2]:
                    if st.button("No", key=f"confirm_no_{i}"):
                        st.session_state._confirm_delete_msg_idx = None
                        st.rerun()
                with confirm_cols[3]:
                    st.caption("Delete?")
            else:
                act_cols = st.columns([6, 1])
                with act_cols[1]:
                    btns = st.columns(3)
                    if msg["role"] == "user":
                        with btns[0]:
                            if st.button("\u270F\ufe0f", key=f"edit_{i}", help="Edit"):
                                st.session_state.editing_idx = i
                                st.rerun()
                        with btns[1]:
                            if st.button("\U0001F504", key=f"retry_{i}", help="Retry"):
                                st.session_state._pending_retry_idx = (i, msg["content"])
                                st.rerun()
                        with btns[2]:
                            if st.button("\U0001F5D1", key=f"del_{i}", help="Delete"):
                                st.session_state._confirm_delete_msg_idx = i
                                st.rerun()
                    else:
                        with btns[2]:
                            if st.button("\U0001F5D1", key=f"del_{i}", help="Delete"):
                                st.session_state._confirm_delete_msg_idx = i
                                st.rerun()

if not st.session_state.messages:
    center_col1, center_col2, center_col3 = st.columns([1, 2, 1])
    with center_col2:
        st.markdown("<div class='empty-state'>", unsafe_allow_html=True)
        st.markdown("### Threat Intelligence Analyst")
        st.markdown("<p style='font-size: 1.1rem; color: #888;'>What can I help you investigate today?</p>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        for i in range(0, len(EXAMPLE_PROMPTS), 2):
            row = st.columns(2)
            for j in range(2):
                if i + j < len(EXAMPLE_PROMPTS):
                    title, desc = EXAMPLE_PROMPTS[i + j]
                    with row[j]:
                        if st.button(
                            f"**{title}**\n\n{desc}",
                            key=f"ex_{i + j}",
                            use_container_width=True,
                            help=desc,
                        ):
                            st.session_state._pending_query = title
                            st.rerun()

# Bottom form bar - centered ChatGPT-style input
input_placeholder = "Ask about IPs, domains, hashes, CVEs, threat actors..." if st.session_state.agent_mode_toolbar == "Analysis" else "Ask anything..."

# Centered wrapper
chat_bottom = st.container()
with chat_bottom:
    st.markdown('<div class="chat-bottom-bar">', unsafe_allow_html=True)

    # Form with text input and send button only
    with st.form("chat_form", clear_on_submit=True, border=False):
        query = st.text_input("Message", placeholder=input_placeholder, key="chat_input_text", label_visibility="collapsed")
        btn_cols = st.columns([6, 1])
        with btn_cols[1]:
            submitted = st.form_submit_button("↑", use_container_width=True)

    # Mode/Model selectors below input box
    st.markdown('<div class="chat-selectors">', unsafe_allow_html=True)
    sel_cols = st.columns([1, 1])
    with sel_cols[0]:
        def _mode_label(m: str) -> str:
            return {"Analysis": "Analysis (Uses Threat Detection API)", "Talking": "Talking (Uses LLM API only)"}.get(m, m)
        st.selectbox("Mode", options=["Analysis", "Talking"], format_func=_mode_label, key="agent_mode_toolbar", label_visibility="collapsed", on_change=_sync_mode)
    with sel_cols[1]:
        default_label = _get_default_model_label()
        model_options = list(MODEL_SELECT_OPTIONS.keys())
        default_index = model_options.index(default_label) if default_label in model_options else 0
        st.selectbox("Model", options=model_options, index=default_index, key="selected_model_toolbar", label_visibility="collapsed", on_change=_sync_model_selection)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)

if submitted and query:
    _sync_model_selection()
    st.session_state._pending_query = query
    st.rerun()
