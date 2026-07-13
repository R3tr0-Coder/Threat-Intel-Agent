import json
import re
from pathlib import Path
from typing import Optional

_techniques: dict[str, dict] = {}
ATTACK_ID_PATTERN = re.compile(r'(T\d{4}(?:\.\d{3})?)', re.IGNORECASE)


def _load_techniques() -> dict[str, dict]:
    global _techniques
    if _techniques:
        return _techniques
    p = Path(__file__).resolve().parent / "data" / "techniques.json"
    if not p.exists():
        _techniques = {}
        return _techniques
    with open(p, encoding="utf-8") as f:
        _techniques = json.load(f)
    return _techniques


def resolve_technique(technique_id: str) -> Optional[dict]:
    db = _load_techniques()
    key = technique_id.upper()
    return db.get(key)


def resolve_tags(tags: list[str]) -> list[dict]:
    resolved = []
    for tag in tags:
        m = ATTACK_ID_PATTERN.match(tag.strip())
        if m:
            tid = m.group(1).upper()
            info = resolve_technique(tid)
            if info:
                resolved.append(info)
    return resolved


def find_techniques_in_text(text: str) -> list[dict]:
    found = []
    for m in ATTACK_ID_PATTERN.finditer(text):
        tid = m.group(1).upper()
        info = resolve_technique(tid)
        if info:
            found.append(info)
    return found


def all_techniques() -> dict[str, dict]:
    return _load_techniques()


def get_all_tactics() -> list[str]:
    db = _load_techniques()
    tactics = set()
    for info in db.values():
        for t in info.get("tactics", []):
            tactics.add(t)
    return sorted(tactics)
