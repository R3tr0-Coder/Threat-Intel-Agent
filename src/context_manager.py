import re
from typing import Optional

from src.models import EntityContext, IntentClassification, ConversationTurn


class ContextManager:
    def __init__(self):
        self.entity_context = EntityContext()
        self.history: list[ConversationTurn] = []
        self.max_history = 20

    def add_turn(self, turn: ConversationTurn):
        self.history.append(turn)
        if len(self.history) > self.max_history:
            self.history.pop(0)
        self._update_entities(turn)

    def _update_entities(self, turn: ConversationTurn):
        entities = turn.intent.entities
        if entities.get("ip"):
            self.entity_context.ips[entities["ip"]] = turn.timestamp
            self.entity_context.last_topic = entities["ip"]
        if entities.get("domain"):
            self.entity_context.domains[entities["domain"]] = turn.timestamp
            self.entity_context.last_topic = entities["domain"]
        if entities.get("hash"):
            self.entity_context.hashes[entities["hash"]] = turn.timestamp
            self.entity_context.last_topic = entities["hash"]
        if entities.get("url"):
            self.entity_context.urls[entities["url"]] = turn.timestamp
            self.entity_context.last_topic = entities["url"]
        if entities.get("actor"):
            self.entity_context.actors[entities["actor"]] = turn.timestamp
            self.entity_context.last_topic = entities["actor"]
        if entities.get("software"):
            self.entity_context.software[entities["software"]] = turn.timestamp
            self.entity_context.last_topic = entities["software"]
        if turn.tool_results:
            for r in turn.tool_results:
                source_ip = r.data.get("ip") or r.data.get("value")
                cves = r.data.get("cves", [])
                for cve in cves:
                    cve_id = cve.get("id", "")
                    if cve_id:
                        self.entity_context.cves[cve_id] = turn.timestamp
                        if source_ip:
                            self._add_relationship(source_ip, cve_id)
                resolutions = r.data.get("resolutions", [])
                for res in resolutions:
                    host = res.get("host", "")
                    if host and source_ip:
                        self._add_relationship(source_ip, host)
                hostnames = r.data.get("hostnames", [])
                for hn in hostnames:
                    if hn and source_ip:
                        self._add_relationship(source_ip, hn)
                domains = r.data.get("domains", [])
                for d in domains:
                    if d and source_ip:
                        self._add_relationship(source_ip, d)
                pulse_actors = []
                pulses = r.data.get("pulses", [])
                for p in pulses:
                    adv = p.get("adversary", "")
                    if adv and adv not in pulse_actors:
                        pulse_actors.append(adv)
                for adv in pulse_actors:
                    for entity_key in list(self.entity_context.ips.keys())[-3:]:
                        self._add_relationship(entity_key, adv)

    def _add_relationship(self, a: str, b: str):
        if a not in self.entity_context.relationships:
            self.entity_context.relationships[a] = []
        if b not in self.entity_context.relationships[a]:
            self.entity_context.relationships[a].append(b)
        if b not in self.entity_context.relationships:
            self.entity_context.relationships[b] = []
        if a not in self.entity_context.relationships[b]:
            self.entity_context.relationships[b].append(a)

    def resolve_references(self, query: str) -> tuple[str, Optional[str]]:
        pronoun_patterns = [
            r"\b(it|its|that|this|they|them|the ip|that ip|the domain|that domain|the hash|that hash)\b",
            r"\b(the\s+(ip|domain|hash|actor|software|version|file|url))\b",
            r"\b(its\s+(asn|isp|reputation|country|score|owner|registrar))\b",
        ]
        q_lower = query.lower()

        has_pronoun = any(re.search(p, q_lower) for p in pronoun_patterns)
        if not has_pronoun:
            return query, None

        resolved_value = None
        entity_type = None

        if re.search(r"\b(asn|isp|country|ip)\b", q_lower) and not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", query):
            if self.entity_context.ips:
                resolved_value = list(self.entity_context.ips.keys())[-1]
                entity_type = "ip"
            elif self.entity_context.domains:
                resolved_value = list(self.entity_context.domains.keys())[-1]
                entity_type = "domain"
        elif re.search(r"\b(domain|hostname|host)\b", q_lower) and not re.search(r"\b[a-zA-Z0-9]\.[a-zA-Z]{2,}\b", query):
            if self.entity_context.ips:
                resolved_value = list(self.entity_context.ips.keys())[-1]
                entity_type = "ip"
        elif re.search(r"\b(hash|file|sha|md5)\b", q_lower):
            if self.entity_context.hashes:
                resolved_value = list(self.entity_context.hashes.keys())[-1]
                entity_type = "hash"
        elif re.search(r"\b(actor|group|apt)\b", q_lower):
            if self.entity_context.actors:
                resolved_value = list(self.entity_context.actors.keys())[-1]
                entity_type = "actor"
        elif re.search(r"\b(software|product|app|version)\b", q_lower):
            if self.entity_context.software:
                resolved_value = list(self.entity_context.software.keys())[-1]
                entity_type = "software"
        elif re.search(r"\b(cve|vulnerability|exposure)\b", q_lower):
            if self.entity_context.cves:
                resolved_value = list(self.entity_context.cves.keys())[-1]
                entity_type = "cve"
        else:
            if self.entity_context.last_topic:
                resolved_value = self.entity_context.last_topic

        if resolved_value and entity_type:
            resolved = query
            if "its" in q_lower:
                resolved = re.sub(r"\bits\b", f"{resolved_value}'s", query, flags=re.IGNORECASE)
            elif re.search(r"\b(the ip|that ip|the domain|that domain|the hash|that hash)\b", q_lower):
                resolved = re.sub(
                    r"\b(the ip|that ip|the domain|that domain|the hash|that hash)\b",
                    resolved_value,
                    query,
                    flags=re.IGNORECASE,
                )
            return resolved, resolved_value

        return query, None
