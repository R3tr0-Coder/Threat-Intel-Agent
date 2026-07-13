import pytest
from src.context_manager import ContextManager
from src.models import EntityContext, IntentClassification, IntentType, ConversationTurn, ToolResult


class TestContextManager:
    def test_initial_state(self, context_manager):
        assert len(context_manager.history) == 0
        assert context_manager.entity_context.last_topic is None

    def test_update_context_with_ip(self, context_manager):
        turn = _make_turn("Is 45.83.122.10 malicious?", IntentType.ioc_lookup, {"ip": "45.83.122.10"})
        context_manager.add_turn(turn)
        assert "45.83.122.10" in context_manager.entity_context.ips
        assert context_manager.entity_context.last_topic == "45.83.122.10"

    def test_update_context_with_domain(self, context_manager):
        turn = _make_turn("Check evil.com", IntentType.ioc_lookup, {"domain": "evil.com"})
        context_manager.add_turn(turn)
        assert "evil.com" in context_manager.entity_context.domains

    def test_update_context_with_hash(self, context_manager):
        h = "a" * 64
        turn = _make_turn("Scan hash", IntentType.ioc_lookup, {"hash": h})
        context_manager.add_turn(turn)
        assert h in context_manager.entity_context.hashes

    def test_reference_resolution_ip_pronoun(self, context_manager, entity_context):
        context_manager.entity_context = entity_context
        resolved, ref = context_manager.resolve_references("and what's its ASN?")
        assert ref == "45.83.122.10"
        assert "45.83.122.10" in resolved

    def test_reference_resolution_the_ip(self, context_manager, entity_context):
        context_manager.entity_context = entity_context
        resolved, ref = context_manager.resolve_references("Pivot from that IP to domains")
        assert ref == "45.83.122.10"

    def test_reference_resolution_domain(self, context_manager, entity_context):
        context_manager.entity_context = entity_context
        resolved, ref = context_manager.resolve_references("what's the reputation of the domain?")
        assert ref is not None

    def test_no_reference_needed(self, context_manager):
        resolved, ref = context_manager.resolve_references("Is 1.2.3.4 malicious?")
        assert ref is None
        assert resolved == "Is 1.2.3.4 malicious?"

    def test_history_limit(self, context_manager):
        for i in range(25):
            turn = _make_turn(f"Query {i}", IntentType.unknown, {})
            context_manager.add_turn(turn)
        assert len(context_manager.history) == 20

    def test_multiple_entities(self, context_manager):
        turn1 = _make_turn("Check IP", IntentType.ioc_lookup, {"ip": "1.2.3.4"})
        turn2 = _make_turn("Check domain", IntentType.ioc_lookup, {"domain": "test.com"})
        context_manager.add_turn(turn1)
        context_manager.add_turn(turn2)
        assert "1.2.3.4" in context_manager.entity_context.ips
        assert "test.com" in context_manager.entity_context.domains


def _make_turn(query: str, intent_type: IntentType, entities: dict) -> ConversationTurn:
    return ConversationTurn(
        query=query,
        intent=IntentClassification(intent=intent_type, entities=entities, confidence=0.8),
        tool_results=[ToolResult(source="test", data={"result": "ok"})],
        confidence=0.8,
        response="Test response",
    )
