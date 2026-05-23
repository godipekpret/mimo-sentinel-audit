"""
Tests for the MiMo Reasoning Engine.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai.reasoning_engine import MiMoReasoningEngine


class TestMiMoReasoningEngine:
    """Test suite for MiMoReasoningEngine."""

    def test_analyze_reentrancy(self):
        engine = MiMoReasoningEngine()
        code = """
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
        """
        result = engine.analyze_vulnerability(code, "reentrancy")
        assert result.vulnerability == "reentrancy"
        assert result.confidence > 0
        assert len(result.reasoning_chain) > 0
        assert "reentrancy" in result.exploit_scenario.lower() or "attacker" in result.exploit_scenario.lower()

    def test_analyze_overflow(self):
        engine = MiMoReasoningEngine()
        result = engine.analyze_vulnerability("a += b", "integer_overflow")
        assert result.vulnerability == "integer_overflow"
        assert "SafeMath" in result.mitigation or "Solidity 0.8" in result.mitigation

    def test_confidence_calculation(self):
        engine = MiMoReasoningEngine()
        chain = ["step1", "step2", "step3", "step4", "step5"]
        confidence = engine._calculate_confidence(chain)
        assert 0 < confidence <= 0.95

    def test_history_tracking(self):
        engine = MiMoReasoningEngine()
        engine.analyze_vulnerability("code1", "reentrancy")
        engine.analyze_vulnerability("code2", "integer_overflow")
        history = engine.get_history()
        assert len(history) == 2
        assert history[0].vulnerability == "reentrancy"

    def test_references_provided(self):
        engine = MiMoReasoningEngine()
        result = engine.analyze_vulnerability("code", "reentrancy")
        assert len(result.references) > 0

    def test_unknown_vuln_type(self):
        engine = MiMoReasoningEngine()
        result = engine.analyze_vulnerability("code", "unknown_type")
        assert result.vulnerability == "unknown_type"
        assert len(result.reasoning_chain) >= 1
