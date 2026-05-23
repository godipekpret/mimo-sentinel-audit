"""
Tests for the Rugpull Detector module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinel.rugpull_detector import RugpullDetector


class TestRugpullDetector:
    """Test suite for RugpullDetector."""

    def test_detects_blacklist(self):
        source = """
        mapping(address => bool) public isBlackListed;
        function transfer(address to, uint amount) public {
            require(!isBlackListed[msg.sender]);
        }
        """
        detector = RugpullDetector(source)
        signals = detector.analyze()
        types = [s.signal_type for s in signals]
        assert "blacklist_mechanism" in types

    def test_detects_hidden_mint(self):
        source = """
        function mint(address to, uint amount) external {
            _totalSupply += amount;
            _balances[to] += amount;
        }
        """
        detector = RugpullDetector(source)
        signals = detector.analyze()
        types = [s.signal_type for s in signals]
        assert "public_mint" in types

    def test_detects_fee_manipulation(self):
        source = """
        uint public buyFee = 5;
        uint public sellFee = 5;
        function setFee(uint _buy, uint _sell) external onlyOwner {
            buyFee = _buy;
            sellFee = _sell;
        }
        """
        detector = RugpullDetector(source)
        signals = detector.analyze()
        types = [s.signal_type for s in signals]
        assert "fee_manipulation" in types or "split_fees" in types

    def test_detects_trading_toggle(self):
        source = """
        bool public tradingEnabled = false;
        function enableTrading() external onlyOwner {
            tradingEnabled = true;
        }
        """
        detector = RugpullDetector(source)
        signals = detector.analyze()
        types = [s.signal_type for s in signals]
        assert "trading_toggle" in types

    def test_risk_score(self):
        source = """
        mapping(address => bool) public isBlackListed;
        function mint(address to, uint amount) external {
            _totalSupply += amount;
        }
        bool public tradingEnabled = false;
        """
        detector = RugpullDetector(source)
        detector.analyze()
        score = detector.risk_score()
        assert score > 0
        assert score <= 100

    def test_clean_token(self):
        source = """
        function transfer(address to, uint amount) public returns (bool) {
            _balances[msg.sender] -= amount;
            _balances[to] += amount;
            return true;
        }
        """
        detector = RugpullDetector(source)
        signals = detector.analyze()
        critical = [s for s in signals if s.severity == "CRITICAL"]
        assert len(critical) == 0
