"""
Tests for the Gas Optimizer module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinel.gas_optimizer import GasOptimizer


class TestGasOptimizer:
    """Test suite for GasOptimizer."""

    def test_detects_custom_error_opportunity(self):
        source = """
        function transfer(address to, uint amount) public {
            require(msg.sender != address(0), "Invalid sender");
            require(to != address(0), "Invalid recipient");
        }
        """
        optimizer = GasOptimizer(source)
        suggestions = optimizer.analyze()
        patterns = [s.pattern for s in suggestions]
        assert "custom_error" in patterns

    def test_detects_calldata_opportunity(self):
        source = """
        function process(bytes memory data) external {
            // process data
        }
        """
        optimizer = GasOptimizer(source)
        suggestions = optimizer.analyze()
        patterns = [s.pattern for s in suggestions]
        assert "calldata_not_memory" in patterns

    def test_total_savings(self):
        source = """
        require(amount > 0, "Zero amount");
        function foo(bytes memory x) external {}
        """
        optimizer = GasOptimizer(source)
        optimizer.analyze()
        savings = optimizer.total_savings()
        assert savings > 0

    def test_clean_code(self):
        source = """
        pragma solidity 0.8.19;
        contract Clean {
            uint256 public constant MAX = 100;
            function add(uint256 a, uint256 b) pure returns (uint256) {
                return a + b;
            }
        }
        """
        optimizer = GasOptimizer(source)
        suggestions = optimizer.analyze()
        # Clean code should have minimal suggestions
        high_savings = [s for s in suggestions if s.savings_percent > 80]
        assert len(high_savings) == 0
