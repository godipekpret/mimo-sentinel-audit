"""
Tests for the Static Analyzer module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinel.analyzer import StaticAnalyzer, Severity


class TestStaticAnalyzer:
    """Test suite for StaticAnalyzer."""

    def test_detects_reentrancy(self):
        source = """
        function withdraw() external {
            uint amount = balances[msg.sender];
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] = 0;
        }
        """
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        types = [f.vuln_type for f in findings]
        assert "reentrancy" in types or "unchecked_return" in types

    def test_detects_selfdestruct(self):
        source = """
        function destroy() external {
            selfdestruct(payable(msg.sender));
        }
        """
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        types = [f.vuln_type for f in findings]
        assert "unprotected_selfdestruct" in types

    def test_detects_tx_origin(self):
        source = """
        modifier onlyOwner() {
            require(tx.origin == owner);
            _;
        }
        """
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        types = [f.vuln_type for f in findings]
        assert "tx_origin" in types

    def test_detects_floating_pragma(self):
        source = 'pragma solidity ^0.8.0;'
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        types = [f.vuln_type for f in findings]
        assert "floating_pragma" in types

    def test_clean_contract(self):
        source = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.19;

        contract Safe {
            mapping(address => uint) public balances;
            
            function deposit() external payable {
                balances[msg.sender] += msg.value;
            }
        }
        """
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_summary_counts(self):
        source = """
        pragma solidity ^0.8.0;
        function foo() {
            selfdestruct(payable(msg.sender));
        }
        """
        analyzer = StaticAnalyzer(source)
        analyzer.analyze()
        summary = analyzer.get_summary()
        assert summary["CRITICAL"] >= 1
        assert summary["LOW"] >= 1

    def test_finding_to_dict(self):
        source = 'pragma solidity ^0.8.0;'
        analyzer = StaticAnalyzer(source)
        findings = analyzer.analyze()
        assert len(findings) > 0
        d = findings[0].to_dict()
        assert "vuln_type" in d
        assert "severity" in d
        assert "line" in d
