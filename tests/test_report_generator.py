"""
Tests for the Report Generator module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinel.report_generator import ReportGenerator


class TestReportGenerator:
    """Test suite for ReportGenerator."""

    def test_generate_html(self, tmp_path):
        findings = [
            {"vuln_type": "reentrancy", "severity": "CRITICAL", "line": 47, "message": "External call"},
            {"vuln_type": "unchecked_return", "severity": "HIGH", "line": 89, "message": "Unchecked call"},
        ]
        gen = ReportGenerator("TestToken.sol", findings)
        out = str(tmp_path / "report.html")
        gen.generate_html(out)
        assert os.path.exists(out)
        content = open(out).read()
        assert "CRITICAL" in content
        assert "MiMo Sentinel" in content

    def test_generate_json(self, tmp_path):
        findings = [{"vuln_type": "overflow", "severity": "MEDIUM", "line": 10, "message": "Math"}]
        gen = ReportGenerator("Test.sol", findings)
        out = str(tmp_path / "report.json")
        gen.generate_json(out)
        import json
        data = json.loads(open(out).read())
        assert data["contract"] == "Test.sol"
        assert data["score"] == 95

    def test_score_calculation(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        gen = ReportGenerator("test", findings)
        score = gen._calculate_score()
        assert score == 100 - 20 - 12 - 5

    def test_summary_text(self):
        findings = [{"severity": "CRITICAL", "vuln_type": "reentrancy", "line": 1, "message": "test"}]
        gen = ReportGenerator("Token.sol", findings)
        text = gen.get_summary_text()
        assert "Token.sol" in text
        assert "CRITICAL" in text

    def test_perfect_score(self):
        gen = ReportGenerator("Safe.sol", [])
        assert gen._calculate_score() == 100
