"""
Tests for the Fuzzer module.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sentinel.fuzzer import ContractFuzzer, FuzzResult


class TestContractFuzzer:
    """Test suite for ContractFuzzer."""

    def test_fuzz_passes_with_always_true(self):
        fuzzer = ContractFuzzer(iterations=100, seed=42)
        results = fuzzer.fuzz_function(
            "test_func",
            ["uint256"],
            lambda inputs: True,
        )
        assert all(r.passed for r in results)
        assert len(results) == 100

    def test_fuzz_detects_failures(self):
        fuzzer = ContractFuzzer(iterations=100, seed=42)
        results = fuzzer.fuzz_function(
            "overflow_check",
            ["uint256"],
            lambda inputs: inputs["param_0"] < 2**255,
        )
        failures = [r for r in results if not r.passed]
        assert len(failures) > 0

    def test_edge_case_generation(self):
        fuzzer = ContractFuzzer(iterations=1000, seed=42)
        addresses = [fuzzer._gen_address() for _ in range(100)]
        assert any(a == "0x" + "0" * 40 for a in addresses)

    def test_uint256_edge_cases(self):
        fuzzer = ContractFuzzer(iterations=100, seed=42)
        values = [fuzzer._gen_uint256() for _ in range(100)]
        assert all(0 <= v < 2**256 for v in values)

    def test_failure_inputs_extraction(self):
        fuzzer = ContractFuzzer(iterations=50, seed=42)
        fuzzer.fuzz_function("test", ["uint256"], lambda x: x["param_0"] != 0)
        failure_inputs = fuzzer.get_failure_inputs()
        assert all(inp["param_0"] == 0 for inp in failure_inputs)

    def test_report_generation(self):
        fuzzer = ContractFuzzer(iterations=10, seed=42)
        fuzzer.fuzz_function("test", ["bool"], lambda x: True)
        report = fuzzer.generate_report()
        assert "test" in report
        assert "Total: 10" in report
