"""
Contract Fuzzer
Property-based testing engine for Solidity smart contracts.
Generates random inputs to discover edge-case vulnerabilities.
"""

from __future__ import annotations
import random
import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzResult:
    """Result of a single fuzzing iteration."""
    test_name: str
    passed: bool
    input_data: dict[str, Any]
    error: Optional[str] = None
    gas_used: int = 0
    duration_ms: float = 0.0


class ContractFuzzer:
    """Generates and executes random inputs against contract functions."""

    def __init__(self, iterations: int = 1000, seed: Optional[int] = None) -> None:
        self.iterations = iterations
        self.rng = random.Random(seed)
        self.results: list[FuzzResult] = []
        self._strategies: dict[str, Callable] = {
            "uint256": self._gen_uint256,
            "address": self._gen_address,
            "bytes32": self._gen_bytes32,
            "bool": self._gen_bool,
            "string": self._gen_string,
            "int256": self._gen_int256,
        }

    def fuzz_function(
        self,
        func_name: str,
        param_types: list[str],
        assertion: Callable[[dict], bool],
    ) -> list[FuzzResult]:
        """Fuzz a function with random inputs and check assertion."""
        logger.info(f"Fuzzing {func_name} with {self.iterations} iterations")
        self.results.clear()

        for i in range(self.iterations):
            inputs = self._generate_inputs(param_types)
            try:
                passed = assertion(inputs)
                self.results.append(FuzzResult(
                    test_name=func_name, passed=passed, input_data=inputs
                ))
            except Exception as e:
                self.results.append(FuzzResult(
                    test_name=func_name, passed=False,
                    input_data=inputs, error=str(e),
                ))

        failures = [r for r in self.results if not r.passed]
        logger.info(f"Fuzz complete: {len(failures)}/{self.iterations} failures")
        return self.results

    def _generate_inputs(self, param_types: list[str]) -> dict[str, Any]:
        """Generate random inputs for given parameter types."""
        inputs = {}
        for i, ptype in enumerate(param_types):
            gen = self._strategies.get(ptype, self._gen_uint256)
            inputs[f"param_{i}"] = gen()
        return inputs

    def _gen_uint256(self) -> int:
        """Generate uint256 with edge cases."""
        edges = [0, 1, 2**256 - 1, 2**128, 2**255, 2**8]
        if self.rng.random() < 0.3:
            return self.rng.choice(edges)
        return self.rng.randint(0, 2**256 - 1)

    def _gen_address(self) -> str:
        """Generate random Ethereum address."""
        if self.rng.random() < 0.2:
            return "0x" + "0" * 40
        addr = self.rng.randbytes(20).hex()
        return f"0x{addr}"

    def _gen_bytes32(self) -> bytes:
        """Generate random bytes32."""
        return self.rng.randbytes(32)

    def _gen_bool(self) -> bool:
        return self.rng.choice([True, False])

    def _gen_string(self) -> str:
        """Generate random string with edge cases."""
        edges = ["", "a" * 256, "\x00", "🔥" * 10]
        if self.rng.random() < 0.2:
            return self.rng.choice(edges)
        length = self.rng.randint(0, 100)
        return "".join(chr(self.rng.randint(32, 126)) for _ in range(length))

    def _gen_int256(self) -> int:
        """Generate int256 with edge cases."""
        edges = [0, -1, 1, -(2**255), 2**255 - 1]
        if self.rng.random() < 0.2:
            return self.rng.choice(edges)
        return self.rng.randint(-(2**255), 2**255 - 1)

    def get_failure_inputs(self) -> list[dict[str, Any]]:
        """Return inputs that caused failures for reproduction."""
        return [r.input_data for r in self.results if not r.passed]

    def generate_report(self) -> str:
        """Generate a human-readable fuzzing report."""
        total = len(self.results)
        failures = sum(1 for r in self.results if not r.passed)
        report = f"Fuzzing Report: {self.results[0].test_name if self.results else 'N/A'}\n"
        report += f"{'='*50}\n"
        report += f"Total: {total} | Passed: {total - failures} | Failed: {failures}\n"
        if failures:
            report += f"\nSample failures:\n"
            for r in self.results[:5]:
                if not r.passed:
                    report += f"  Input: {r.input_data} Error: {r.error}\n"
        return report
