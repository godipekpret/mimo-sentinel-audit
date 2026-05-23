"""
Gas Optimizer
Analyzes Solidity code and suggests gas-efficient alternatives.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GasSuggestion:
    """A gas optimization suggestion."""
    pattern: str
    line: int
    current_cost: int  # estimated gas
    optimized_cost: int
    suggestion: str
    savings_percent: float
    code_snippet: str


# Known gas anti-patterns and their optimizations
GAS_RULES: list[dict] = [
    {
        "name": "storage_read_in_loop",
        "pattern": r"for\s*\([^)]*\)\s*\{[^}]*\bstorage\b",
        "line_pattern": r"for\s*\(",
        "suggestion": "Cache storage variable in memory before loop",
        "savings": 2100,
    },
    {
        "name": "redundant_sload",
        "pattern": r"(\w+)\s*=.*;\s*\n.*\1\s*=",
        "line_pattern": r"(\w+)\s*=.*;",
        "suggestion": "Multiple SLOAD for same variable — use memory cache",
        "savings": 2100,
    },
    {
        "name": "string_concat_in_loop",
        "pattern": r"for\s*\(.*\+\s*=",
        "line_pattern": r"\+\s*=",
        "suggestion": "String concatenation in loop is expensive — use bytes.concat()",
        "savings": 500,
    },
    {
        "name": "unchecked_safe_math",
        "pattern": r"(?<!unchecked\s*\{)\s*[\+\-]\s*1\s*;",
        "line_pattern": r"[\+\-]\s*1\s*;",
        "suggestion": "Use ++i / --i instead of i++ / i-- (saves ~5 gas per iteration)",
        "savings": 5,
    },
    {
        "name": "public_to_external",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s+public",
        "line_pattern": r"function\s+\w+\s*\([^)]*\)\s+public",
        "suggestion": "Use 'external' instead of 'public' if function isn't called internally",
        "savings": 30,
    },
    {
        "name": "short_circuit_missing",
        "pattern": r"require\s*\(\s*\w+\s*&&\s*\w+",
        "line_pattern": r"require\s*\(",
        "suggestion": "Put cheaper condition first in && for short-circuit evaluation",
        "savings": 100,
    },
    {
        "name": "emit_optimization",
        "pattern": r"emit\s+\w+\s*\([^)]*,\s*0\s*,",
        "line_pattern": r"emit\s+",
        "suggestion": "Avoid emitting zero values — costs extra LOG gas",
        "savings": 375,
    },
    {
        "name": "calldata_not_memory",
        "pattern": r"function\s+\w+\s*\([^)]*memory\s+(\w+)\s*\)",
        "line_pattern": r"memory\s+\w+",
        "suggestion": "Use 'calldata' instead of 'memory' for read-only function parameters",
        "savings": 60,
    },
    {
        "name": "packing_struct_members",
        "pattern": r"struct\s+\w+\s*\{",
        "line_pattern": r"struct\s+\w+",
        "suggestion": "Pack struct members to fit in fewer 32-byte storage slots",
        "savings": 20000,
    },
    {
        "name": "immutable_missing",
        "pattern": r"(?<!immutable\s)\baddress\s+public\s+\w+;",
        "line_pattern": r"address\s+public\s+\w+;",
        "suggestion": "Use 'immutable' for values set only in constructor — saves ~2100 gas on reads",
        "savings": 2100,
    },
]


class GasOptimizer:
    """Analyzes Solidity code for gas optimization opportunities."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.suggestions: list[GasSuggestion] = []

    def analyze(self) -> list[GasSuggestion]:
        """Run gas optimization analysis."""
        logger.info("Running gas optimization analysis")
        self._check_patterns()
        self._check_storage_packing()
        self._check_constant_variables()
        self._check_error_handling()
        self.suggestions.sort(key=lambda s: s.savings_percent, reverse=True)
        logger.info(f"Gas optimizer complete: {len(self.suggestions)} suggestions")
        return self.suggestions

    def _check_patterns(self) -> None:
        """Check source against gas anti-patterns."""
        for rule in GAS_RULES:
            for i, line in enumerate(self.lines, 1):
                if re.search(rule["line_pattern"], line):
                    self.suggestions.append(GasSuggestion(
                        pattern=rule["name"],
                        line=i,
                        current_cost=rule["savings"] * 2,
                        optimized_cost=rule["savings"],
                        suggestion=rule["suggestion"],
                        savings_percent=50.0,
                        code_snippet=line.strip()[:80],
                    ))

    def _check_storage_packing(self) -> None:
        """Check for struct/variable packing opportunities."""
        in_struct = False
        struct_name = ""
        members: list[tuple[int, str]] = []
        for i, line in enumerate(self.lines, 1):
            match = re.search(r"struct\s+(\w+)\s*\{", line)
            if match:
                in_struct = True
                struct_name = match.group(1)
                members = []
                continue
            if in_struct and "}" in line:
                in_struct = False
                if len(members) > 3:
                    self.suggestions.append(GasSuggestion(
                        pattern="struct_packing",
                        line=i,
                        current_cost=len(members) * 20000,
                        optimized_cost=(len(members) // 2) * 20000,
                        suggestion=f"Struct '{struct_name}' can be packed into fewer slots",
                        savings_percent=30.0,
                        code_snippet=f"struct {struct_name} ({len(members)} members)",
                    ))
                continue
            if in_struct:
                members.append((i, line.strip()))

    def _check_constant_variables(self) -> None:
        """Find variables that could be declared constant or immutable."""
        state_var = re.compile(r"^\s*(uint\d*|int\d*|address|bool|bytes\d*)\s+(public\s+|private\s+|internal\s+)?(\w+)\s*;")
        assignments = set()
        for line in self.lines:
            assign = re.search(r"(\w+)\s*=\s*", line)
            if assign:
                assignments.add(assign.group(1))

        for i, line in enumerate(self.lines, 1):
            match = state_var.match(line)
            if match:
                var_name = match.group(3)
                if var_name not in assignments or "constructor" in self.source:
                    self.suggestions.append(GasSuggestion(
                        pattern="constant_candidate",
                        line=i,
                        current_cost=2100,
                        optimized_cost=100,
                        suggestion=f"Variable '{var_name}' may be constant/immutable",
                        savings_percent=95.0,
                        code_snippet=line.strip()[:80],
                    ))

    def _check_error_handling(self) -> None:
        """Check for gas-efficient error handling (custom errors vs require strings)."""
        require_with_string = re.compile(r'require\s*\([^,]+,\s*"[^"]+"\s*\)')
        for i, line in enumerate(self.lines, 1):
            if require_with_string.search(line):
                self.suggestions.append(GasSuggestion(
                    pattern="custom_error",
                    line=i,
                    current_cost=500,
                    optimized_cost=100,
                    suggestion="Use custom errors instead of require strings — saves ~200 gas",
                    savings_percent=60.0,
                    code_snippet=line.strip()[:80],
                ))

    def total_savings(self) -> int:
        """Calculate total estimated gas savings."""
        return sum(s.current_cost - s.optimized_cost for s in self.suggestions)
