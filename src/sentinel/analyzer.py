"""
Static Analysis Engine
Performs deep code inspection for known vulnerability patterns in Solidity contracts.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    vuln_type: str
    severity: Severity
    line: int
    message: str
    recommendation: str = ""
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "line": self.line,
            "message": self.message,
            "recommendation": self.recommendation,
        }


VULN_PATTERNS: dict[str, dict] = {
    "reentrancy": {
        "severity": Severity.CRITICAL,
        "pattern": r"\.(call|send|transfer)\{.*value.*\}\(.*\)[\s\S]*?(balances|_balances)\[",
        "message": "External call before state update — reentrancy risk",
        "recommendation": "Use checks-effects-interactions pattern or ReentrancyGuard",
    },
    "unprotected_selfdestruct": {
        "severity": Severity.CRITICAL,
        "pattern": r"selfdestruct\s*\(",
        "message": "Unprotected selfdestruct can destroy the contract",
        "recommendation": "Add owner-only modifier or remove selfdestruct",
    },
    "unchecked_return": {
        "severity": Severity.HIGH,
        "pattern": r"\.call\{.*\}\(.*\);\s*$",
        "message": "Unchecked low-level call return value",
        "recommendation": "Check return value: (bool success, ) = addr.call(...); require(success);",
    },
    "tx_origin": {
        "severity": Severity.HIGH,
        "pattern": r"tx\.origin",
        "message": "Use of tx.origin for authentication is vulnerable to phishing",
        "recommendation": "Use msg.sender instead of tx.origin",
    },
    "integer_overflow": {
        "severity": Severity.MEDIUM,
        "pattern": r"(?<!unchecked\s*\{)\s*[\+\-\*]\s*(?!.*pragma solidity \^0\.8)",
        "message": "Arithmetic operation may overflow (pre-0.8.0)",
        "recommendation": "Upgrade to Solidity 0.8+ or use SafeMath",
    },
    "floating_pragma": {
        "severity": Severity.LOW,
        "pattern": r"pragma solidity\s*\^",
        "message": "Floating pragma version — lock to a specific version",
        "recommendation": "Use pragma solidity 0.8.19; (exact version)",
    },
    "timestamp_dependency": {
        "severity": Severity.LOW,
        "pattern": r"block\.timestamp",
        "message": "Block timestamp can be manipulated by miners (±15s)",
        "recommendation": "Avoid using block.timestamp for critical logic",
    },
}


class StaticAnalyzer:
    """Performs static analysis on Solidity source code."""

    def __init__(self, source: str, filename: str = "contract.sol") -> None:
        self.source = source
        self.filename = filename
        self.lines = source.splitlines()
        self.findings: list[Finding] = []

    def analyze(self) -> list[Finding]:
        """Run all static analysis checks and return findings."""
        logger.info(f"Analyzing {self.filename} ({len(self.lines)} lines)")
        self._check_patterns()
        self._check_function_visibility()
        self._check_unchecked_math()
        self.findings.sort(key=lambda f: list(Severity).index(f.severity))
        logger.info(f"Found {len(self.findings)} issues")
        return self.findings

    def _check_patterns(self) -> None:
        """Match source against known vulnerability patterns."""
        for name, vuln in VULN_PATTERNS.items():
            for i, line in enumerate(self.lines, 1):
                if re.search(vuln["pattern"], line):
                    self.findings.append(Finding(
                        vuln_type=name,
                        severity=vuln["severity"],
                        line=i,
                        message=vuln["message"],
                        recommendation=vuln["recommendation"],
                        code_snippet=line.strip(),
                    ))

    def _check_function_visibility(self) -> None:
        """Detect functions with missing visibility specifiers."""
        func_pattern = re.compile(r"function\s+\w+\s*\([^)]*\)[^{]*\{")
        for i, line in enumerate(self.lines, 1):
            match = func_pattern.search(line)
            if match and not any(kw in line for kw in ["public", "private", "internal", "external"]):
                self.findings.append(Finding(
                    vuln_type="missing_visibility",
                    severity=Severity.MEDIUM,
                    line=i,
                    message="Function missing explicit visibility specifier",
                    recommendation="Add public/private/internal/external to all functions",
                    code_snippet=line.strip(),
                ))

    def _check_unchecked_math(self) -> None:
        """Check for arithmetic in unchecked blocks."""
        unchecked = False
        depth = 0
        for i, line in enumerate(self.lines, 1):
            if "unchecked" in line:
                unchecked = True
                depth = line.count("{") - line.count("}")
                continue
            if unchecked:
                depth += line.count("{") - line.count("}")
                if depth <= 0:
                    unchecked = False
                    continue
                if re.search(r"[\+\-\*]", line):
                    self.findings.append(Finding(
                        vuln_type="unchecked_math",
                        severity=Severity.MEDIUM,
                        line=i,
                        message="Arithmetic in unchecked block — no overflow protection",
                        recommendation="Verify bounds manually or remove unchecked block",
                        code_snippet=line.strip(),
                    ))

    def get_summary(self) -> dict[str, int]:
        """Return count of findings by severity."""
        summary = {s.value: 0 for s in Severity}
        for f in self.findings:
            summary[f.severity.value] += 1
        return summary
