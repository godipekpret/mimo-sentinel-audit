"""
Approval Scanner
Detects unlimited token approvals and common approval vulnerabilities.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

MAX_UINT256 = 2**256 - 1


@dataclass
class ApprovalIssue:
    """Detected approval vulnerability."""
    issue_type: str
    severity: str
    line: int
    spender: str
    amount: Optional[int]
    message: str
    recommendation: str


class ApprovalScanner:
    """Scans contract code for approval-related vulnerabilities."""

    DANGEROUS_PATTERNS = [
        {
            "name": "unlimited_approval",
            "pattern": r"approve\s*\([^,]*,\s*(?:type\(uint256\)\.max|2\*\*256\s*-\s*1|uint256\(-1\))",
            "severity": "HIGH",
            "msg": "Unlimited token approval — user funds at risk",
        },
        {
            "name": "zero_address_check_missing",
            "pattern": r"function\s+approve\s*\([^)]*address\s+(\w+)[^)]*\)[^{]*\{",
            "severity": "MEDIUM",
            "msg": "approve() missing zero-address check for spender",
        },
        {
            "name": "increaseAllowance_missing",
            "pattern": r"\.approve\s*\(",
            "severity": "LOW",
            "msg": "Using approve() instead of increaseAllowance() — race condition risk",
        },
        {
            "name": "return_value_unchecked",
            "pattern": r"\.approve\s*\([^)]*\)\s*;",
            "severity": "HIGH",
            "msg": "Unchecked approve() return value",
        },
    ]

    SAFE_APPROVAL_PATTERNS = [
        r"SafeERC20",
        r"safeApprove",
        r"safeIncreaseAllowance",
        r"permit",
        r"EIP2612",
    ]

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.issues: list[ApprovalIssue] = []

    def scan(self) -> list[ApprovalIssue]:
        """Scan source for approval vulnerabilities."""
        logger.info("Scanning for approval vulnerabilities")
        self._check_dangerous_patterns()
        self._check_permit_availability()
        self._check_approval_in_loops()
        self._check_event_emission()
        logger.info(f"Approval scan complete: {len(self.issues)} issues found")
        return self.issues

    def _check_dangerous_patterns(self) -> None:
        """Check for known dangerous approval patterns."""
        for i, line in enumerate(self.lines, 1):
            for pat in self.DANGEROUS_PATTERNS:
                if re.search(pat["pattern"], line):
                    self.issues.append(ApprovalIssue(
                        issue_type=pat["name"],
                        severity=pat["severity"],
                        line=i,
                        spender=self._extract_spender(line),
                        amount=None,
                        message=pat["msg"],
                        recommendation=self._get_recommendation(pat["name"]),
                    ))

    def _check_permit_availability(self) -> None:
        """Check if EIP-2612 permit is implemented."""
        has_permit = bool(re.search(r"function\s+permit\s*\(", self.source))
        has_approve = bool(re.search(r"function\s+approve\s*\(", self.source))
        if has_approve and not has_permit:
            self.issues.append(ApprovalIssue(
                issue_type="no_permit",
                severity="INFO",
                line=0,
                spender="N/A",
                amount=None,
                message="Contract has approve() but no EIP-2612 permit() function",
                recommendation="Consider implementing permit() for gasless approvals",
            ))

    def _check_approval_in_loops(self) -> None:
        """Detect approvals inside loops — potential griefing."""
        in_loop = False
        for i, line in enumerate(self.lines, 1):
            if re.search(r"for\s*\(|while\s*\(", line):
                in_loop = True
            if in_loop and re.search(r"\.approve\s*\(", line):
                self.issues.append(ApprovalIssue(
                    issue_type="approval_in_loop",
                    severity="HIGH",
                    line=i,
                    spender="N/A",
                    amount=None,
                    message="Approval inside loop — potential gas griefing vector",
                    recommendation="Move approvals outside loops or use permit pattern",
                ))
            if in_loop and line.strip() == "}":
                in_loop = False

    def _check_event_emission(self) -> None:
        """Check if Approval events are properly emitted."""
        has_approval_event = bool(re.search(r"emit\s+Approval\s*\(", self.source))
        has_approve_func = bool(re.search(r"function\s+approve\s*\(", self.source))
        if has_approve_func and not has_approval_event:
            self.issues.append(ApprovalIssue(
                issue_type="missing_event",
                severity="MEDIUM",
                line=0,
                spender="N/A",
                amount=None,
                message="approve() function does not emit Approval event",
                recommendation="Emit Approval event per ERC-20 specification",
            ))

    def _extract_spender(self, line: str) -> str:
        """Extract spender address from approve call."""
        match = re.search(r"approve\s*\(\s*(\w+)", line)
        return match.group(1) if match else "unknown"

    def _get_recommendation(self, issue_type: str) -> str:
        """Get recommendation for issue type."""
        recs = {
            "unlimited_approval": "Use exact needed amount or permit2",
            "zero_address_check_missing": "Add require(spender != address(0))",
            "increaseAllowance_missing": "Use SafeERC20.safeIncreaseAllowance()",
            "return_value_unchecked": "Use SafeERC20.safeApprove() or check return",
        }
        return recs.get(issue_type, "Review approval pattern")

    def is_safe_approval_library_used(self) -> bool:
        """Check if SafeERC20 or similar is imported."""
        return any(re.search(p, self.source) for p in self.SAFE_APPROVAL_PATTERNS)
