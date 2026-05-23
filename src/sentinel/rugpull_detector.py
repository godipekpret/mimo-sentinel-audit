"""
Rugpull Detector
Identifies honeypot, hidden mint, fee manipulation, and other rugpull patterns.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class RugpullSignal:
    """A detected rugpull indicator."""
    signal_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    evidence: str
    line: int = 0


class RugpullDetector:
    """Detects common rugpull patterns in Solidity contracts."""

    # Patterns that indicate hidden owner-only functions
    HONEYPOT_PATTERNS = [
        (r"require\s*\(\s*msg\.sender\s*==\s*owner", "owner_gated_transfer"),
        (r"_balances\[.*\]\s*=\s*0\s*;", "balance_zeroing"),
        (r"blacklist|isBlackListed|_isExcluded", "blacklist_mechanism"),
        (r"tx\.origin\s*==\s*", "tx_origin_check"),
    ]

    HIDDEN_MINT_PATTERNS = [
        (r"function\s+mint\s*\([^)]*\)[^{]*(public|external)", "public_mint"),
        (r"_totalSupply\s*\+=|totalSupply\s*\+=\s*", "supply_modification"),
        (r"hiddenMint|shadowMint|_mint", "hidden_mint_function"),
    ]

    FEE_PATTERNS = [
        (r"fee\s*[><=]|setFee|_fee\s*=\s*[0-9]", "fee_manipulation"),
        (r"buyFee|sellFee|transferFee", "split_fees"),
        (r"maxFee|MAX_FEE", "fee_cap"),
        (r"require\s*\(\s*.*[Ff]ee\s*<=?\s*[0-9]", "fee_limit"),
    ]

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.signals: list[RugpullSignal] = []

    def analyze(self) -> list[RugpullSignal]:
        """Run all rugpull detection checks."""
        logger.info("Running rugpull detection analysis")
        self._check_honeypot()
        self._check_hidden_mint()
        self._check_fee_manipulation()
        self._check_proxy_patterns()
        self._check_liquidity_risks()
        self.signals.sort(key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(s.severity))
        logger.info(f"Rugpull scan complete: {len(self.signals)} signals found")
        return self.signals

    def _check_honeypot(self) -> None:
        """Detect honeypot patterns — tokens that can't be sold."""
        for i, line in enumerate(self.lines, 1):
            for pattern, name in self.HONEYPOT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.signals.append(RugpullSignal(
                        signal_type=name,
                        severity="CRITICAL" if "blacklist" in name else "HIGH",
                        description=f"Honeypot indicator: {name}",
                        evidence=line.strip(),
                        line=i,
                    ))

    def _check_hidden_mint(self) -> None:
        """Detect hidden or unrestricted mint functions."""
        for i, line in enumerate(self.lines, 1):
            for pattern, name in self.HIDDEN_MINT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = "CRITICAL" if "hidden" in name else "HIGH"
                    self.signals.append(RugpullSignal(
                        signal_type=name,
                        severity=severity,
                        description=f"Minting risk: {name}",
                        evidence=line.strip(),
                        line=i,
                    ))

    def _check_fee_manipulation(self) -> None:
        """Detect fee structures that can be manipulated."""
        has_fee_cap = bool(re.search(r"MAX_FEE|maxFee", self.source))
        for i, line in enumerate(self.lines, 1):
            for pattern, name in self.FEE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = "MEDIUM" if has_fee_cap else "HIGH"
                    self.signals.append(RugpullSignal(
                        signal_type=name,
                        severity=severity,
                        description=f"Fee manipulation risk: {name}",
                        evidence=line.strip(),
                        line=i,
                    ))

    def _check_proxy_patterns(self) -> None:
        """Detect upgradeable proxy patterns that could be exploited."""
        proxy_indicators = [
            (r"delegatecall", "delegatecall_usage"),
            (r"upgradeTo|upgradeToAndCall", "upgradeable_proxy"),
            (r"implementation\(\)", "proxy_implementation"),
        ]
        for i, line in enumerate(self.lines, 1):
            for pattern, name in proxy_indicators:
                if re.search(pattern, line):
                    self.signals.append(RugpullSignal(
                        signal_type=name,
                        severity="MEDIUM",
                        description=f"Proxy pattern: {name} — contract logic can be replaced",
                        evidence=line.strip(),
                        line=i,
                    ))

    def _check_liquidity_risks(self) -> None:
        """Detect liquidity removal or manipulation patterns."""
        liq_patterns = [
            (r"removeLiquidity|withdrawLiquidity", "liquidity_removal"),
            (r"addLiquidity.*onlyOwner", "owner_only_liquidity"),
            (r"tradingOpen\s*=\s*false|tradingEnabled\s*=\s*false", "trading_toggle"),
        ]
        for i, line in enumerate(self.lines, 1):
            for pattern, name in liq_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.signals.append(RugpullSignal(
                        signal_type=name,
                        severity="HIGH",
                        description=f"Liquidity risk: {name}",
                        evidence=line.strip(),
                        line=i,
                    ))

    def risk_score(self) -> int:
        """Calculate overall rugpull risk score (0-100)."""
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        score = sum(weights.get(s.severity, 0) for s in self.signals)
        return min(score, 100)
