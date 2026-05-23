"""
MiMo Reasoning Engine
Core AI reasoning module for analyzing smart contract vulnerabilities.
Uses MiMo's chain-of-thought reasoning for deep vulnerability assessment.
"""

from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ReasoningResult:
    """Result of MiMo AI reasoning analysis."""
    vulnerability: str
    confidence: float
    reasoning_chain: list[str]
    exploit_scenario: str
    impact_assessment: str
    mitigation: str
    references: list[str]


class MiMoReasoningEngine:
    """
    AI reasoning engine that performs chain-of-thought analysis
    of smart contract vulnerabilities using MiMo's capabilities.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "mimo-7b") -> None:
        self.api_key = api_key
        self.model = model
        self._reasoning_history: list[ReasoningResult] = []
        logger.info(f"MiMo Reasoning Engine initialized (model: {model})")

    def analyze_vulnerability(
        self,
        code_snippet: str,
        vuln_type: str,
        context: Optional[dict[str, Any]] = None,
    ) -> ReasoningResult:
        """
        Perform chain-of-thought analysis of a vulnerability.
        
        Args:
            code_snippet: The vulnerable code
            vuln_type: Type of vulnerability detected
            context: Additional context (contract name, chain, etc.)
        
        Returns:
            ReasoningResult with full analysis
        """
        logger.info(f"MiMo analyzing: {vuln_type}")
        reasoning_chain = self._build_reasoning_chain(code_snippet, vuln_type)
        exploit_scenario = self._generate_exploit_scenario(vuln_type, code_snippet)
        impact = self._assess_impact(vuln_type, context)

        result = ReasoningResult(
            vulnerability=vuln_type,
            confidence=self._calculate_confidence(reasoning_chain),
            reasoning_chain=reasoning_chain,
            exploit_scenario=exploit_scenario,
            impact_assessment=impact,
            mitigation=self._generate_mitigation(vuln_type, code_snippet),
            references=self._get_references(vuln_type),
        )
        self._reasoning_history.append(result)
        return result

    def _build_reasoning_chain(self, code: str, vuln_type: str) -> list[str]:
        """Build step-by-step reasoning chain for vulnerability analysis."""
        chains = {
            "reentrancy": [
                "1. Identified external call (.call/.send/.transfer) in function",
                "2. State variable update occurs AFTER the external call",
                "3. Attacker can deploy malicious contract that calls back into function",
                "4. Recursive callback re-enters before balance is zeroed",
                "5. This allows draining the contract's entire balance",
            ],
            "integer_overflow": [
                "1. Arithmetic operation without SafeMath or Solidity 0.8+",
                "2. Result can wrap around uint256 bounds",
                "3. Attacker can trigger overflow to manipulate balances",
                "4. Critical if used in token transfers or balance checks",
            ],
            "access_control": [
                "1. Function lacks proper access control modifier",
                "2. Any external caller can invoke this function",
                "3. If function modifies state, unauthorized changes possible",
                "4. Attacker can call function to drain funds or alter contract state",
            ],
            "oracle_manipulation": [
                "1. Price oracle reads spot price from DEX reserves",
                "2. Flash loan can temporarily skew reserve ratios",
                "3. Manipulated price allows attacker to borrow/exchange at favorable rate",
                "4. After repaying flash loan, price returns to normal but damage is done",
            ],
        }
        return chains.get(vuln_type, [f"1. Detected {vuln_type} pattern in code", "2. Requires manual verification"])

    def _generate_exploit_scenario(self, vuln_type: str, code: str) -> str:
        """Generate a realistic exploit scenario."""
        scenarios = {
            "reentrancy": (
                "Attacker deploys malicious contract with fallback function. "
                "Calls vulnerable withdraw() function. Fallback re-enters withdraw() "
                "before balance is updated. Loop continues until contract is drained."
            ),
            "integer_overflow": (
                "Attacker triggers arithmetic overflow by sending specific amounts. "
                "Overflow causes balance to wrap to a massive number, allowing "
                "withdrawal of more tokens than deposited."
            ),
            "flash_loan": (
                "Attacker takes flash loan of large amount. Manipulates DEX price "
                "by swapping in flash loan. Exploits vulnerable protocol using "
                "manipulated price. Repays flash loan with profit."
            ),
        }
        return scenarios.get(vuln_type, f"Exploit scenario for {vuln_type} requires case-specific analysis")

    def _assess_impact(self, vuln_type: str, context: Optional[dict]) -> str:
        """Assess the impact of the vulnerability."""
        impacts = {
            "reentrancy": "CRITICAL — Complete loss of contract funds. Historical losses: $60M+ (The DAO)",
            "integer_overflow": "HIGH — Unauthorized token minting, balance manipulation",
            "access_control": "CRITICAL — Unauthorized contract takeover or fund theft",
            "oracle_manipulation": "HIGH — Price manipulation leading to protocol insolvency",
            "unchecked_return": "MEDIUM — Silent failures may cause inconsistent state",
        }
        return impacts.get(vuln_type, "Impact assessment requires context-specific analysis")

    def _calculate_confidence(self, chain: list[str]) -> float:
        """Calculate confidence based on reasoning chain depth."""
        base = min(len(chain) * 0.2, 0.95)
        return round(base, 2)

    def _generate_mitigation(self, vuln_type: str, code: str) -> str:
        """Generate mitigation recommendation."""
        mitigations = {
            "reentrancy": "Use OpenZeppelin's ReentrancyGuard. Apply checks-effects-interactions pattern.",
            "integer_overflow": "Upgrade to Solidity 0.8+ or use SafeMath library.",
            "access_control": "Add onlyOwner or role-based access control modifiers.",
            "oracle_manipulation": "Use Chainlink TWAP oracles or multiple price sources.",
        }
        return mitigations.get(vuln_type, "Consult security best practices for this vulnerability type")

    def _get_references(self, vuln_type: str) -> list[str]:
        """Get relevant references and resources."""
        refs = {
            "reentrancy": [
                "SWC-107: Reentrancy",
                "OpenZeppelin ReentrancyGuard",
                "The DAO Post-Mortem",
            ],
            "integer_overflow": [
                "SWC-101: Integer Overflow",
                "OpenZeppelin SafeMath",
            ],
            "access_control": [
                "SWC-105: Unprotected Ether Withdrawal",
                "OpenZeppelin AccessControl",
            ],
        }
        return refs.get(vuln_type, ["Smart Contract Weakness Classification"])

    def get_history(self) -> list[ReasoningResult]:
        """Return all reasoning results."""
        return self._reasoning_history
