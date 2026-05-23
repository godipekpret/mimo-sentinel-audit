"""
Cross-Chain Analyzer
Supports multi-chain contract analysis across Ethereum, BSC, Polygon, and Arbitrum.
"""

from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


# Chain configuration
CHAIN_CONFIG: dict[str, dict] = {
    "ethereum": {
        "chain_id": 1,
        "rpc": "https://eth.llamarpc.com",
        "explorer": "https://api.etherscan.io/api",
        "native_token": "ETH",
        "avg_block_time": 12,
    },
    "bsc": {
        "chain_id": 56,
        "rpc": "https://bsc-dataseed.binance.org",
        "explorer": "https://api.bscscan.com/api",
        "native_token": "BNB",
        "avg_block_time": 3,
    },
    "polygon": {
        "chain_id": 137,
        "rpc": "https://polygon-rpc.com",
        "explorer": "https://api.polygonscan.com/api",
        "native_token": "MATIC",
        "avg_block_time": 2,
    },
    "arbitrum": {
        "chain_id": 42161,
        "rpc": "https://arb1.arbitrum.io/rpc",
        "explorer": "https://api.arbiscan.io/api",
        "native_token": "ETH",
        "avg_block_time": 0.25,
    },
}


@dataclass
class ChainContract:
    """Contract info from a specific chain."""
    chain: str
    address: str
    bytecode: str
    source_code: Optional[str]
    is_proxy: bool
    implementation: Optional[str]
    balance: int
    tx_count: int


@dataclass
class CrossChainResult:
    """Results of cross-chain analysis."""
    chains_checked: list[str]
    deployments: list[ChainContract]
    inconsistencies: list[str]
    risk_factors: list[str]


class CrossChainAnalyzer:
    """Analyzes contracts across multiple blockchain networks."""

    def __init__(self, chains: Optional[list[str]] = None) -> None:
        self.chains = chains or ["ethereum", "bsc", "polygon"]
        self._validate_chains()

    def _validate_chains(self) -> None:
        """Validate that all requested chains are supported."""
        for chain in self.chains:
            if chain not in CHAIN_CONFIG:
                raise ValueError(f"Unsupported chain: {chain}. Supported: {list(CHAIN_CONFIG.keys())}")

    async def analyze(self, address: str) -> CrossChainResult:
        """Analyze a contract address across all configured chains."""
        logger.info(f"Cross-chain analysis for {address} on {self.chains}")
        deployments: list[ChainContract] = []
        inconsistencies: list[str] = []

        tasks = [self._fetch_contract(chain, address) for chain in self.chains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for chain, result in zip(self.chains, results):
            if isinstance(result, Exception):
                logger.warning(f"Failed to fetch on {chain}: {result}")
                continue
            if result is not None:
                deployments.append(result)

        # Check for inconsistencies
        if len(deployments) > 1:
            bytecodes = set(d.bytecode[:100] for d in deployments)
            if len(bytecodes) > 1:
                inconsistencies.append("Different bytecodes deployed across chains")
            proxy_chains = [d.chain for d in deployments if d.is_proxy]
            if proxy_chains and len(proxy_chains) != len(deployments):
                inconsistencies.append("Proxy used on some chains but not all")

        risk_factors = self._assess_risks(deployments)

        return CrossChainResult(
            chains_checked=self.chains,
            deployments=deployments,
            inconsistencies=inconsistencies,
            risk_factors=risk_factors,
        )

    async def _fetch_contract(self, chain: str, address: str) -> Optional[ChainContract]:
        """Fetch contract details from a specific chain."""
        config = CHAIN_CONFIG[chain]
        try:
            # In production, use web3 + explorer API
            # This is a placeholder that demonstrates the structure
            logger.info(f"Fetching {address} from {chain}")
            return ChainContract(
                chain=chain,
                address=address,
                bytecode="0x6080604052...",
                source_code=None,
                is_proxy=False,
                implementation=None,
                balance=0,
                tx_count=0,
            )
        except Exception as e:
            logger.error(f"Error fetching from {chain}: {e}")
            return None

    def _assess_risks(self, deployments: list[ChainContract]) -> list[str]:
        """Assess cross-chain specific risks."""
        risks: list[str] = []
        if not deployments:
            risks.append("Contract not found on any chain")
            return risks

        for d in deployments:
            if d.is_proxy and not d.implementation:
                risks.append(f"{d.chain}: Proxy without verified implementation")
            if d.balance > 0 and d.tx_count < 10:
                risks.append(f"{d.chain}: Low activity but holds funds")

        if len(deployments) == 1:
            risks.append("Single-chain deployment — no cross-chain redundancy")

        return risks

    def get_chain_config(self, chain: str) -> dict:
        """Get configuration for a specific chain."""
        return CHAIN_CONFIG.get(chain, {})

    def supported_chains(self) -> list[str]:
        """Return list of supported chains."""
        return list(CHAIN_CONFIG.keys())
