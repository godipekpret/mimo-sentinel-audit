"""
Mempool Monitor
Real-time transaction monitoring for detecting frontrunning, sandwich attacks, and MEV.
"""

from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PendingTx:
    """Represents a pending mempool transaction."""
    hash: str
    from_addr: str
    to_addr: str
    value: int
    gas_price: int
    data: str
    timestamp: float = field(default_factory=time.time)

    def is_swap(self) -> bool:
        """Check if transaction is a DEX swap (Uniswap/SushiSwap selector)."""
        swap_selectors = ["0x38ed1739", "0x7ff36ab5", "0x18cbafe5", "0xfb3bdb41"]
        return self.data[:10] in swap_selectors

    def is_approval(self) -> bool:
        """Check if transaction is a token approval."""
        return self.data[:10] == "0x095ea7b3"


@dataclass
class MEVDetection:
    """Detected MEV activity."""
    attack_type: str
    victim_tx: str
    attacker_tx: str
    profit_estimate: float
    confidence: float


class MempoolMonitor:
    """Monitors the mempool for suspicious transaction patterns."""

    def __init__(self, w3_client=None, chain: str = "ethereum") -> None:
        self.w3 = w3_client
        self.chain = chain
        self.pending: dict[str, PendingTx] = {}
        self.detections: list[MEVDetection] = []
        self._running = False
        self._sandwich_window: dict[str, list[PendingTx]] = {}

    async def start_monitoring(self, duration: int = 3600) -> None:
        """Start monitoring mempool for given duration in seconds."""
        logger.info(f"Starting mempool monitor on {self.chain} for {duration}s")
        self._running = True
        start = time.time()

        while self._running and (time.time() - start) < duration:
            try:
                pending_txs = await self._fetch_pending()
                for tx in pending_txs:
                    self._analyze_transaction(tx)
                    self._detect_sandwich(tx)
                    self._detect_frontrun(tx)
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                await asyncio.sleep(1)

        self._running = False
        logger.info(f"Monitor stopped. {len(self.detections)} MEV events detected")

    def stop(self) -> None:
        """Stop the mempool monitor."""
        self._running = False

    async def _fetch_pending(self) -> list[PendingTx]:
        """Fetch pending transactions from the node."""
        if self.w3 is None:
            return []
        try:
            block = self.w3.eth.get_block("pending", full_transactions=True)
            txs = []
            for tx in block.transactions:
                txs.append(PendingTx(
                    hash=tx.hash.hex(),
                    from_addr=tx["from"],
                    to_addr=tx.get("to", ""),
                    value=tx["value"],
                    gas_price=tx["gasPrice"],
                    data=tx["input"].hex()[:200],
                ))
            return txs
        except Exception as e:
            logger.warning(f"Failed to fetch pending txs: {e}")
            return []

    def _analyze_transaction(self, tx: PendingTx) -> None:
        """Analyze a single transaction for suspicious patterns."""
        if tx.is_swap():
            self._sandwich_window.setdefault(tx.to_addr, []).append(tx)
            # Clean old entries (>30s)
            cutoff = time.time() - 30
            self._sandwich_window[tx.to_addr] = [
                t for t in self._sandwich_window[tx.to_addr] if t.timestamp > cutoff
            ]

    def _detect_sandwich(self, tx: PendingTx) -> None:
        """Detect sandwich attack patterns."""
        target_pool = tx.to_addr
        if target_pool not in self._sandwich_window:
            return
        window = self._sandwich_window[target_pool]
        if len(window) < 3:
            return
        # Check for same attacker, high gas price ordering
        for i in range(len(window) - 2):
            front, victim, back = window[i], window[i+1], window[i+2]
            if (front.from_addr == back.from_addr and
                front.gas_price > victim.gas_price and
                back.gas_price > victim.gas_price):
                self.detections.append(MEVDetection(
                    attack_type="sandwich",
                    victim_tx=victim.hash,
                    attacker_tx=front.hash,
                    profit_estimate=0.0,
                    confidence=0.85,
                ))
                logger.warning(f"Sandwich detected: attacker={front.from_addr[:10]}...")

    def _detect_frontrun(self, tx: PendingTx) -> None:
        """Detect frontrunning by gas price analysis."""
        if not tx.is_swap():
            return
        for pool_txs in self._sandwich_window.values():
            for other in pool_txs:
                if (other.hash != tx.hash and
                    other.to_addr == tx.to_addr and
                    other.from_addr != tx.from_addr and
                    tx.gas_price > other.gas_price * 1.1):
                    self.detections.append(MEVDetection(
                        attack_type="frontrun",
                        victim_tx=other.hash,
                        attacker_tx=tx.hash,
                        profit_estimate=0.0,
                        confidence=0.6,
                    ))

    def get_detections(self) -> list[MEVDetection]:
        """Return all detected MEV events."""
        return self.detections
