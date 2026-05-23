"""
Web3 Client
Blockchain interaction layer for contract fetching and transaction analysis.
"""

from __future__ import annotations
from typing import Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)


class Web3Client:
    """Web3 client for blockchain interactions."""

    def __init__(self, rpc_url: str, chain: str = "ethereum") -> None:
        self.rpc_url = rpc_url
        self.chain = chain
        self._w3 = None
        self._connected = False

    def connect(self) -> bool:
        """Establish connection to blockchain node."""
        try:
            from web3 import Web3
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self._connected = self._w3.is_connected()
            if self._connected:
                logger.info(f"Connected to {self.chain} at {self.rpc_url[:50]}...")
            else:
                logger.warning(f"Failed to connect to {self.chain}")
            return self._connected
        except ImportError:
            logger.warning("web3 not installed — using mock mode")
            self._connected = False
            return False

    def get_contract_code(self, address: str) -> Optional[str]:
        """Fetch contract bytecode from blockchain."""
        if not self._connected or self._w3 is None:
            logger.warning("Not connected — returning None")
            return None
        try:
            code = self._w3.eth.get_code(address)
            return code.hex()
        except Exception as e:
            logger.error(f"Failed to get code for {address}: {e}")
            return None

    def get_contract_source(self, address: str, api_key: Optional[str] = None) -> Optional[str]:
        """Fetch verified source code from block explorer."""
        import requests
        explorers = {
            "ethereum": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}",
            "bsc": f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={address}",
            "polygon": f"https://api.polygonscan.com/api?module=contract&action=getsourcecode&address={address}",
        }
        url = explorers.get(self.chain)
        if not url:
            logger.warning(f"No explorer API for {self.chain}")
            return None
        if api_key:
            url += f"&apikey={api_key}"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("status") == "1" and data["result"][0].get("SourceCode"):
                return data["result"][0]["SourceCode"]
            return None
        except Exception as e:
            logger.error(f"Explorer API error: {e}")
            return None

    def get_transaction(self, tx_hash: str) -> Optional[dict]:
        """Fetch transaction details."""
        if not self._connected or self._w3 is None:
            return None
        try:
            tx = self._w3.eth.get_transaction(tx_hash)
            return dict(tx)
        except Exception as e:
            logger.error(f"Failed to get tx {tx_hash}: {e}")
            return None

    def get_block(self, block_id: str = "latest", full: bool = False) -> Optional[dict]:
        """Fetch block data."""
        if not self._connected or self._w3 is None:
            return None
        try:
            block = self._w3.eth.get_block(block_id, full_transactions=full)
            return dict(block)
        except Exception as e:
            logger.error(f"Failed to get block: {e}")
            return None

    def estimate_gas(self, to: str, data: str, value: int = 0) -> Optional[int]:
        """Estimate gas for a transaction."""
        if not self._connected or self._w3 is None:
            return None
        try:
            return self._w3.eth.estimate_gas({
                "to": to,
                "data": data,
                "value": value,
            })
        except Exception as e:
            logger.error(f"Gas estimation failed: {e}")
            return None

    @property
    def is_connected(self) -> bool:
        return self._connected
