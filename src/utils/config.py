"""
Configuration Manager
Handles loading and validating configuration from environment and files.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """Application configuration."""
    # RPC endpoints
    ethereum_rpc: str = "https://eth.llamarpc.com"
    bsc_rpc: str = "https://bsc-dataseed.binance.org"
    polygon_rpc: str = "https://polygon-rpc.com"
    arbitrum_rpc: str = "https://arb1.arbitrum.io/rpc"

    # API keys
    etherscan_api_key: Optional[str] = None
    bscscan_api_key: Optional[str] = None
    mimo_api_key: Optional[str] = None

    # Scanner settings
    max_iterations: int = 1000
    scan_timeout: int = 300
    output_format: str = "html"
    output_dir: str = "./reports"

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    @classmethod
    def from_env(cls, env_path: Optional[str] = None) -> Config:
        """Load config from environment variables and .env file."""
        if env_path and Path(env_path).exists():
            cls._load_dotenv(env_path)

        return cls(
            ethereum_rpc=os.getenv("ETHEREUM_RPC", cls.ethereum_rpc),
            bsc_rpc=os.getenv("BSC_RPC", cls.bsc_rpc),
            polygon_rpc=os.getenv("POLYGON_RPC", cls.polygon_rpc),
            arbitrum_rpc=os.getenv("ARBITRUM_RPC", cls.arbitrum_rpc),
            etherscan_api_key=os.getenv("ETHERSCAN_API_KEY"),
            bscscan_api_key=os.getenv("BSCSCAN_API_KEY"),
            mimo_api_key=os.getenv("MIMO_API_KEY"),
            max_iterations=int(os.getenv("MAX_ITERATIONS", "1000")),
            scan_timeout=int(os.getenv("SCAN_TIMEOUT", "300")),
            output_format=os.getenv("OUTPUT_FORMAT", "html"),
            output_dir=os.getenv("OUTPUT_DIR", "./reports"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_file=os.getenv("LOG_FILE"),
        )

    @staticmethod
    def _load_dotenv(path: str) -> None:
        """Manually load .env file (no python-dotenv dependency)."""
        try:
            for line in Path(path).read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    os.environ.setdefault(key, value)
        except Exception:
            pass

    def get_rpc_url(self, chain: str) -> str:
        """Get RPC URL for a specific chain."""
        rpcs = {
            "ethereum": self.ethereum_rpc,
            "bsc": self.bsc_rpc,
            "polygon": self.polygon_rpc,
            "arbitrum": self.arbitrum_rpc,
        }
        return rpcs.get(chain, self.ethereum_rpc)

    def validate(self) -> list[str]:
        """Validate configuration and return list of warnings."""
        warnings = []
        if not self.etherscan_api_key:
            warnings.append("ETHERSCAN_API_KEY not set — explorer lookups will be limited")
        if self.max_iterations < 100:
            warnings.append("MAX_ITERATIONS is very low — may miss edge cases")
        if not Path(self.output_dir).exists():
            warnings.append(f"Output directory {self.output_dir} does not exist")
        return warnings

    def __repr__(self) -> str:
        return f"Config(chain=ethereum, format={self.output_format}, level={self.log_level})"
