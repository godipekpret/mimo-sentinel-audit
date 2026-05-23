# 🛡️ MiMo Sentinel Audit

**AI-Powered Smart Contract Security Auditor** — Built with MiMo Reasoning Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MiMo 100T](https://img.shields.io/badge/MiMo-100T%20Project-green.svg)](https://github.com/XiaomiMiMo)

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MiMo Sentinel Audit                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Analyzer │  │  Fuzzer  │  │ Rugpull  │  │ Mempool  │   │
│  │  Engine  │  │  Engine  │  │ Detector │  │ Monitor  │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│       └──────────────┴──────────────┴──────────────┘         │
│                          │                                   │
│                   ┌──────▼──────┐                            │
│                   │  MiMo AI    │                            │
│                   │  Reasoning  │                            │
│                   │  Engine     │                            │
│                   └──────┬──────┘                            │
│                          │                                   │
│  ┌──────────┐  ┌────────▼────────┐  ┌──────────────────┐   │
│  │  Gas     │  │   Report        │  │  Cross-Chain     │   │
│  │Optimizer │  │   Generator     │  │  Analysis        │   │
│  └──────────┘  └─────────────────┘  └──────────────────┘   │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Web3 Client / Blockchain Interface       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Features

- **Static Analysis** — Deep code inspection for known vulnerability patterns
- **Fuzzing Engine** — Property-based testing with randomized inputs
- **Rugpull Detection** — Identifies honeypot, hidden mint, and fee manipulation
- **Mempool Monitoring** — Real-time transaction monitoring for frontrunning
- **Approval Scanner** — Detects unlimited token approvals and revoke risks
- **Exploit Matcher** — Pattern matching against 500+ known exploits
- **Gas Optimization** — Suggests gas-efficient code alternatives
- **MiMo AI Reasoning** — Natural language vulnerability explanations
- **Cross-Chain Analysis** — Supports Ethereum, BSC, Polygon, Arbitrum
- **HTML Reports** — Professional audit reports with severity ratings

## 📋 Requirements

- Python 3.10+
- Node.js 18+ (for Hardhat integration)
- Docker (optional)

## ⚡ Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/dpk-jr/mimo-sentinel-audit.git
cd mimo-sentinel-audit

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env
# Edit .env with your RPC endpoints
```

### Run an Audit

```bash
# Audit a single contract
python -m sentinel audit examples/vulnerable_token.sol

# Audit with specific checks
python -m sentinel audit contract.sol --checks rugpull,overflow,approval

# Generate HTML report
python -m sentinel audit contract.sol --output report.html --format html

# Monitor mempool
python -m sentinel monitor --chain ethereum --duration 3600
```

### Docker

```bash
docker-compose up --build
docker run sentinel-audit audit /contracts/token.sol
```

## 🔍 Supported Vulnerability Types

| Category | Vulns Detected |
|----------|---------------|
| Reentrancy | Single, Cross-function, Cross-contract |
| Integer | Overflow, Underflow, Truncation |
| Access Control | Missing modifiers, Unprotected functions |
| Rugpull | Honeypot, Hidden mint, Fee manipulation |
| Flash Loan | Price manipulation, Oracle attacks |
| Approval | Unlimited allowance, Race conditions |
| Gas Griefing | Unbounded loops, Storage patterns |
| Front-running | MEV exposure, Transaction ordering |

## 📊 Example Output

```
🛡️  MiMo Sentinel Audit v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target: 0x7af6...D8f69A | Chain: Ethereum

[CRITICAL] Reentrancy in withdraw() — Line 47
  └─ MiMo: External call before state update enables recursive drain

[HIGH] Unlimited approval in approve() — Line 89
  └─ MiMo: Consider using approve(0) pattern or permit2

[MEDIUM] Centralized owner can pause transfers — Line 12
  └─ MiMo: Add timelock or multi-sig for pause functionality

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Report: sentinel_report_2026.html | Score: 34/100
```

## 📁 Project Structure

```
mimo-sentinel-audit/
├── src/
│   ├── sentinel/          # Core audit engine
│   │   ├── analyzer.py    # Static analysis engine
│   │   ├── fuzzer.py      # Property-based fuzzer
│   │   ├── rugpull_detector.py
│   │   ├── mempool_monitor.py
│   │   ├── approval_scanner.py
│   │   ├── exploit_matcher.py
│   │   ├── gas_optimizer.py
│   │   ├── report_generator.py
│   │   └── cross_chain.py
│   ├── ai/                # MiMo AI reasoning
│   │   ├── reasoning_engine.py
│   │   └── vulnerability_explainer.py
│   └── utils/             # Utilities
│       ├── web3_client.py
│       ├── config.py
│       ├── logger.py
│       └── rate_limiter.py
├── tests/                 # Test suite
├── examples/              # Sample contracts
├── docs/                  # Documentation
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 🤖 MiMo AI Integration

MiMo Sentinel uses the MiMo reasoning engine to:
- Explain vulnerabilities in natural language
- Suggest specific code fixes with context
- Assess exploit likelihood based on market conditions
- Generate human-readable audit reports

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built for the **MiMo 100T Token Creator Incentive Program**
- Powered by **Xiaomi MiMo** reasoning capabilities
- Inspired by Slither, Mythril, and Securify
