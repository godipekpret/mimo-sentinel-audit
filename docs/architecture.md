# MiMo Sentinel Audit — Architecture Documentation

## Overview

MiMo Sentinel Audit is an AI-powered smart contract security auditing tool built for the MiMo 100T Token Creator Incentive Program. It combines traditional static analysis with MiMo's reasoning capabilities to provide comprehensive vulnerability detection and human-readable explanations.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Interface                            │
│                   CLI / Python API / Docker                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                     Core Audit Engine                            │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │
│  │  Static     │ │  Fuzzer    │ │  Exploit   │ │  Rugpull   │   │
│  │  Analyzer   │ │  Engine    │ │  Matcher   │ │  Detector  │   │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘ └──────┬─────┘   │
│         └───────────────┴──────────────┴──────────────┘          │
│                              │                                   │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │
│  │  Approval   │ │  Gas       │ │  Mempool   │ │  Cross     │   │
│  │  Scanner    │ │  Optimizer │ │  Monitor   │ │  Chain     │   │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘ └──────┬─────┘   │
│         └───────────────┴──────────────┴──────────────┘          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                    AI Reasoning Layer                             │
│  ┌────────────────────┐  ┌────────────────────┐                 │
│  │  MiMo Reasoning    │  │  Vulnerability     │                 │
│  │  Engine            │  │  Explainer         │                 │
│  └────────────────────┘  └────────────────────┘                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│                   Blockchain Interface                            │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐                   │
│  │  Web3      │ │  Rate      │ │  Config    │                   │
│  │  Client    │ │  Limiter   │ │  Manager   │                   │
│  └────────────┘ └────────────┘ └────────────┘                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌────▼────┐      ┌────▼────┐
    │Ethereum │      │  BSC    │      │Polygon  │
    │  Node   │      │  Node   │      │  Node   │
    └─────────┘      └─────────┘      └─────────┘
```

## Module Descriptions

### Static Analyzer (`analyzer.py`)
Performs regex-based pattern matching against 7+ vulnerability categories. Detects reentrancy, integer overflow, unchecked returns, tx.origin usage, and more.

### Fuzzer (`fuzzer.py`)
Property-based testing engine that generates random inputs for contract functions. Includes edge-case generation for uint256, addresses, and other Solidity types.

### Rugpull Detector (`rugpull_detector.py`)
Identifies common rugpull patterns including honeypots, hidden mint functions, fee manipulation, proxy patterns, and liquidity risks.

### Exploit Matcher (`exploit_matcher.py`)
Matches contract code against 10+ built-in exploit signatures (expandable to 500+). Categories include reentrancy, oracle manipulation, access control, and more.

### Mempool Monitor (`mempool_monitor.py`)
Real-time mempool monitoring for detecting sandwich attacks, frontrunning, and MEV extraction.

### Approval Scanner (`approval_scanner.py`)
Detects unlimited approvals, missing permit support, approval-in-loop patterns, and missing event emissions.

### Gas Optimizer (`gas_optimizer.py`)
Identifies gas optimization opportunities including storage reads in loops, custom error usage, calldata vs memory, and struct packing.

### Report Generator (`report_generator.py`)
Generates professional HTML and JSON audit reports with severity ratings, findings, and gas optimization suggestions.

### Cross-Chain Analyzer (`cross_chain.py`)
Analyzes contracts across Ethereum, BSC, Polygon, and Arbitrum. Detects cross-chain inconsistencies and proxy patterns.

### MiMo Reasoning Engine (`reasoning_engine.py`)
Chain-of-thought analysis engine that provides step-by-step vulnerability reasoning, exploit scenarios, and mitigation recommendations.

### Vulnerability Explainer (`vulnerability_explainer.py`)
Generates human-readable explanations with code examples, real-world incidents, and fix suggestions.

## Data Flow

1. **Input**: Solidity source code (file or verified contract address)
2. **Analysis**: All modules run in parallel on the source
3. **Reasoning**: MiMo AI processes findings for deeper analysis
4. **Reporting**: Results compiled into HTML/JSON report
5. **Output**: Report file + terminal summary

## Supported Chains

| Chain    | Chain ID | Avg Block Time |
|----------|----------|----------------|
| Ethereum | 1        | 12s            |
| BSC      | 56       | 3s             |
| Polygon  | 137      | 2s             |
| Arbitrum | 42161    | 0.25s          |
