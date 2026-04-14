# 🔐 Solidify - Web3 Smart Contract Security Auditor

> **Catch vulnerabilities before attackers do.**

Solidify is an AI-powered smart contract security auditor built for Web3 developers. Paste Solidity code, upload a `.sol` file, or scan any live on-chain contract — and get back a structured threat report with plain-English explanations, severity scores, and AI-generated secure patches.

Built at **GDG Abuja × Build with AI Sprint Hackathon** by Team Solidify.
ecosystem — Solidify hunts Web3.

---

## 🚨 The Problem

Millions of dollars are lost every year to preventable smart contract exploits. Traditional manual security auditing is expensive, slow, and inaccessible to early-stage Web3 projects and independent developers. Most emerging developers deploy contracts without any security review at all.

Solidify is the **first line of defense** every Web3 developer deserves.

---

## ✅ What Solidify Does

- 🔍 **Scans** Solidity contracts for known vulnerability patterns
- 🧠 **Explains** every risk in plain English — no security background required
- 🎯 **Scores** findings by severity: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`
- 🩹 **Patches** vulnerabilities with AI-generated secure code replacements
- 📄 **Exports** a professional PDF audit report with one click
- 🌐 **Scans live contracts** directly from a blockchain address

---

## 🎯 Three Input Modes

| Mode | How | What You Get |
|---|---|---|
| **Paste Code** | Drop Solidity into the editor | Instant audit + patch side-by-side |
| **Upload File** | Drag & drop `.sol` file | Full structured audit + PDF export |
| **On-Chain Scan** | Enter contract address | Fetch → audit → report from live chain |

---

## 🔌 Provider Integration

### Default Provider
- **Google Gemini** - Default AI provider for smart contract analysis

### BYOA (Bring Your Own API)
Users can connect their own API keys for:
- **Anthropic** - Claude models
- **OpenAI** - GPT models
- **NVIDIA** - NIM inference
- **Qwen** - Alibaba Qwen models
- **Ollama** - Open-source local models
- **Groq** - Fast inference
- **Google Vertex AI** - Google's enterprise AI

---

## 🏗️ Architecture

```
Frontend (React)
    │
    ▼
Backend (FastAPI + Python)
    │
    ▼
AI Provider Layer (Gemini Default + BYOA)
    │
    ▼
Etherscan / Sourcify / RPC (on-chain mode)
```

---

## 🔬 40-Feature Roadmap

### 🔴 Critical Features (MVP)

| # | Feature | Description |
|---|---------|-------------|
| 01 | **Core Solidity Audit Engine** | Send any Solidity contract to Gemini via structured prompt. Returns full JSON audit with vulnerability breakdown. |
| 02 | **Severity Classification + CVSS Scoring** | Every vulnerability gets CVSS 3.1 score (0.0–10.0) and severity badge: CRITICAL / HIGH / MEDIUM / LOW. |
| 03 | **Side-by-Side Patch Generation** | For every vuln, returns original vulnerable snippet AND corrected secure replacement. |
| 04 | **File Upload Audit (.sol)** | Drag-and-drop `.sol` file. Backend extracts source and passes through audit engine. |
| 05 | **On-Chain Contract Scan (Etherscan)** | Input contract address → fetches verified source from Etherscan API → audits live contract. |
| 06 | **PDF Audit Report Export** | One-click PDF export with cover page, executive summary, vulnerability table, code diffs. |

### 🟠 High Priority Features

| # | Feature | Description |
|---|---------|-------------|
| 07 | **Multi-Vulnerability Chaining Detection** | Detects when vulnerabilities can be chained together for amplified impact. |
| 08 | **Proof-of-Concept Exploit Generation** | For HIGH/CRITICAL vulns, generates working Solidity PoC exploit contract. |
| 09 | **Reentrancy Attack Simulation** | Dedicated reentrancy scanner with PoC attacker contract generation. |
| 10 | **Integer Overflow/Underflow PoC** | Detects unchecked arithmetic, generates PoC for overflow exploitation. |
| 11 | **Access Control Bypass PoC** | Identifies missing `onlyOwner`, broken role guards, generates calldata for exploitation. |
| 12 | **Flash Loan Attack Surface Detection** | Scans oracle dependencies, single-block manipulation points for flash loan exploits. |
| 13 | **Multi-Chain Support** | BSC, Polygon, Arbitrum, Base - routes to correct block explorer API per chain. |
| 14 | **DeFi Protocol Pattern Recognition** | Recognizes AMM, lending protocols, yield farming patterns. Applies protocol-specific checks. |
| 15 | **NFT Contract Audit Mode** | ERC-721/ERC-1155 audit: metadata manipulation, royalty bypass, unrestricted mint. |
| 16 | **Audit History + Session Memory** | Stores past audits, users can revisit, compare, and track fixes. |
| 17 | **Natural Language Audit Query** | Ask plain English: "Is this safe to deploy?", "What's the worst vulnerability?" |
| 18 | **Vulnerability Confidence Scoring** | AI confidence percentage (0–100%) for each finding. Flags confirmed/likely/false positive. |

### 🟡 Medium Priority Features

| # | Feature | Description |
|---|---------|-------------|
| 19 | **Gas Optimization Analysis** | Identifies gas inefficiencies, redundant storage reads, unoptimized loops. |
| 20 | **Front-Running Attack Detection + PoC** | Identifies mempool front-running vulnerable functions, generates PoC. |
| 21 | **Sandwich Attack Surface Scanner** | Detects DEX swap functions vulnerable to sandwich attacks. |
| 22 | **Oracle Manipulation Detection** | Flags on-chain spot price usage, shows flash loan price manipulation. |
| 23 | **Price Manipulation PoC Generator** | Generates multi-step price manipulation attack with full Solidity PoC. |
| 24 | **Upgradeable Proxy Pattern Audit** | Audits UUPS, Transparent, Beacon proxies for storage collision, initialization flaws. |
| 25 | **Governance Attack Surface Detection** | Scans DAO governance for flash loan voting, proposal spam, timelock bypass. |
| 26 | **Token Economics Vulnerability Scan** | Analyzes unlimited mint, broken burn, fee-on-transfer, rebase token issues. |
| 27 | **Cross-Contract Interaction Analysis** | Traces external calls, flags trust assumptions, reentrancy across contract boundaries. |
| 28 | **Sourcify + IPFS Source Verification** | Falls back to Sourcify's decentralized source registry, IPFS metadata lookup. |
| 29 | **Foundry/Hardhat Test Case Generator** | Generates failing test cases in Foundry or Hardhat format. |
| 30 | **Markdown Audit Report Export** | Export as clean `.md` file for GitHub issues, security disclosure. |
| 31 | **Contract Diff Auditor** | Upload two versions → diffs → audits delta → flags new vulnerabilities. |
| 32 | **Real-Time Audit Streaming (SSE)** | Stream findings in real-time via Server-Sent Events. |
| 33 | **Multi-File / Multi-Contract Project Audit** | Upload `.zip` of Hardhat/Foundry project, audits entire codebase. |
| 34 | **ERC Standard Compliance Check** | Validates ERC-20, ERC-721, ERC-1155 interface implementations. |
| 35 | **On-Chain Transaction History Risk Scan** | Fetches recent tx history, flags unusual patterns, known attacker addresses. |
| 36 | **Wallet Drainer Pattern Detection** | Identifies `setApprovalForAll` abuse, `permit` signature phishing patterns. |

### 🟢 Roadmap Features

| # | Feature | Description |
|---|---------|-------------|
| 37 | **Audit REST API** | Public API key-gated endpoint for external tool integration. |
| 38 | **VS Code Extension** | Audit Solidity directly in VS Code with inline annotations. |
| 39 | **CI/CD Pipeline Integration** | GitHub Action runs Solidify on every PR, fails on CRITICAL/HIGH. |
| 40 | **Solidify Agent Mode** | Fully autonomous: discovers contracts, audits each, chains findings, produces ecosystem report. |

---

## 🧬 Vulnerability Coverage

| Vulnerability | Severity |
|---|---|
| Reentrancy | 🔴 CRITICAL |
| Integer Overflow / Underflow | 🟠 HIGH |
| Access Control Flaws | 🟠 HIGH |
| Unchecked External Calls | 🟠 HIGH |
| Flash Loan Attack Surface | 🟠 HIGH |
| tx.origin Authentication | 🟡 MEDIUM |
| Front-Running Exposure | 🟡 MEDIUM |
| Timestamp Dependence | 🟡 MEDIUM |
| Uninitialized Storage Pointers | 🟠 HIGH |
| Self-destruct Abuse | 🔴 CRITICAL |
| Denial of Service (Gas Griefing) | 🟡 MEDIUM |
| Wallet Drainer Patterns | 🟠 HIGH |

---

## 📁 Project Structure

```
solidify/
├── backend/                          # FastAPI backend (10 files)
├── frontend/                         # React frontend
│   ├── src/
│   │   ├── components/               # UI Components
│   │   ├── App.jsx
│   │   └── api.js
│   └── package.json
│
├── runtime/                          # Process layer (9 files)
├── integrations/                     # LLM + tool bridges (9 files)
├── memory/                           # Memory management (8 files)
├── storage/                          # Storage layer (9 files)
├── validations/                      # Validation logic (8 files)
├── sessions/                         # Session management (9 files)
├── commands/                         # Command handlers (9 files)
├── exploitation/                     # Web3 exploitation (9 files)
├── reports/                          # Report generation (9 files)
├── chains/                           # Multi-step audit chains (8 files)
├── core/                             # Orchestration (8 files)
├── tools/                            # Tool definitions (8 files)
├── providers/                        # Provider specs (12 files)
├── config/                           # Configuration files (8 JSON)
├── rules/                            # Detection rules (9 MD files)
├── models/                           # Model definitions (8 files)
├── hunts/                            # Offensive operation specs (2 files)
├── severity/                         # Scoring + triage (8 files)
├── recon/                            # Recon pipeline (8 files)
├── audit-engine/                     # Smart contract audit engine (9 files)
├── solidity-analysis/               # Solidity analysis (8 files)
├── vuln-detection/                  # Vulnerability detection (8 files)
├── hooks/                            # Hook specs (9 files)
├── mcp/                              # MCP protocol (9 files)
├── skills/                           # Skill definitions (9 files)
├── system-prompt/                    # System prompts (8 files)
├── tasks/                            # Task definitions (8 files)
├── context-management/              # Context management (9 files)
├── task-persistence/                # Task persistence (9 files)
├── blockchain/                       # Blockchain integration (8 files)
│
├── prompts/                          # Gemini prompts (3 MD)
├── sample_contracts/                # Demo Solidity contracts (3 files)
├── docs/
├── team.md                           # Team information
├── team-tasks.md                     # Task assignments
├── features.md                       # 40-Feature Roadmap
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- Gemini API key ([Get one free](https://aistudio.google.com))
- Etherscan API key ([Get one free](https://etherscan.io/apis))

### 1. Clone
```bash
git clone https://github.com/Lifejiggy/solidify.git
cd solidify
```

### 2. Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Add your GEMINI_API_KEY and ETHERSCAN_API_KEY to .env
uvicorn main:app --reload
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

### 4. Open
```
http://localhost:5173
```

---

## 🔑 Environment Variables

```env
# Default Provider (Gemini)
GEMINI_API_KEY=your_gemini_key_here

# BYOA Providers (Optional)
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENAI_API_KEY=your_openai_key_here
NVIDIA_API_KEY=your_nvidia_key_here
QWEN_API_KEY=your_qwen_key_here
OLLAMA_BASE_URL=http://localhost:11434
GROQ_API_KEY=your_groq_key_here
GOOGLE_VERTEX_PROJECT=your_project
GOOGLE_VERTEX_LOCATION=us-central1

# Blockchain
ETHERSCAN_API_KEY=your_etherscan_key_here
SOURCIFY_API_URL=https://repo.sourcify.dev

# App Config
ENVIRONMENT=development
PORT=8000
CORS_ORIGINS=http://localhost:5173
```

---

## 📦 Dependencies

### Backend
```
fastapi
uvicorn
google-generativeai
python-multipart
reportlab
httpx
python-dotenv
```

### Frontend
```
react + vite
axios
@monaco-editor/react
```

---

## 👥 Team Solidify

| Name | Role | Focus | Email |
|------|------|-------|-------|
| **Peace Stephen** | Tech Lead | AI/LLM, Backend, Runtime, Integrations | Bloomtonjovish@gmail.com |
| **Joel Emmanuel Adinoyi** | Security Lead | Vuln Detection, Blockchain, Solidity Analysis | adinoyijoel1@gmail.com |
| **Mayowa Sunusi** | Frontend Lead | UI/UX, React Components, Reports | mayowa.u.sunusi@gmail.com |
| **Yusuf Sanusi** | Frontend Dev | API Integration, Tools, Providers | suleimain.onimisi@gmail.com |
| **Abubakar Adamu** | Product/QA | Documentation, Validation, Testing, Config | abubakaradamuibrahim2022@gmail.com |

### Team Task Distribution

| Member | Primary Modules |
|--------|----------------|
| **Peace** | backend, runtime, core, integrations, system-prompt, models, providers |
| **Joel** | vuln-detection, blockchain, solidity-analysis, audit-engine, chains, exploitation |
| **Mayowa** | frontend/components, reports, severity |
| **Yusuf** | frontend/api, tools,, sessions, tasks |
| **Abubakar** | config, validations, storage, context-management, task-persistence, docs, rules |

---

## ⚠️ Disclaimer

Solidify is a security research and educational tool. All exploit generation features are intended for use within **authorized scope only** — on contracts you own, have written, or have explicit permission to test. The  team assumes no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](./LICENSE)

---

*Built with 🔐 by Team Solidify | GDG Abuja × Build with AI Sprint*
*Solidify v1.0 Roadmap | MVP + 40 Features*
