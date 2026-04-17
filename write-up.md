# 🔐 Solidify — Final Foundation Document
**GDG Abuja × Build with AI Sprint Hackathon**
**Tech Lead: Peace Stephen (ArkhAngelLifeJiggy)**
**Security Lead: Joel Emmanuel Adinoyi**

---

## 🧠 Project Identity

**Name:** Solidify
**Tagline:** *"Catch vulnerabilities before attackers do."*
**Category:** AI-Powered Web3 Security Tool
**Stack:** Gemini API + Python (FastAPI) + React

---

## 🚨 Problem Statement

Many emerging developers struggle to identify complex vulnerabilities in smart contracts prior to deployment, leading to catastrophic and costly exploits. Traditional manual security auditing is highly expensive and slow, leaving early-stage Web3 projects and independent developers vulnerable.

### Why This Matters
Security is currently the biggest bottleneck in the blockchain space. Millions of dollars are lost annually to preventable code exploits. Providing an accessible, fast, and accurate "first-line-of-defense" security tool empowers developers to build safer decentralized applications and fosters greater trust in the ecosystem.

---

## ✅ Proposed Solution

A **web-based AI smart contract analyzer**. Developers paste, upload, or provide a contract address — and Solidify acts as an automated security researcher.

It will:
- Scan Solidity code for known vulnerability patterns
- Explain each risk in plain English
- Categorize findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Generate secure code snippet replacements side-by-side with the original
- Export a structured audit report as PDF

---

## 🎯 MVP Demo Targets (Saturday)

| # | Feature | Input | Output |
|---|---|---|---|
| 1 | **Code Paste Audit** | Raw Solidity in browser editor | Structured vuln report + patch suggestions |
| 2 | **File Upload Audit** | `.sol` file upload | Full audit + downloadable PDF report |
| 3 | **On-chain Scan** | Contract address (Ethereum/BSC) | Fetched source → audit → report |

> All three input modes feed the same Gemini audit pipeline. The interface adapts the input method only.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────┐
│             FRONTEND (React)            │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ Code Editor │  │   File Uploader  │  │
│  │  (paste)    │  │   (.sol input)   │  │
│  └─────────────┘  └──────────────────┘  │
│         ┌──────────────────┐            │
│         │  Address Input   │            │
│         │  (on-chain scan) │            │
│         └──────────────────┘            │
│              Audit Dashboard            │
│         (side-by-side diff view)        │
└──────────────────┬──────────────────────┘
                   │ HTTP POST
┌──────────────────▼──────────────────────┐
│           BACKEND (FastAPI + Python)    │
│  /audit/code   → raw Solidity           │
│  /audit/file   → .sol file upload       │
│  /audit/chain  → address lookup         │
│  /export/pdf   → reportlab PDF          │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│            GEMINI API LAYER             │
│  Model: gemini-1.5-pro                  │
│  - Structured prompt → JSON output      │
│  - Vuln classification + CVSS scoring   │
│  - Plain English risk explanation       │
│  - Secure patch code generation         │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│       ON-CHAIN DATA (for /chain)        │
│  - Etherscan API (free tier)            │
│  - Sourcify (verified source fallback)  │
└─────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
soligard/
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── routes/
│   │   ├── audit_code.py          # POST /audit/code
│   │   ├── audit_file.py          # POST /audit/file
│   │   └── audit_chain.py         # POST /audit/chain
│   ├── core/
│   │   ├── gemini_client.py       # Gemini API wrapper (Peace)
│   │   ├── prompt_engine.py       # All prompt templates (Peace)
│   │   ├── vuln_taxonomy.py       # Vuln definitions (Joel)
│   │   └── pdf_generator.py       # PDF export (reportlab)
│   ├── utils/
│   │   └── chain_fetcher.py       # Etherscan + Sourcify (Joel)
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                      # Mayowa + Yusuf
│   ├── src/
│   │   ├── components/
│   │   │   ├── CodeEditor.jsx     # Monaco editor (Solidity syntax)
│   │   │   ├── FileUpload.jsx     # Drag & drop .sol upload
│   │   │   ├── ChainInput.jsx     # Contract address input
│   │   │   └── AuditReport.jsx    # Side-by-side diff + severity badges
│   │   ├── App.jsx
│   │   └── api.js                 # All backend calls
│   └── package.json
│
├── prompts/                       # Peace owns this
│   ├── audit_system.md            # Master Gemini system prompt
│   ├── vuln_categories.md         # Joel's taxonomy in Markdown
│   └── patch_format.md            # JSON output format spec
│
├── sample_contracts/              # Joel owns this
│   ├── clean_contract.sol         # Demo: no vulnerabilities
│   ├── reentrancy_vuln.sol        # Demo: reentrancy attack
│   └── overflow_vuln.sol          # Demo: integer overflow
│
├── docs/
│   └── ARCHITECTURE.md
├── .gitignore
└── README.md
```

---

## 🧬 Gemini Prompt Architecture

### Master System Prompt
```
You are Solidify, an expert smart contract security auditor powered by Gemini.

Analyze the provided Solidity smart contract code and return a structured security audit.

For every vulnerability found, return:
- vulnerability_name: string
- severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
- cvss_score: float (0.0 - 10.0)
- affected_lines: list of integers
- description: plain English explanation (max 3 sentences, non-technical friendly)
- original_code: the vulnerable snippet
- patched_code: the secure replacement snippet

Return ONLY valid JSON. No markdown. No preamble. No explanation outside the JSON.

Schema:
{
  "contract_name": string,
  "audit_summary": string,
  "overall_risk_score": float,
  "total_vulnerabilities": integer,
  "vulnerabilities": [
    {
      "vulnerability_name": string,
      "severity": string,
      "cvss_score": float,
      "affected_lines": [integer],
      "description": string,
      "original_code": string,
      "patched_code": string
    }
  ],
  "recommendations": [string]
}
```

---

## 🔐 Vulnerability Taxonomy (Joel's Domain)

| Category | Pattern | Severity |
|---|---|---|
| Reentrancy | External call before state update | CRITICAL |
| Integer Overflow/Underflow | Unchecked arithmetic | HIGH |
| Access Control | Missing onlyOwner / role guards | HIGH |
| Unchecked External Calls | Return value ignored | HIGH |
| tx.origin Authentication | Using tx.origin instead of msg.sender | MEDIUM |
| Timestamp Dependence | block.timestamp for logic | MEDIUM |
| Uninitialized Storage Pointers | Storage var used before set | HIGH |
| Front-running | Predictable on-chain state | MEDIUM |
| Self-destruct Abuse | Unguarded selfdestruct | CRITICAL |
| Denial of Service | Unbounded loops / gas griefing | MEDIUM |

---

## 👥 Team Roles & Ownership

| Person | Role | Owns |
|---|---|---|
| **Peace** | Tech Lead + AI Layer | `gemini_client.py`, `prompt_engine.py`, backend API routes, `prompts/` |
| **Joel** | Security Lead | `vuln_taxonomy.py`, `chain_fetcher.py`, `sample_contracts/`, security test cases |
| **Mayowa** | Frontend Lead | React UI, component design, overall UX |
| **Yusuf** | Frontend Support | `api.js`, PDF download flow, frontend ↔ backend integration |
| **Abubakar** | Product + QA | User flow testing, demo script, README writeup |

---

## 📅 Day-by-Day Sprint Plan

### ✅ Day 1 — Tuesday: Foundation
- [ ] GitHub repo created, all members added with write access
- [ ] `.env.example` committed (API key slots ready)
- [ ] FastAPI skeleton running locally
- [ ] `gemini_client.py` + `/audit/code` endpoint returning JSON audit
- [ ] Joel commits `vuln_taxonomy.py`
- [ ] Mayowa sets up React + Monaco editor component
- [ ] **EOD Goal:** Paste Solidity → receive structured JSON audit ✅

### ✅ Day 2 — Wednesday: Core Features
- [ ] `/audit/file` endpoint (`.sol` file handling)
- [ ] Etherscan integration for `/audit/chain`
- [ ] Frontend connects to `/audit/code`, results displayed
- [ ] PDF generator skeleton (reportlab)
- [ ] Joel commits 3 sample contracts for testing
- [ ] **EOD Goal:** All 3 input modes working in backend ✅

### ✅ Day 3 — Thursday: Full Integration
- [ ] Full frontend ↔ backend integration
- [ ] `AuditReport.jsx` — side-by-side diff view with severity badges
- [ ] PDF export working end-to-end
- [ ] Error handling (invalid code, bad address, API failures, rate limits)
- [ ] **EOD Goal:** Complete demo flow working locally ✅

### ✅ Day 4 — Friday: Deploy + Demo Prep
- [ ] Backend deployed (Railway or Render free tier)
- [ ] Frontend deployed (Vercel or Netlify)
- [ ] Abubakar runs full QA pass on live URL
- [ ] Demo rehearsed: 3 contracts (1 clean, 2 vulnerable)
- [ ] README finalized
- [ ] **EOD Goal:** Live URL working, demo rehearsed ✅

### 🏆 Day 5 — Saturday: Demo Day
- [ ] Final bug fixes (morning only — freeze by noon)
- [ ] Demo flow: paste → scan → report → patch → PDF
- [ ] Peace presents: AI architecture + Gemini layer
- [ ] Joel presents: security logic + vuln taxonomy
- [ ] Mayowa presents: UI/UX design decisions
- [ ] Abubakar narrates: user journey + product story
- [ ] **WIN** 🏆

---

## 🔑 Environment Variables

```env
GEMINI_API_KEY=your_gemini_key_here
ETHERSCAN_API_KEY=your_etherscan_key_here
ENVIRONMENT=development
PORT=8000
CORS_ORIGINS=http://localhost:5173
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/your-org/soligard.git

# Backend
cd backend
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

---

## 📦 Dependencies

### Backend (requirements.txt)
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
@monaco-editor/react      # Solidity syntax highlighting
```

---

## 🎤 Demo Script (Saturday — 5 min)

1. **Hook (30s)** — "Last year, $1.8B was lost to smart contract exploits. Most were preventable."
2. **Problem (45s)** — Abubakar walks the judge through the pain of manual audits
3. **Demo 1 (60s)** — Paste reentrancy vulnerable contract → show report + patch side-by-side
4. **Demo 2 (45s)** — Upload `.sol` file → export PDF audit report
5. **Demo 3 (45s)** — Enter contract address → on-chain scan result
6. **Architecture (30s)** — Peace explains Gemini prompt layer in one sentence
7. **Close (30s)** — "Solidify is the first line of defense every Web3 developer deserves."

---

*Built with 🔐 by Team Solidify | GDG Abuja × Build with AI Sprint*
*Peace · Joel · Mayowa · Yusuf · Abubakar*