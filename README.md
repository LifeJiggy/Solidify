# 🔐 Solidify — Web3 Smart Contract Security Auditor

AI-powered smart contract security auditor with real-time streaming, stop/pause/resume controls, and multi-provider support.

Built at **GDG Abuja × Build with AI Sprint Hackathon** by Team Solidify.
Part of the TCP (The Coding Peace) ecosystem — Ghost hunts Web2, Solidify hunts Web3.

---

## What It Does

- **Paste code, upload a `.sol` file, or scan a live contract address** — three input modes
- **Real-time AI streaming** — see the analysis arrive character-by-character via SSE
- **Stop / Pause / Resume** — full control over long-running audits
- **Structured audit report** — severity counts, expandable vuln cards, CVSS scores
- **14+ vulnerability classes** — reentrancy, access control, overflow, unchecked calls, flash loans, oracle manipulation, front-running, selfdestruct, delegatecall, weak randomness, unprotected initializers, zero-address checks, centralization risk, and more
- **Multi-provider AI** — NVIDIA (Gemma 3/4, Llama, Nemotron), OpenAI, Anthropic, Qwen, Groq, Ollama
- **Chat with AI** — ask security questions in plain English
- **Export** — JSON, Markdown, HTML report formats
- **Static scanner fallback** — works even without an API key

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+

### 1. Backend
```powershell
cd C:\Users\ADMIN\Python_Project\Hackathon\2026\Solidify
python server.py
```

Starts on `http://localhost:8000`.

### 2. Frontend
```powershell
cd frontend
npm install
npm run dev
```

Opens at `http://localhost:5173`.

### 3. Use it
Paste any Solidity contract → click **Audit** → watch streaming results in real-time.

---

## Input Modes

| Mode | How |
|------|-----|
| **Paste Code** | Drop Solidity source directly into the editor |
| **Upload File** | Drag-and-drop `.sol` files |
| **On-Chain Scan** | Enter a verified contract address — fetches source from block explorer |
| **Compare** | Side-by-side diff audit of two contract versions |

---

## Streaming Controls

During an active audit, controls appear in the stream panel header:

- **⏸ Pause** — freezes the AI stream in place
- **▶ Resume** — continues from where it paused
- **⏹ Stop** — immediately cancels the audit

The server uses Server-Sent Events (SSE) to push status events and content chunks to the frontend in real-time.

---

## AI Providers

Switch providers in Settings. Set the corresponding environment variable before starting the server:

| Provider | Env Variable | Default Models |
|----------|-------------|----------------|
| **NVIDIA** ⭐ | `NVIDIA_API_KEY` | **Google Gemma 4-27B**, Gemma 4-9B, Gemma 3-27B, Gemma 3-12B, Llama 3.1 Nemotron 70B, Nemotron 4-340B |
| Google | `GEMINI_API_KEY` | Gemini 2.5 Flash, 2.5 Pro, 3.5 Flash |
| OpenAI | `OPENAI_API_KEY` | GPT-4o, GPT-4-turbo, GPT-3.5-turbo |
| Anthropic | `ANTHROPIC_API_KEY` | Claude 3 Opus, Sonnet, Haiku |
| Qwen | `QWEN_API_KEY` | Qwen2.5 Coder 32B, 7B |
| Groq | `GROQ_API_KEY` | Llama 3 70B, Mixtral 8x7B |
| Ollama | `OLLAMA_BASE_URL` | Llama 3, CodeLlama, Mistral (local) |

> ⭐ **Default provider**: NVIDIA with **Google Gemma 3-27B**. Set `NVIDIA_API_KEY` in `.env` to enable streaming audits. Without any API key, the **static scanner fallback** activates automatically.

---

## Vulnerability Coverage

| Vulnerability | Severity |
|--------------|----------|
| Reentrancy | 🔴 CRITICAL |
| Unprotected Initializer | 🔴 CRITICAL |
| Selfdestruct / Suicide | 🔴 CRITICAL |
| Missing Access Control | 🔴 CRITICAL |
| Unsafe Delegatecall | 🟠 HIGH |
| Integer Overflow / Underflow | 🟠 HIGH |
| Unchecked External Calls | 🟠 HIGH |
| Weak Randomness | 🟠 HIGH |
| tx.origin Authentication | 🟡 MEDIUM |
| Timestamp Dependence | 🟡 MEDIUM |
| Unbounded Gas Loop | 🟡 MEDIUM |
| Missing Zero-Address Check | 🟡 MEDIUM |
| Floating Pragma | ℹ️ INFO |
| Hardcoded Address | ℹ️ INFO |
| Deprecated `now` Usage | ℹ️ INFO |

---

## Architecture

```
Frontend (React + Vite)              Backend (FastAPI + Python)
       │                                    │
       │── POST /api/audit/start ──────────►│  asyncio.create_task(_run_audit)
       │◄── { task_id }                     │
       │                                    │
       │── GET /api/audit/stream/{id} ─────►│  SSE event generator
       │◄── data: {"status":"connecting"}   │  _push_event / _push_chunk
       │◄── data: {"status":"streaming",    │
       │         "chunk":"{\"score\":"}      │
       │◄── data: {"status":"completed",    │
       │         "result":{...}}             │
       │                                    │
       │── POST /api/audit/pause/{id} ─────►│  pause_tasks.add(id)
       │── POST /api/audit/resume/{id} ────►│  pause_tasks.discard(id)
       │── POST /api/audit/stop/{id}  ─────►│  cancelled_tasks.add(id)
```

### Key Modules

| File | Role |
|------|------|
| `server.py` | FastAPI app, SSE streaming, static scanner, all API endpoints |
| `providers/streaming.py` | Centralized stream processor — 6 per-provider parsers (OpenAI, Anthropic, Ollama, Qwen, Google), rate-limit detection, content sanitization |
| `providers/nvidia.py` (and 7 more) | Each ~15 lines — delegate to `StreamingProcessor.process_stream_simple()` |
| `frontend/src/api.js` | `streamAudit()` SSE parser + `validateReport()` frontend schema validation |
| `frontend/src/App.jsx` | Task state management, `AuditControls` wiring, StatusBar |
| `frontend/src/components/AuditControls.jsx` | Pause/Resume/Stop buttons |

---

## Commands

| Button | Action |
|--------|--------|
| **Audit** | Full AI-powered security audit (streaming) |
| **Hunt** | Targeted vulnerability hunt |
| **Scan** | Quick static analysis scan |
| **Gas** | Gas optimization analysis |
| **FrontRun** | MEV / front-running detection |
| **Oracle** | Oracle manipulation analysis |
| **Ask** | Ask a security question to the AI |
| **Chat** | Full conversational AI chat |

---

## Environment Variables

```bash
# AI Provider Keys
NVIDIA_API_KEY=your_key_here         # Default — Gemma 3/4 via NVIDIA NIM
GEMINI_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here
QWEN_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
OLLAMA_BASE_URL=http://localhost:11434

# Blockchain Explorer
ETHERSCAN_API_KEY=your_key_here

# App Config
PORT=8000
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173
```

---

## Project Structure

```
solidify/
├── server.py                    # FastAPI entry point
├── providers/                   # AI provider wrappers (8 providers)
│   ├── streaming.py             # Centralized stream processor
│   ├── stream_mixin.py          # Streaming mixin utilities
│   ├── nvidia.py                # NVIDIA NIM provider
│   ├── openai.py                # OpenAI provider
│   ├── anthropic.py             # Anthropic provider
│   ├── groq.py                  # Groq provider
│   ├── ollama.py                # Ollama local provider
│   ├── qwen.py                  # Qwen provider
│   ├── google.py                # Google provider
│   ├── minimax.py               # MiniMax provider
│   ├── provider_factory.py      # Provider factory + cache
│   └── __init__.py
├── frontend/
│   ├── index.html               # All CSS inline
│   ├── src/
│   │   ├── App.jsx              # Main app component
│   │   ├── api.js               # API client + SSE parser
│   │   ├── main.jsx
│   │   └── components/          # UI components
│   └── package.json
├── rules/                        # Static detection rules
├── memory/                       # Session memory
├── audits/                       # Audit engine modules
├── reports/                      # Report templates
├── models/                       # Model configurations
├── USAGE.md                      # Detailed usage guide
└── README.md
```

---

## Team Solidify

| Name | Role | Focus |
|------|------|-------|
| Peace Stephen | Tech Lead | AI/LLM, Backend, Streaming, Providers |
| Joel Emmanuel Adinoyi | Security Lead | Vuln Detection, Solidity Analysis, Blockchain |
| Mayowa Sunusi | Frontend Lead | UI/UX, React Components, Reports |
| Yusuf Sanusi | Frontend Dev | API Integration, Tools, Providers |
| Abubakar Adamu | Product/QA | Documentation, Validation, Testing |

---

## Disclaimer

Solidify is a security research and educational tool. All analysis features are intended for use within authorized scope only — on contracts you own, have written, or have explicit permission to test. The team assumes no liability for misuse.

---

## License

MIT License — see [LICENSE](LICENSE)

---

Built with 🔐 by Team Solidify | GDG Abuja × Build with AI Sprint
