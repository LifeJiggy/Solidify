# Solidify — Usage Guide

Smart contract security auditor with real-time AI streaming, stop/pause/resume controls, and multi-provider support.

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- An API key for at least one AI provider (see below)

### 1. Backend

```powershell
cd C:\Users\ADMIN\Python_Project\Hackathon\2026\Solidify
python server.py
```

Starts on `http://localhost:8000`. Set your API key as an environment variable before starting:

| Provider | Env Variable | Default Model |
|----------|-------------|---------------|
| Google | `GEMINI_API_KEY` | `gemini-2.5-flash` |
| NVIDIA | `NVIDIA_API_KEY` | `nvidia/nvidia-nemotron-nano-9b-v2` |
| OpenAI | `OPENAI_API_KEY` | `gpt-4o` |
| Anthropic | `ANTHROPIC_API_KEY` | `claude-3-opus` |

Without any API key, the static scanner fallback activates automatically — the demo won't break.

### 2. Frontend

```powershell
cd C:\Users\ADMIN\Python_Project\Hackathon\2026\Solidify\frontend
npm install
npm run dev
```

Opens at `http://localhost:5173`.

---

## Demo Flow

1. **Open the app** — a sample Solidity contract is pre-loaded in the editor
2. **Click Audit** — streaming JSON arrives in real-time from the AI
3. **Pause/Resume/Stop** — controls appear in the stream panel header during an active audit
4. **View Report** — when complete, the structured report fades in with severity counts and expandable vulnerability cards
5. **Filter** — toggle severity buttons or use the search bar to narrow results
6. **Export** — click JSON, Markdown, or HTML to save the report

---

## Features

### AI Providers

Switch providers and models in Settings (top-right):

- **Google Gemini** — Gemini 2.5 Flash / 2.5 Pro / 3.5 Flash (default)
- **NVIDIA** — Nemotron / Llama / Gemma / Qwen models
- **OpenAI** — GPT-4o / GPT-4-turbo
- **Anthropic** — Claude 3 Opus / Sonnet / Haiku
- **Qwen** — Qwen2.5 Coder models
- **Ollama** — Local models (Llama 3, CodeLlama, Mistral)
- **Groq** — Groq-hosted models

### Audit Commands

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

### Input Modes

| Tab | Use |
|-----|-----|
| **Paste Code** | Paste Solidity source directly |
| **Upload File** | Upload `.sol` files |
| **On-Chain Scan** | Enter a verified contract address to pull source from explorer |
| **Compare** | Side-by-side diff of two contracts |

### Code Editor Features

- Solidity syntax highlighting
- Auto-save draft (recovers on page refresh)
- Sample contracts dropdown
- Bookmark frequently audited contracts
- Auto-refresh scan (re-scans on edit)

### Stop / Pause / Resume

- **Stop** — immediately cancels the running audit
- **Pause** — freezes the AI stream in place
- **Resume** — continues from where it was paused

---

## API Reference

### `POST /api/audit/start`

Start a new audit:

```json
{
  "code": "contract Foo { ... }",
  "chain": "ethereum",
  "command": "audit",
  "provider": "nvidia",
  "model": "nvidia/nvidia-nemotron-nano-9b-v2"
}
```

Returns `{ "task_id": "abc123", "status": "started" }`.

### `GET /api/audit/stream/{task_id}`

SSE endpoint — yields `data: {...}` events:

| Event | Fields |
|-------|--------|
| `queued` / `connecting` / `analyzing` / `scanning` | `status`, `progress` |
| `streaming` | `status`, `chunk` |
| `paused` / `cancelled` / `resumed` | `status`, `progress` |
| `completed` | `status`, `progress`, `result` |
| `failed` | `status`, `error` |

### `POST /api/audit/stop/{task_id}`

### `POST /api/audit/pause/{task_id}`

### `POST /api/audit/resume/{task_id}`

### `GET /api/audit/report/{task_id}`

### `POST /api/chat`

Chat with the AI:

```json
{
  "message": "How do I prevent reentrancy?",
  "history": [],
  "provider": "nvidia",
  "model": "nvidia/nvidia-nemotron-nano-9b-v2"
}
```

---

## Architecture

```
Frontend (React + Vite)         Backend (FastAPI + Python)
       │                               │
       │── POST /api/audit/start ──────►  create task, launch _run_audit()
       │◄── { task_id }                │
       │                               │
       │── GET /api/audit/stream/id ──►  SSE event generator
       │◄── data: {"status":"queued"}  │
       │◄── data: {"status":"streaming","chunk":"..."}
       │◄── data: {"status":"completed","result":{...}}
       │                               │
       │── POST /api/audit/pause/id ──►  pause_tasks.add(id)
       │── POST /api/audit/resume/id ──►  pause_tasks.discard(id)
       │── POST /api/audit/stop/id  ───►  cancelled_tasks.add(id)
```

**Key components:**

- `server.py` — FastAPI app, SSE streaming, static scanner fallback
- `providers/streaming.py` — Centralized stream processor with per-provider parsers (OpenAI, Anthropic, Ollama, Qwen, Google)
- `providers/nvidia.py` (and 7 others) — Each ~15 lines, delegate to `StreamingProcessor.process_stream_simple()`
- `frontend/src/api.js` — `streamAudit()` SSE parser + `validateReport()` frontend validation
- `frontend/src/App.jsx` — Main app with task state management, `AuditControls` for pause/resume/stop

---

## Production Build

```powershell
cd frontend
npm run build
```

Serves from `frontend/dist/`. Deploy the FastAPI backend with:

```powershell
uvicorn server:app --host 0.0.0.0 --port 8000
```

---

## Troubleshooting

**"No vulnerabilities found!" but AI found issues** — restart the backend. The server normalizes severity case-insensitively; if you see this, the `.upper()` fix in `_validate_report()` is active.

**Stream hangs mid-sentence** — conference Wi-Fi can drop packets. Click **Stop** and re-run, or the 120s timeout auto-falls back to the static scanner.

**"AI provider not available"** — set the corresponding `*_API_KEY` environment variable and restart the server.

**Port 8000 already in use** — change the port: `python server.py --port 8001`. Update `API_BASE` in `frontend/src/api.js` to match.
