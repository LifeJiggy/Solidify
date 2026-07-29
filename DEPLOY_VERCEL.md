# Deploy Solidify to Vercel

## Prerequisites

- Node.js 18+
- Vercel account (free at vercel.com)
- GitHub repo pushed with latest code

## Files already created

| File | Purpose |
|------|---------|
| `vercel.json` | Routes: `/api/*` → Python backend, everything else → frontend |
| `api/index.py` | ASGI entry point, imports `server.py` app |
| `requirements.txt` | Python dependencies (already at root) |

## Deploy steps

### 1. Login to Vercel

```powershell
npx vercel login
```

Opens browser — authenticate with GitHub/GitLab/email.

### 2. Deploy to production

```powershell
npx vercel --prod
```

Follow prompts:
- **Set up and deploy?** → `Y`
- **Which scope?** → select your Vercel account
- **Link to existing project?** → `N` (create new)
- **Project name?** → `solidify` (or your choice)
- **Directory?** → `.` (root, just press Enter)

Vercel will:
1. Install Python deps from `requirements.txt`
2. Build frontend (`cd frontend && npm install && npm run build`)
3. Deploy Python serverless function from `api/index.py`
4. Output a URL like `https://solidify-xxx.vercel.app`

### 3. Set environment variables

After first deploy, go to:

**Vercel Dashboard → Project → Settings → Environment Variables**

Add:

| Name | Value |
|------|-------|
| `NVIDIA_API_KEY` | your NVIDIA API key |
| `SOLIDIFY_PROVIDER` | `nvidia` |
| `SOLIDIFY_MODEL` | `google/gemma-3-27b-it` |

Or for other providers:
`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.

### 4. Redeploy after env changes

```powershell
npx vercel --prod
```

Or enable **Auto-deploy** in Dashboard → Git → connect your repo — every push redeploys automatically.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Application error` on API calls | Check env vars are set in Vercel dashboard |
| Frontend shows but API 404s | Verify `vercel.json` routes — `/api/*` must point to `api/index.py` |
| Python module not found | Ensure `requirements.txt` lists all deps and `api/index.py` has `sys.path.insert(0, ...)` |
| Streaming not showing tokens | Check `NVIDIA_API_KEY` is correct and model name matches NVIDIA's API |
| Build fails on `npm install` | Run `cd frontend && npm install` locally first to verify |
