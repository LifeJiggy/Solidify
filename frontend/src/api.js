const API_BASE = 'http://localhost:8000/api';
const DEFAULT_TIMEOUT = 30000;
const STREAM_TIMEOUT = 120000;

const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function validateReport(report) {
  if (!report || typeof report !== 'object') return null;
  const score = typeof report.score === 'number' ? Math.max(0, Math.min(10, report.score)) : 5;
  const summary = typeof report.summary === 'string' ? report.summary : 'Audit completed.';
  const vulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];
  return {
    score,
    summary,
    vulnerabilities: vulns.map(v => ({
      type: typeof v.type === 'string' ? v.type : 'Unknown',
      severity: VALID_SEVERITIES.includes((v.severity || '').toUpperCase()) ? v.severity.toUpperCase() : 'INFO',
      location: typeof v.location === 'string' ? v.location : '',
      description: typeof v.description === 'string' ? v.description : '',
      recommendation: typeof v.recommendation === 'string' ? v.recommendation : '',
      cvss: typeof v.cvss === 'number' ? Math.max(0, Math.min(10, v.cvss)) : 5.0,
    })),
  };
}

class ApiError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function fetchWithTimeout(url, options = {}, timeout = DEFAULT_TIMEOUT, retries = 1) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) {
        let data;
        try { data = await res.json(); } catch { data = null; }
        throw new ApiError(data?.detail || `HTTP ${res.status}`, res.status, data);
      }
      return res;
    } catch (e) {
      clearTimeout(timer);
      if (e.name === 'AbortError') throw new ApiError('Request timed out', 408);
      if (attempt < retries && e.name === 'ApiError' && e.status >= 500) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      if (e instanceof ApiError) throw e;
      throw new ApiError(e.message || 'Network error', 0);
    }
  }
}

export async function startAudit(codeOrAddress, chain, options = {}) {
  const body = { chain, ...options };
  if (codeOrAddress && /^0x[a-fA-F0-9]{40}$/.test(codeOrAddress) && !body.address) {
    body.address = codeOrAddress;
  } else if (!body.code && !body.address) {
    body.code = codeOrAddress;
  }
  const res = await fetchWithTimeout(`${API_BASE}/audit/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, 15000);
  return res.json();
}

export async function streamAudit(taskId, onChunk, onComplete, onError) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), STREAM_TIMEOUT);
    const response = await fetch(`${API_BASE}/audit/stream/${taskId}`, { signal: controller.signal });
    clearTimeout(timer);

    if (!response.ok) {
      onError(`Stream failed: HTTP ${response.status}`);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          const data = JSON.parse(line.slice(6));
          if (data.status === 'streaming' && data.chunk) {
            onChunk(data.chunk);
          } else if (data.status === 'completed' && data.result) {
            onComplete(validateReport(data.result));
            return;
          } else if (data.status === 'failed') {
            onError(data.error || 'Audit failed');
            return;
          } else if (data.status === 'cancelled') {
            onChunk('\n⏹ Audit cancelled by user\n');
            if (typeof onComplete === 'function') {
              onComplete({ score: 0, vulnerabilities: [], summary: 'Audit was cancelled' });
            }
            return;
          } else if (['connecting', 'analyzing', 'scanning', 'queued', 'resumed'].includes(data.status)) {
            onChunk(data.status + '...\n');
          } else if (data.status === 'paused') {
            onChunk('\n⏸ Audit paused\n');
          }
        } catch {
          // skip malformed JSON
        }
      }
    }
    // Stream ended without completion
    onError('Stream ended unexpectedly');
  } catch (e) {
    onError(e.name === 'AbortError' ? 'Stream timed out' : e.message);
  }
}

export async function getAuditStatus(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/audit/status/${taskId}`);
  return res.json();
}

export async function getAuditReport(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/audit/report/${taskId}`);
  return validateReport(await res.json());
}

export async function getChains() {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/chains`, {}, 5000);
    return res.json();
  } catch {
    return [
      { id: 'ethereum', name: 'Ethereum', chain_id: 1 },
      { id: 'bsc', name: 'BNB Chain', chain_id: 56 },
      { id: 'polygon', name: 'Polygon', chain_id: 137 },
      { id: 'arbitrum', name: 'Arbitrum', chain_id: 42161 },
      { id: 'optimism', name: 'Optimism', chain_id: 10 },
    ];
  }
}

export async function chat(message, history = [], provider = 'nvidia', model = 'minimaxai/minimax-m2.5') {
  const res = await fetchWithTimeout(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history, provider, model }),
  }, 60000);
  return res.json();
}

export async function exportMarkdown(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/export/markdown/${taskId}`);
  return res.text();
}

export async function exportPdf(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/export/pdf/${taskId}`);
  return res.text();
}

export async function getPoc(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/poc/${taskId}`);
  return res.json();
}

async function detect(code, endpoint) {
  const res = await fetchWithTimeout(`${API_BASE}/detect/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  }, 30000);
  return res.json();
}

export const detectGas = (code) => detect(code, 'gas');
export const detectFrontrun = (code) => detect(code, 'frontrun');
export const detectOracle = (code) => detect(code, 'oracle');

export async function stopAudit(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/audit/stop/${taskId}`, { method: 'POST' }, 5000);
  return res.json();
}

export async function pauseAudit(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/audit/pause/${taskId}`, { method: 'POST' }, 5000);
  return res.json();
}

export async function resumeAudit(taskId) {
  const res = await fetchWithTimeout(`${API_BASE}/audit/resume/${taskId}`, { method: 'POST' }, 5000);
  return res.json();
}

export default { startAudit, streamAudit, getAuditStatus, getAuditReport, getChains, chat, exportMarkdown, exportPdf, getPoc, detectGas, detectFrontrun, detectOracle, stopAudit, pauseAudit, resumeAudit };
