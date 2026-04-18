const API_BASE = 'http://localhost:8000/api';

export async function startAudit(codeOrAddress, chain, options = {}) {
  const body = {
    chain,
    ...options,
  };
  
  // Detect if it's an address (starts with 0x and is 42 chars)
  if (codeOrAddress && codeOrAddress.startsWith('0x') && codeOrAddress.length === 42) {
    body.address = codeOrAddress;
  } else {
    body.code = codeOrAddress;
  }
  
  const res = await fetch(`${API_BASE}/audit/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
}

export async function streamAudit(taskId, onChunk, onComplete, onError) {
  try {
    const response = await fetch(`${API_BASE}/audit/stream/${taskId}`);
    if (!response.ok) {
      throw new Error('Stream failed');
    }
    
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      
      const text = decoder.decode(value);
      const lines = text.split('\n');
      
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            
            if (data.status === 'streaming' && data.chunk) {
              onChunk(data.chunk);
            } else if (data.status === 'completed' && data.result) {
              onComplete(data.result);
            } else if (data.status === 'failed') {
              onError(data.error || 'Audit failed');
            } else if (data.status === 'connecting' || data.status === 'analyzing') {
              onChunk(data.status + '...\n');
            }
          } catch (e) {
            // Skip parse errors
          }
        }
      }
    }
  } catch (e) {
    onError(e.message);
  }
}

export async function getAuditStatus(taskId) {
  const res = await fetch(`${API_BASE}/audit/status/${taskId}`);
  return res.json();
}

export async function getAuditReport(taskId) {
  const res = await fetch(`${API_BASE}/audit/report/${taskId}`);
  return res.json();
}

export async function getChains() {
  try {
    const res = await fetch(`${API_BASE}/chains`);
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

export async function chat(message, history = []) {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, history }),
  });
  return res.json();
}

export async function exportMarkdown(taskId) {
  const res = await fetch(`${API_BASE}/export/markdown/${taskId}`);
  return res.text();
}

export async function exportPdf(taskId) {
  const res = await fetch(`${API_BASE}/export/pdf/${taskId}`);
  return res.text();
}

export async function getPoc(taskId) {
  const res = await fetch(`${API_BASE}/poc/${taskId}`);
  return res.json();
}

export async function detectGas(code) {
  const res = await fetch(`${API_BASE}/detect/gas`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  return res.json();
}

export async function detectFrontrun(code) {
  const res = await fetch(`${API_BASE}/detect/frontrun`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  return res.json();
}

export async function detectOracle(code) {
  const res = await fetch(`${API_BASE}/detect/oracle`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  return res.json();
}

export default { startAudit, streamAudit, getAuditStatus, getAuditReport, getChains, chat, exportMarkdown, exportPdf, getPoc, detectGas, detectFrontrun, detectOracle };