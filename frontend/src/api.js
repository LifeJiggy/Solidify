const API_BASE = 'http://localhost:8000/api';

export async function startAudit(codeOrAddress, chain, options = {}) {
  const body = {
    chain,
    ...options,
    code: codeOrAddress && codeOrAddress.startsWith('0x') ? undefined : codeOrAddress,
    address: codeOrAddress?.startsWith('0x') ? codeOrAddress : undefined,
  };
  if (!body.code && !body.address) body.code = codeOrAddress;
  
  const res = await fetch(`${API_BASE}/audit/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json();
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
      { id: 'ethereum', name: 'Ethereum', rpc: 'https://eth.llamarpc.com' },
      { id: 'bsc', name: 'BNB Chain', rpc: 'https://bsc-dataseed.binance.org' },
      { id: 'polygon', name: 'Polygon', rpc: 'https://polygon-rpc.com' },
      { id: 'arbitrum', name: 'Arbitrum', rpc: 'https://arb1.arbitrum.io/rpc' },
      { id: 'optimism', name: 'Optimism', rpc: 'https://mainnet.optimism.io' },
    ];
  }
}

export default { startAudit, getAuditStatus, getAuditReport, getChains };