const API_BASE = 'http://localhost:8000/api';

export async function startAudit(contractCode, chain, options = {}) {
  const res = await fetch(`${API_BASE}/audit/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contract_code: contractCode, chain, ...options }),
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
  const res = await fetch(`${API_BASE}/chains`);
  return res.json();
}

export default { startAudit, getAuditStatus, getAuditReport, getChains };