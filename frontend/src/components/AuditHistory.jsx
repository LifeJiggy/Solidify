import { useState, useEffect } from 'react';

const HISTORY_KEY = 'solidify_audit_history';

export function saveAuditToHistory(contract, report) {
  try {
    const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    history.unshift({
      id: Date.now().toString(36),
      timestamp: new Date().toISOString(),
      preview: (contract || '').slice(0, 80),
      score: report?.score || 0,
      vulnCount: report?.vulnerabilities?.length || 0,
      report,
    });
    if (history.length > 50) history.length = 50;
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch (e) {
    // storage full or unavailable - silently skip
  }
}

export default function AuditHistory({ onSelectReport, onClose }) {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    try {
      setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'));
    } catch { setHistory([]); }
  }, []);

  const clearHistory = () => {
    localStorage.removeItem(HISTORY_KEY);
    setHistory([]);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal history-modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>Audit History</h3>
          <button onClick={onClose}>X</button>
        </div>
        {history.length === 0 ? (
          <p className="empty-msg">No past audits yet.</p>
        ) : (
          <div className="history-list">
            {history.map(item => (
              <div key={item.id} className="history-item" onClick={() => { onSelectReport(item); onClose(); }}>
                <div className="history-meta">
                  <span className={`score-badge ${item.score >= 7 ? 'good' : item.score >= 4 ? 'medium' : 'poor'}`}>
                    {item.score}/10
                  </span>
                  <span className="history-vulns">{item.vulnCount} vulns</span>
                  <span className="history-date">{new Date(item.timestamp).toLocaleDateString()}</span>
                </div>
                <code className="history-preview">{item.preview}{item.preview.length >= 80 ? '...' : ''}</code>
              </div>
            ))}
          </div>
        )}
        {history.length > 0 && (
          <div className="modal-actions">
            <button className="secondary-btn" onClick={clearHistory}>Clear History</button>
          </div>
        )}
      </div>
    </div>
  );
}
