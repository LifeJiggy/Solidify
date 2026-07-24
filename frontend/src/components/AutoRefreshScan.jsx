import { useEffect, useRef, useState, useCallback } from 'react';
import { detectGas, detectFrontrun, detectOracle } from '../api';
import { showToast } from './Toast';

export default function AutoRefreshScan({ code, chain, provider, model, onResults }) {
  const [enabled, setEnabled] = useState(false);
  const [lastHash, setLastHash] = useState('');
  const [scanning, setScanning] = useState(false);
  const debounceRef = useRef(null);

  const hashCode = useCallback((str) => {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash.toString();
  }, []);

  useEffect(() => {
    if (!enabled || !code || code.length < 10) return;
    const currentHash = hashCode(code);
    if (currentHash === lastHash) return;

    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(async () => {
      setLastHash(currentHash);
      setScanning(true);
      try {
        const [gas, fr, or] = await Promise.all([
          detectGas(code).catch(() => ({ optimizations: [] })),
          detectFrontrun(code).catch(() => ({ vulnerabilities: [] })),
          detectOracle(code).catch(() => ({ vulnerabilities: [] })),
        ]);
        const results = {
          gas: gas.optimizations || [],
          frontrun: fr.vulnerabilities || [],
          oracle: or.vulnerabilities || [],
          timestamp: Date.now(),
        };
        if (onResults) onResults(results);
      } catch {
        // silent - debounced background scan
      }
      setScanning(false);
    }, 1500);

    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [code, enabled, lastHash, hashCode, onResults]);

  return (
    <div className="auto-refresh-scan">
      <label className="toggle-label">
        <input type="checkbox" checked={enabled} onChange={e => { setEnabled(e.target.checked); setLastHash(''); }} />
        <span className="toggle-text">Live Scan</span>
        {scanning && <span className="scanning-indicator" />}
      </label>
      {enabled && (
        <span className="auto-hint">Scanning on changes (1.5s debounce)</span>
      )}
    </div>
  );
}

export function AutoRefreshResults({ results }) {
  if (!results) return null;
  const total = (results.gas?.length || 0) + (results.frontrun?.length || 0) + (results.oracle?.length || 0);
  return (
    <div className="auto-refresh-results">
      <span className="auto-refresh-badge">
        Live: {total} issue{total !== 1 ? 's' : ''}
      </span>
      {results.gas?.length > 0 && (
        <span className="auto-refresh-item gas">{results.gas.length} gas</span>
      )}
      {results.frontrun?.length > 0 && (
        <span className="auto-refresh-item frontrun">{results.frontrun.length} frontrun</span>
      )}
      {results.oracle?.length > 0 && (
        <span className="auto-refresh-item oracle">{results.oracle.length} oracle</span>
      )}
      {total === 0 && <span className="auto-refresh-clean">Clean</span>}
    </div>
  );
}
