import { useState, useMemo, useCallback } from 'react';
import CodeEditor from './CodeEditor';
import { detectGas, detectFrontrun, detectOracle } from '../api';
import { showToast } from './Toast';

function computeDiffLines(left, right) {
  const lLines = (left || '').split('\n');
  const rLines = (right || '').split('\n');
  const maxLen = Math.max(lLines.length, rLines.length);
  const result = [];
  for (let i = 0; i < maxLen; i++) {
    const l = lLines[i] || '';
    const r = rLines[i] || '';
    if (l !== r) {
      result.push({ line: i + 1, left: l, right: r, type: l && r ? 'modified' : l ? 'removed' : 'added' });
    }
  }
  return result;
}

export default function ContractCompare() {
  const [leftCode, setLeftCode] = useState('');
  const [rightCode, setRightCode] = useState('');
  const [view, setView] = useState('side-by-side');
  const [scanResults, setScanResults] = useState(null);
  const [scanning, setScanning] = useState(false);

  const diffs = useMemo(() => computeDiffLines(leftCode, rightCode), [leftCode, rightCode]);

  const diffStats = useMemo(() => {
    if (!diffs.length) return null;
    const added = diffs.filter(d => d.type === 'added').length;
    const removed = diffs.filter(d => d.type === 'removed').length;
    const modified = diffs.filter(d => d.type === 'modified').length;
    return { added, removed, modified, total: diffs.length };
  }, [diffs]);

  const handleScanBoth = useCallback(async () => {
    if (!leftCode && !rightCode) { showToast('Paste code in at least one side', 'error'); return; }
    setScanning(true);
    setScanResults(null);
    const results = {};
    try {
      if (leftCode) {
        const [gas, fr, or] = await Promise.all([
          detectGas(leftCode).catch(() => ({ optimizations: [] })),
          detectFrontrun(leftCode).catch(() => ({ vulnerabilities: [] })),
          detectOracle(leftCode).catch(() => ({ vulnerabilities: [] })),
        ]);
        results.left = { gas: gas.optimizations || [], frontrun: fr.vulnerabilities || [], oracle: or.vulnerabilities || [] };
      }
      if (rightCode) {
        const [gas, fr, or] = await Promise.all([
          detectGas(rightCode).catch(() => ({ optimizations: [] })),
          detectFrontrun(rightCode).catch(() => ({ vulnerabilities: [] })),
          detectOracle(rightCode).catch(() => ({ vulnerabilities: [] })),
        ]);
        results.right = { gas: gas.optimizations || [], frontrun: fr.vulnerabilities || [], oracle: or.vulnerabilities || [] };
      }
      setScanResults(results);
      showToast('Comparison scan complete', 'success');
    } catch (e) {
      showToast('Scan failed: ' + e.message, 'error');
    }
    setScanning(false);
  }, [leftCode, rightCode]);

  const clearBoth = () => { setLeftCode(''); setRightCode(''); setScanResults(null); };

  return (
    <div className="contract-compare">
      <div className="compare-toolbar">
        <div className="compare-tabs">
          <button className={`cmd-btn ${view === 'side-by-side' ? 'active' : ''}`} onClick={() => setView('side-by-side')}>Side by Side</button>
          <button className={`cmd-btn ${view === 'unified' ? 'active' : ''}`} onClick={() => setView('unified')}>Unified Diff</button>
        </div>
        <div className="compare-info">
          {diffStats && (
            <span className="diff-stats">
              <span className="diff-added">+{diffStats.added}</span>
              <span className="diff-removed">-{diffStats.removed}</span>
              <span className="diff-modified">~{diffStats.modified}</span>
              <span className="diff-total">{diffStats.total} changes</span>
            </span>
          )}
          <button className="secondary-btn" onClick={handleScanBoth} disabled={scanning}>
            {scanning ? 'Scanning...' : 'Compare Issues'}
          </button>
          <button className="secondary-btn" onClick={clearBoth}>Clear Both</button>
        </div>
      </div>

      <div className="compare-editors">
        <div className="compare-side">
          <div className="compare-side-header">
            <h4>Original</h4>
          </div>
          <CodeEditor value={leftCode} onChange={setLeftCode} />
        </div>
        <div className="compare-side">
          <div className="compare-side-header">
            <h4>Modified</h4>
          </div>
          <CodeEditor value={rightCode} onChange={setRightCode} />
        </div>
      </div>

      {view === 'unified' && diffs.length > 0 && (
        <div className="diff-view">
          <h4>Changes ({diffs.length} lines)</h4>
          <pre className="diff-output">
            {diffs.map(d => (
              <div key={d.line} className={`diff-line diff-${d.type}`}>
                <span className="diff-lineno">{d.line}</span>
                <span className="diff-marker">{d.type === 'added' ? '+' : d.type === 'removed' ? '-' : '~'}</span>
                <span className="diff-text">{d.type === 'added' ? d.right : d.type === 'removed' ? d.left : `${d.left} → ${d.right}`}</span>
              </div>
            ))}
          </pre>
        </div>
      )}

      {scanResults && (
        <div className="compare-results">
          <h4>Security Comparison</h4>
          <div className="compare-results-grid">
            {['gas', 'frontrun', 'oracle'].map(category => (
              <div key={category} className="compare-category">
                <h5>{category.charAt(0).toUpperCase() + category.slice(1)}</h5>
                <div className="compare-side-results">
                  <div className="compare-side-result">
                    <strong>Original:</strong>
                    <span className="count-badge">{scanResults.left?.[category]?.length || 0} issues</span>
                  </div>
                  <div className="compare-side-result">
                    <strong>Modified:</strong>
                    <span className="count-badge">{scanResults.right?.[category]?.length || 0} issues</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
