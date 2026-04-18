import { useState } from 'react';

export default function AuditReport({ report }) {
  const [expanded, setExpanded] = useState({});
  const [showPatch, setShowPatch] = useState({});

  if (!report) return <div className="audit-report empty"><p>Run an audit to see vulnerabilities</p></div>;

  const vulns = report.vulnerabilities || [];
  const critical = vulns.filter(v => v.severity === 'CRITICAL').length;
  const high = vulns.filter(v => v.severity === 'HIGH').length;
  const medium = vulns.filter(v => v.severity === 'MEDIUM').length;
  const low = vulns.filter(v => v.severity === 'LOW').length;

  const severityClass = (severity) => severity?.toLowerCase() || 'info';
  const toggleExpand = (idx) => setExpanded(prev => ({ ...prev, [idx]: !prev[idx] }));
  const togglePatch = (idx) => setShowPatch(prev => ({ ...prev, [idx]: !prev[idx] }));

  return (
    <div className="audit-report">
      <div className="report-header">
        <h2>Audit Report</h2>
      </div>

      <div className="score-card">
        <div className="score-main">
          <div className="score-value">{report.score || 'N/A'}</div>
          <div className="score-label">Security Score</div>
        </div>
        <div className="severity-counts">
          <div className="count critical"><span>{critical}</span>CRITICAL</div>
          <div className="count high"><span>{high}</span>HIGH</div>
          <div className="count medium"><span>{medium}</span>MEDIUM</div>
          <div className="count low"><span>{low}</span>LOW</div>
        </div>
      </div>

      <div className="summary-section">
        <h3>Executive Summary</h3>
        <p>{report.summary || 'No summary available'}</p>
      </div>

      <div className="vulnerabilities">
        <h3>Vulnerabilities ({vulns.length})</h3>
        {vulns.length === 0 ? (
          <div className="no-vulns">No vulnerabilities found!</div>
        ) : (
          vulns.map((v, i) => (
            <div key={i} className={'vuln-card ' + severityClass(v.severity)}>
              <div className="vuln-header" onClick={() => toggleExpand(i)}>
                <div className="vuln-title">
                  <SeverityBadge level={v.severity} />
                  <span className="vuln-type">{v.type}</span>
                </div>
                <span className="expand-icon">{expanded[i] ? '-' : '+'}</span>
              </div>
              
              {expanded[i] && (
                <div className="vuln-details">
                  <div className="detail-row">
                    <label>Location</label>
                    <code>{v.location || 'N/A'}</code>
                  </div>
                  <div className="detail-row">
                    <label>Description</label>
                    <p>{v.description}</p>
                  </div>
                  {v.recommendation && (
                    <div className="detail-row">
                      <label>Recommendation</label>
                      <p className="recommendation">{v.recommendation}</p>
                    </div>
                  )}
                  {v.patch && (
                    <div className="patch-section">
                      <button className="btn-small" onClick={() => togglePatch(i)}>
                        {showPatch[i] ? 'Hide Patch' : 'Show Patch'}
                      </button>
                      {showPatch[i] && (
                        <pre className="patch-code">{v.patch}</pre>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SeverityBadge({ level }) {
  const colors = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', LOW: '#3fb950', INFO: '#58a6ff' };
  return <span className="severity-badge" style={{ background: colors[level] || colors.INFO }}>{level}</span>;
}