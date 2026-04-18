export default function AuditReport({ report }) {
  if (!report) return <div className="audit-report empty">No report yet</div>;

  const severityClass = (severity) => {
    const map = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
    return map[severity] || '';
  };

  return (
    <div className="audit-report">
      <h2>Audit Report</h2>
      <div className="summary">
        <span className="score">Score: {report.score || 'N/A'}</span>
        <span className="vulns">{report.vulnerabilities?.length || 0} issues</span>
      </div>
      <div className="vulnerabilities">
        {(report.vulnerabilities || []).map((v, i) => (
          <div key={i} className={`vuln ${severityClass(v.severity)}`}>
            <span className="severity">{v.severity}</span>
            <span className="type">{v.type}</span>
            <pre className="location">{v.location}</pre>
            <p className="description">{v.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}