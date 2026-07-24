import { useState, useMemo } from 'react';

export default function SeverityFilter({ vulnerabilities, children }) {
  const [activeFilters, setActiveFilters] = useState(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  const [searchQuery, setSearchQuery] = useState('');

  const toggleFilter = (sev) => {
    setActiveFilters(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  const filtered = useMemo(() =>
    (vulnerabilities || []).filter(v =>
      activeFilters.includes(v.severity) &&
      (!searchQuery ||
        v.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (v.description || '').toLowerCase().includes(searchQuery.toLowerCase()))
    ),
    [vulnerabilities, activeFilters, searchQuery]
  );

  const counts = useMemo(() => {
    const c = {};
    (vulnerabilities || []).forEach(v => { c[v.severity] = (c[v.severity] || 0) + 1; });
    return c;
  }, [vulnerabilities]);

  const hasActiveFilters = activeFilters.length < 4;

  return (
    <div className="vuln-filter">
      <div className="filter-bar">
        <div className="filter-severities">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              className={`filter-btn ${activeFilters.includes(sev) ? 'active' : ''} ${sev.toLowerCase()}`}
              onClick={() => toggleFilter(sev)}
            >
              {sev} ({counts[sev] || 0})
            </button>
          ))}
          {hasActiveFilters && (
            <button className="filter-btn" onClick={() => setActiveFilters(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])}>
              Show All
            </button>
          )}
        </div>
        <div className="filter-search">
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search vulnerabilities..."
            className="search-input"
          />
          {searchQuery && <button className="search-clear" onClick={() => setSearchQuery('')}>X</button>}
        </div>
      </div>
      {children(filtered)}
    </div>
  );
}
