import { useState, useEffect, useRef } from 'react';

export default function NetworkStatus() {
  const [status, setStatus] = useState('checking');
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    const check = async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      try {
        const dev2 = typeof location !== 'undefined' && location.hostname === 'localhost';
        const apiBase = dev2 ? 'http://localhost:8000/api' : '/api';
        const res = await fetch(apiBase + '/chains', { signal: controller.signal });
        if (mounted.current) setStatus(res.ok ? 'connected' : 'error');
      } catch {
        if (mounted.current) setStatus('offline');
      }
      clearTimeout(timer);
    };
    check();
    const interval = setInterval(check, 15000);
    return () => { mounted.current = false; clearInterval(interval); };
  }, []);

  const colors = { connected: '#3fb950', offline: '#f85149', error: '#d29922', checking: '#8b949e' };
  const labels = { connected: 'Online', offline: 'Offline', error: 'Error', checking: '...' };

  return (
    <span className="network-status" title={`API: ${labels[status]}`}>
      <span className="status-dot" style={{ background: colors[status] }} />
    </span>
  );
}
