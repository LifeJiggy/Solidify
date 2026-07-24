import { useState, useEffect, useRef } from 'react';

export default function AuditTimer({ running }) {
  const [elapsed, setElapsed] = useState(0);
  const startRef = useRef(null);

  useEffect(() => {
    if (running) {
      startRef.current = Date.now();
      setElapsed(0);
      const interval = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startRef.current) / 1000));
      }, 200);
      return () => clearInterval(interval);
    } else {
      setElapsed(0);
    }
  }, [running]);

  if (!running) return null;

  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  return <span className="audit-timer">{String(mins).padStart(2, '0')}:{String(secs).padStart(2, '0')}</span>;
}
