import { useEffect } from 'react';

export default function KeyboardShortcuts({ onAudit, onChat, onSettings }) {
  useEffect(() => {
    const handler = (e) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        onAudit();
      }
      if (e.ctrlKey && e.shiftKey && e.key === 'C') {
        e.preventDefault();
        onChat();
      }
      if (e.ctrlKey && e.key === ',') {
        e.preventDefault();
        onSettings();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onAudit, onChat, onSettings]);

  return null;
}
