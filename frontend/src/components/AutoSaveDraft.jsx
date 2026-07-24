import { useEffect, useRef } from 'react';

const DRAFT_KEY = 'solidify_draft';

export default function AutoSaveDraft({ code }) {
  const saved = useRef('');

  useEffect(() => {
    const timer = setInterval(() => {
      if (code && code !== saved.current) {
        try {
          localStorage.setItem(DRAFT_KEY, code);
          saved.current = code;
        } catch {}
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [code]);

  return null;
}

export function loadDraft() {
  try { return localStorage.getItem(DRAFT_KEY); }
  catch { return null; }
}
