import { useState, useEffect, useCallback } from 'react';

let toastId = 0;
let addToastFn = null;

export function showToast(message, type = 'info', duration = 4000) {
  if (addToastFn) addToastFn({ id: ++toastId, message, type, duration });
}

export default function ToastContainer() {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback((toast) => {
    setToasts(prev => [...prev, toast]);
  }, []);

  useEffect(() => {
    addToastFn = addToast;
    return () => { addToastFn = null; };
  }, [addToast]);

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  return (
    <div className="toast-container">
      {toasts.map(t => (
        <ToastItem key={t.id} toast={t} onRemove={removeToast} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onRemove }) {
  useEffect(() => {
    const timer = setTimeout(() => onRemove(toast.id), toast.duration);
    return () => clearTimeout(timer);
  }, [toast, onRemove]);

  return (
    <div className={`toast toast-${toast.type}`} onClick={() => onRemove(toast.id)}>
      <span className="toast-icon">{toast.type === 'error' ? '!' : toast.type === 'success' ? '' : 'i'}</span>
      <span className="toast-msg">{toast.message}</span>
    </div>
  );
}
