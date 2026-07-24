import { stopAudit, pauseAudit, resumeAudit } from '../api';
import { showToast } from './Toast';

export default function AuditControls({ taskId, status, onStateChange }) {
  if (!taskId || !status || status === 'completed' || status === 'failed' || status === 'cancelled') return null;

  const handleStop = async () => {
    try {
      await stopAudit(taskId);
      showToast('Audit stopped', 'info');
      if (onStateChange) onStateChange('cancelled');
    } catch { showToast('Failed to stop', 'error'); }
  };

  const handlePause = async () => {
    try {
      await pauseAudit(taskId);
      showToast('Audit paused', 'info');
      if (onStateChange) onStateChange('paused');
    } catch { showToast('Failed to pause', 'error'); }
  };

  const handleResume = async () => {
    try {
      await resumeAudit(taskId);
      showToast('Audit resumed', 'info');
      if (onStateChange) onStateChange('running');
    } catch { showToast('Failed to resume', 'error'); }
  };

  return (
    <div className="audit-controls">
      {status === 'paused' ? (
        <button className="audit-btn resume" onClick={handleResume} title="Resume">▶ Resume</button>
      ) : (
        <button className="audit-btn pause" onClick={handlePause} title="Pause">⏸ Pause</button>
      )}
      <button className="audit-btn stop" onClick={handleStop} title="Stop">⏹ Stop</button>
    </div>
  );
}
