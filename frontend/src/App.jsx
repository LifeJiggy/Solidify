import { useState } from 'react';
import ChainInput from './components/ChainInput';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import AuditReport from './components/AuditReport';
import { startAudit, getAuditStatus, getAuditReport } from './api';

export default function App() {
  const [contract, setContract] = useState(`// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract SimpleStorage {\n    uint256 private value;\n    \n    function setValue(uint256 _value) public {\n        value = _value;\n    }\n    \n    function getValue() public view returns (uint256) {\n        return value;\n    }\n}`);
  const [chain, setChain] = useState('ethereum');
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAudit = async () => {
    setLoading(true);
    try {
      const result = await startAudit(contract, chain);
      setTaskId(result.task_id);
      pollStatus(result.task_id);
    } catch (e) {
      alert('Error: ' + e.message);
    }
    setLoading(false);
  };

  const pollStatus = async (id) => {
    const interval = setInterval(async () => {
      const s = await getAuditStatus(id);
      setStatus(s);
      if (s.status === 'completed') {
        clearInterval(interval);
        const r = await getAuditReport(id);
        setReport(r);
      }
    }, 2000);
  };

  return (
    <div className="app">
      <header>
        <h1>Solidify</h1>
        <p>Web3 Smart Contract Security Auditor</p>
      </header>
      <main>
        <section className="input-section">
          <ChainInput value={chain} onChange={setChain} />
          <FileUpload onFileLoaded={setContract} />
        </section>
        <CodeEditor value={contract} onChange={setContract} />
        <button className="audit-btn" onClick={handleAudit} disabled={loading}>
          {loading ? 'Auditing...' : 'Start Audit'}
        </button>
        {status && <div className="status">Status: {status.status}</div>}
        {report && <AuditReport report={report} />}
      </main>
    </div>
  );
}