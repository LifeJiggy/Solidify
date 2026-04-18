import { useState } from 'react';
import ChainInput from './components/ChainInput';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import AuditReport from './components/AuditReport';
import { startAudit, getAuditStatus, getAuditReport } from './api';

const SAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private value;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function setValue(uint256 _value) public {
        value = _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
    
    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }
}`;

function ModeTab({ mode, active, onClick }) {
  const labels = { paste: 'Paste Code', upload: 'Upload File', chain: 'On-Chain Scan' };
  return (
    <button className={`mode-tab ${active === mode ? 'active' : ''}`} onClick={onClick}>
      <span>{labels[mode]}</span>
    </button>
  );
}

function ProgressBar({ status }) {
  return (
    <div className="progress-container">
      <div className="progress-steps">
        {['Queued', 'Scanning', 'Analyzing', 'Patching', 'Complete'].map((step, i) => (
          <div key={step} className={`step ${['Queued', 'Scanning', 'Analyzing', 'Patching', 'Complete'].indexOf(status) >= i ? 'done' : ''}`}>
            <div className="step-dot" />
            <span>{step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState('paste');
  const [contract, setContract] = useState(SAMPLE_CONTRACT);
  const [chain, setChain] = useState('ethereum');
  const [contractAddress, setContractAddress] = useState('');
  const [taskId, setTaskId] = useState(null);
  const [status, setStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAudit = async () => {
    setLoading(true);
    try {
      const payload = mode === 'chain' ? { address: contractAddress, chain } : { code: contract, chain };
      const result = await startAudit(payload.code || payload.address, chain, mode === 'chain' ? { address: contractAddress } : {});
      setTaskId(result.task_id);
      pollStatus(result.task_id);
    } catch (e) {
      alert('Error: ' + e.message);
    }
    setLoading(false);
  };

  const pollStatus = async (id) => {
    const interval = setInterval(async () => {
      try {
        const s = await getAuditStatus(id);
        setStatus(s);
        if (s.status === 'completed') {
          clearInterval(interval);
          const r = await getAuditReport(id);
          setReport(r);
        }
      } catch (e) { console.log(e); }
    }, 2000);
  };

  const exportJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit-' + Date.now() + '.json';
    a.click();
  };

  return (
    <div className="app">
      <header>
        <div className="logo">
          <h1>Solidify</h1>
          <span className="badge">SECURE</span>
        </div>
        <p>Web3 Smart Contract Security Auditor</p>
      </header>
      
      <nav className="mode-tabs">
        <ModeTab mode="paste" active={mode} onClick={() => setMode('paste')} />
        <ModeTab mode="upload" active={mode} onClick={() => setMode('upload')} />
        <ModeTab mode="chain" active={mode} onClick={() => setMode('chain')} />
      </nav>

      <main>
        <section className="input-section">
          <ChainInput value={chain} onChange={setChain} />
        </section>

        {mode === 'paste' && (
          <section className="editor-section">
            <div className="section-header">
              <h3>Solidity Contract</h3>
              <button className="secondary-btn" onClick={() => setContract(SAMPLE_CONTRACT)}>Load Sample</button>
            </div>
            <CodeEditor value={contract} onChange={setContract} />
          </section>
        )}

        {mode === 'upload' && (
          <section className="upload-section">
            <FileUpload onFileLoaded={setContract} />
            <CodeEditor value={contract} onChange={setContract} />
          </section>
        )}

        {mode === 'chain' && (
          <section className="chain-section">
            <div className="address-input">
              <label>Contract Address</label>
              <input
                type="text"
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="0x..."
              />
              <p className="hint">Enter any verified contract address to fetch source from explorer</p>
            </div>
          </section>
        )}

        <div className="actions">
          <button className="audit-btn" onClick={handleAudit} disabled={loading}>
            {loading ? 'Running Audit...' : 'Start Audit'}
          </button>
          {report && (
            <>
              <button className="secondary-btn" onClick={exportJSON}>Export JSON</button>
              <button className="secondary-btn" onClick={() => alert('PDF export coming soon!')}>Export PDF</button>
            </>
          )}
        </div>

        {loading && status && <ProgressBar status={status.status} />}

        {report && <AuditReport report={report} />}
      </main>
    </div>
  );
}