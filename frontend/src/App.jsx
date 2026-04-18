import { useState } from 'react';
import ChainInput from './components/ChainInput';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import AuditReport from './components/AuditReport';
import ChatPanel from './components/ChatPanel';
import { startAudit, getAuditStatus, getAuditReport, exportMarkdown, exportPdf, getPoc, detectGas, detectFrontrun, detectOracle } from './api';

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
  const [streamOutput, setStreamOutput] = useState('');
  const [streamProgress, setStreamProgress] = useState('');
  const [showAskModal, setShowAskModal] = useState(false);
  const [askQuestion, setAskQuestion] = useState('');
  const [askAnswer, setAskAnswer] = useState('');
  const [showChat, setShowChat] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [version] = useState('1.0.0');
  const [provider, setProvider] = useState('nvidia');
  const [sessionId, setSessionId] = useState(() => 'sess-' + Date.now().toString(36));
  const [providersList] = useState([
    { id: 'nvidia', name: 'NVIDIA (Minimax)', status: 'active' },
    { id: 'openai', name: 'OpenAI (GPT)', status: 'available' },
    { id: 'anthropic', name: 'Anthropic (Claude)', status: 'available' },
    { id: 'qwen', name: 'Qwen', status: 'available' },
    { id: 'ollama', name: 'Ollama (Local)', status: 'available' },
  ]);
  const [sessions, setSessions] = useState([
    { id: sessionId, name: 'Current', created: new Date().toLocaleDateString() },
  ]);

  const handleNewSession = () => {
    const newId = 'sess-' + Date.now().toString(36);
    setSessions([{ id: newId, name: 'Session ' + (sessions.length + 1), created: new Date().toLocaleDateString() }, ...sessions]);
    setSessionId(newId);
  };

  const handleCommand = async (cmd) => {
    setLoading(true);
    setStreamOutput('Starting ' + cmd + '...\n');
    setStreamProgress('Starting');
    try {
      const result = await startAudit(contract, chain, { command: cmd });
      setTaskId(result.task_id);
      
      // Stream results in real-time
      const interval = setInterval(async () => {
        try {
          const s = await getAuditStatus(result.task_id);
          setStatus(s);
          setStreamProgress(s.status + ' (' + s.progress + '%)');
          setStreamOutput(prev => prev + '\n' + s.status + '...');
          
          if (s.status === 'completed') {
            clearInterval(interval);
            const r = await getAuditReport(result.task_id);
            setReport(r);
            setStreamOutput('Complete!\n\n' + (r.summary || 'Audit done') + '\n\nVulnerabilities: ' + (r.vulnerabilities?.length || 0));
          }
        } catch (e) {
          console.log(e);
        }
      }, 1500);
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleAsk = () => setShowAskModal(true);

  const handleAskSubmit = async () => {
    setLoading(true);
    try {
      const result = await startAudit(askQuestion, chain, { command: 'ask' });
      const r = await getAuditReport(result.task_id);
      setAskAnswer(r.summary || r.vulnerabilities?.[0]?.description || 'No answer');
    } catch (e) {
      setAskAnswer('Error: ' + e.message);
    }
    setLoading(false);
  };

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

  const handleExportMarkdown = async () => {
    if (!taskId) return;
    try {
      const md = await exportMarkdown(taskId);
      const blob = new Blob([md], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit-' + Date.now() + '.md';
      a.click();
    } catch (e) {
      alert('Export failed: ' + e.message);
    }
  };

  const handleExportPdf = async () => {
    if (!taskId) return;
    try {
      const pdf = await exportPdf(taskId);
      const blob = new Blob([pdf], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit-' + Date.now() + '.pdf';
      a.click();
    } catch (e) {
      alert('Export failed: ' + e.message);
    }
  };

  const handleGetPoc = async () => {
    if (!taskId) return;
    try {
      const pocs = await getPoc(taskId);
      if (pocs.pocs?.length > 0) {
        const pocContent = pocs.pocs.map(p => p.exploit_code).join('\n\n');
        const blob = new Blob([pocContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'exploits-' + Date.now() + '.sol';
        a.click();
      } else {
        alert('No critical vulnerabilities for PoC generation');
      }
    } catch (e) {
      alert('PoC generation failed: ' + e.message);
    }
  };

  const handleDetectGas = async () => {
    setLoading(true);
    setStreamOutput('Scanning for gas optimizations...\n');
    try {
      const result = await detectGas(contract);
      const issues = result.optimizations || [];
      if (issues.length > 0) {
        setStreamOutput('Gas Optimizations Found:\n\n' + issues.map(i => '- ' + i.type + ': ' + i.recommendation + ' (' + i.savings + ')').join('\n'));
      } else {
        setStreamOutput('No gas optimizations found. Code looks efficient!');
      }
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetectFrontrun = async () => {
    setLoading(true);
    setStreamOutput('Scanning for front-run vulnerabilities...\n');
    try {
      const result = await detectFrontrun(contract);
      const issues = result.vulnerabilities || [];
      if (issues.length > 0) {
        setStreamOutput('Front-Run Risks Found:\n\n' + issues.map(i => '- [' + i.severity + '] ' + i.type + '\n  ' + i.recommendation).join('\n'));
      } else {
        setStreamOutput('No front-run vulnerabilities detected.');
      }
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetectOracle = async () => {
    setLoading(true);
    setStreamOutput('Scanning for oracle manipulation risks...\n');
    try {
      const result = await detectOracle(contract);
      const issues = result.vulnerabilities || [];
      if (issues.length > 0) {
        setStreamOutput('Oracle Risks Found:\n\n' + issues.map(i => '- [' + i.severity + '] ' + i.type + '\n  ' + i.recommendation).join('\n'));
      } else {
        setStreamOutput('No oracle manipulation risks detected.');
      }
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  return (
    <div className="app">
      <header>
        <div className="logo">
          <h1>Solidify</h1>
          <span className="badge">SECURE</span>
        </div>
        <p>Web3 Smart Contract Security Auditor</p>
        <div className="top-bar">
          <span className="version">v{version}</span>
          <span className="provider">AI: {provider}</span>
          <span className="session">Session: {sessionId.slice(0,8)}</span>
          <button className="settings-btn" onClick={() => setShowSettings(true)}>Settings</button>
          <button className="chat-toggle" onClick={() => setShowChat(true)}>Chat with AI</button>
        </div>
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
          <button className="audit-btn" onClick={() => handleCommand('audit')} disabled={loading}>
            {loading ? 'Running...' : 'Audit'}
          </button>
          <button className="cmd-btn" onClick={() => handleCommand('hunt')} disabled={loading}>Hunt</button>
          <button className="cmd-btn" onClick={() => handleCommand('scan')} disabled={loading}>Scan</button>
          <button className="cmd-btn" onClick={handleAsk}>Ask</button>
          <button className="cmd-btn" onClick={handleDetectGas}>Gas</button>
          <button className="cmd-btn" onClick={handleDetectFrontrun}>FrontRun</button>
          <button className="cmd-btn" onClick={handleDetectOracle}>Oracle</button>
          {report && (
            <>
              <button className="secondary-btn" onClick={exportJSON}>JSON</button>
              <button className="secondary-btn" onClick={handleExportMarkdown}>Markdown</button>
              <button className="secondary-btn" onClick={handleExportPdf}>PDF</button>
              <button className="secondary-btn" onClick={handleGetPoc}>PoC Exploits</button>
            </>
          )}
        </div>

        {showAskModal && (
          <div className="modal-overlay">
            <div className="modal">
              <h3>Ask Security Question</h3>
              <textarea
                value={askQuestion}
                onChange={(e) => setAskQuestion(e.target.value)}
                placeholder="How do I prevent reentrancy..."
              />
              <div className="modal-actions">
                <button onClick={() => setShowAskModal(false)}>Cancel</button>
                <button className="primary" onClick={handleAskSubmit}>Ask AI</button>
              </div>
              {askAnswer && <div className="ask-answer">{askAnswer}</div>}
            </div>
          </div>
        )}

        {loading && status && <ProgressBar status={status.status} />}
        
        {(streamOutput || streamProgress) && (
          <div className="stream-panel">
            <div className="stream-header">
              <span className="stream-status">{streamProgress || 'Processing...'}</span>
            </div>
            <pre className="stream-content">{streamOutput}</pre>
          </div>
        )}

        {report && <AuditReport report={report} />}
      </main>
      
      <ChatPanel isOpen={showChat} onClose={() => setShowChat(false)} />
      
      {showSettings && (
        <div className="modal-overlay">
          <div className="modal settings-modal">
            <div className="modal-header">
              <h3>Settings</h3>
              <button onClick={() => setShowSettings(false)}>X</button>
            </div>
            
            <div className="settings-section">
              <h4>Solidify v{version}</h4>
              <p className="tagline">Web3 Smart Contract Security Auditor</p>
            </div>
            
            <div className="settings-section">
              <h4>AI Provider</h4>
              <select value={provider} onChange={(e) => setProvider(e.target.value)}>
                {providersList.map(p => (
                  <option key={p.id} value={p.id}>{p.name} ({p.status})</option>
                ))}
              </select>
            </div>
            
            <div className="settings-section">
              <h4>Sessions</h4>
              <div className="sessions-list">
                {sessions.map(s => (
                  <div key={s.id} className={'session-item ' + (s.id === sessionId ? 'active' : '')}>
                    <span>{s.name}</span>
                    <span className="session-date">{s.created}</span>
                  </div>
                ))}
              </div>
              <button className="secondary-btn" onClick={handleNewSession}>New Session</button>
            </div>
            
            <div className="settings-section">
              <h4>Available Commands</h4>
              <div className="commands-list">
                <code>audit</code> - Full contract audit<br/>
                <code>hunt</code> - Hunt vulnerabilities<br/>
                <code>scan</code> - Quick scan<br/>
                <code>ask</code> - Ask security question<br/>
                <code>chat</code> - AI chat
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}