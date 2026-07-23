import { useState } from 'react';
import ChainInput from './components/ChainInput';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import AuditReport from './components/AuditReport';
import ChatPanel from './components/ChatPanel';
import { startAudit, streamAudit, getAuditReport, exportMarkdown, exportPdf, getPoc, detectGas, detectFrontrun, detectOracle } from './api';

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

const STATUS_STEPS = {
  queued: 'Queuing audit task...',
  connecting: 'Connecting to AI provider...',
  scanning: 'Scanning contract code...',
  analyzing: 'Analyzing vulnerabilities...',
  streaming: 'Receiving AI analysis...',
  completed: 'Finalizing report...',
  failed: 'Audit failed'
};

function StatusBar({ status, progress }) {
  const steps = ['queued', 'connecting', 'scanning', 'analyzing', 'streaming', 'completed'];
  const currentIdx = steps.indexOf(status || 'queued');
  return (
    <div className="progress-container">
      <div className="progress-steps">
        {steps.map((step, i) => (
          <div key={step} className={`step ${i <= currentIdx ? 'done' : ''}`}>
            <div className="step-dot" />
            <span>{step.charAt(0).toUpperCase() + step.slice(1)}</span>
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
  const [provider, setProvider] = useState(() => localStorage.getItem('provider') || 'nvidia');
  const [model, setModel] = useState(() => localStorage.getItem('model') || 'minimaxai/minimax-m2.5');
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('apiKey') || '');
  const [sessionId, setSessionId] = useState(() => 'sess-' + Date.now().toString(36));
  const [sessions, setSessions] = useState(() => [{ id: 'sess-default', name: 'Session 1', created: new Date().toLocaleDateString() }]);
  const [providersList] = useState([
    { id: 'nvidia', name: 'NVIDIA / Minimax', models: ['minimaxai/minimax-m2.5', 'nvidia/llama-3.1-nemotron-70b'], status: 'active' },
    { id: 'openai', name: 'OpenAI GPT', models: ['gpt-4o', 'gpt-4-turbo', 'gpt-3.5-turbo'], status: 'available' },
    { id: 'anthropic', name: 'Anthropic Claude', models: ['claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku'], status: 'available' },
    { id: 'qwen', name: 'Qwen', models: ['qwen2.5-coder-32b', 'qwen2.5-coder-7b'], status: 'available' },
    { id: 'ollama', name: 'Ollama (Local)', models: ['llama3', 'codellama', 'mistral'], status: 'available' },
  ]);

  const currentProvider = providersList.find(p => p.id === provider);
  const modelOptions = currentProvider?.models || [];

  const handleProviderChange = (newProvider) => {
    setProvider(newProvider);
    localStorage.setItem('provider', newProvider);
    const newModel = providersList.find(p => p.id === newProvider)?.models?.[0];
    if (newModel) {
      setModel(newModel);
      localStorage.setItem('model', newModel);
    }
  };

  const handleModelChange = (newModel) => {
    setModel(newModel);
    localStorage.setItem('model', newModel);
  };

  const handleApiKeyChange = (key) => {
    setApiKey(key);
    localStorage.setItem('apiKey', key);
  };

  const handleNewSession = () => {
    const newId = 'sess-' + Date.now().toString(36);
    setSessions([{ id: newId, name: 'Session ' + (sessions.length + 1), created: new Date().toLocaleDateString() }, ...sessions]);
    setSessionId(newId);
  };

  const getCodeOrAddress = () => {
    if (mode === 'chain') return { address: contractAddress, chain };
    return { code: contract, chain };
  };

  const handleCommand = async (cmd) => {
    setLoading(true);
    setStreamOutput('→ Starting audit with ' + provider + ' / ' + model + '\n');
    setStreamProgress('Queuing...');
    setReport(null);
    setStatus(null);

    try {
      const payload = getCodeOrAddress();
      const result = await startAudit(
        payload.code || payload.address,
        payload.chain,
        { command: cmd, provider, model, ...(payload.address ? { address: payload.address } : {}) }
      );
      setTaskId(result.task_id);

      streamAudit(
        result.task_id,
        (chunk) => {
          if (chunk.endsWith('...\n')) {
            setStreamProgress(STATUS_STEPS[chunk.replace('...\n', '')] || chunk);
          } else {
            setStreamOutput(prev => prev + chunk);
          }
        },
        (auditResult) => {
          setReport(auditResult);
          setStatus({ status: 'completed' });
          setStreamProgress('Complete!');
          setStreamOutput(prev => prev + '\n\n✓ Audit Complete!\n\n' +
            'Score: ' + auditResult.score + '/10\n' +
            'Vulnerabilities: ' + (auditResult.vulnerabilities?.length || 0) + '\n\n' +
            (auditResult.summary || ''));
          setLoading(false);
        },
        (error) => {
          setStreamOutput(prev => prev + '\n[Error: ' + error + ']');
          setStreamProgress('Failed');
          setLoading(false);
        }
      );
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
      setStreamProgress('Failed');
      setLoading(false);
    }
  };

  const handleAsk = () => setShowAskModal(true);

  const handleAskSubmit = async () => {
    setLoading(true);
    try {
      const result = await startAudit(askQuestion, chain, { command: 'ask', provider, model });
      const r = await getAuditReport(result.task_id);
      setAskAnswer(r.summary || r.vulnerabilities?.[0]?.description || 'No answer');
    } catch (e) {
      setAskAnswer('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetectGas = async () => {
    setLoading(true);
    setStreamOutput('Scanning for gas optimizations...\n');
    try {
      const payload = getCodeOrAddress();
      const result = await detectGas(payload.code || payload.address);
      const issues = result.optimizations || [];
      setStreamOutput(issues.length > 0
        ? 'Gas Optimizations Found:\n\n' + issues.map(i => '- ' + i.type + ': ' + i.recommendation + ' (' + i.savings + ')').join('\n')
        : 'No gas optimizations found. Code looks efficient!');
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetectFrontrun = async () => {
    setLoading(true);
    setStreamOutput('Scanning for front-run vulnerabilities...\n');
    try {
      const payload = getCodeOrAddress();
      const result = await detectFrontrun(payload.code || payload.address);
      const issues = result.vulnerabilities || [];
      setStreamOutput(issues.length > 0
        ? 'Front-Run Risks Found:\n\n' + issues.map(i => '- [' + i.severity + '] ' + i.type + '\n  ' + i.recommendation).join('\n')
        : 'No front-run vulnerabilities detected.');
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetectOracle = async () => {
    setLoading(true);
    setStreamOutput('Scanning for oracle manipulation risks...\n');
    try {
      const payload = getCodeOrAddress();
      const result = await detectOracle(payload.code || payload.address);
      const issues = result.vulnerabilities || [];
      setStreamOutput(issues.length > 0
        ? 'Oracle Risks Found:\n\n' + issues.map(i => '- [' + i.severity + '] ' + i.type + '\n  ' + i.recommendation).join('\n')
        : 'No oracle manipulation risks detected.');
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
    }
    setLoading(false);
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
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'audit-' + Date.now() + '.md';
      a.click();
    } catch (e) {
      alert('Export failed: ' + e.message);
    }
  };

  const handleExportPdf = async () => {
    if (!taskId) return;
    try {
      const txt = await exportPdf(taskId);
      const blob = new Blob([txt], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'audit-' + Date.now() + '.txt';
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
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'exploits-' + Date.now() + '.sol';
        a.click();
      } else {
        alert('No critical vulnerabilities for PoC generation');
      }
    } catch (e) {
      alert('PoC generation failed: ' + e.message);
    }
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
          <span className="session">Session: {sessionId.slice(0, 8)}</span>
          <button className="settings-btn" onClick={() => setShowSettings(true)}>Settings</button>
          <button className="chat-toggle" onClick={() => setShowChat(true)}>Chat with AI</button>
        </div>
      </header>

      <nav className="mode-tabs">
        {['paste', 'upload', 'chain'].map(m => (
          <button key={m} className={`mode-tab ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
            <span>{m === 'paste' ? 'Paste Code' : m === 'upload' ? 'Upload File' : 'On-Chain Scan'}</span>
          </button>
        ))}
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
              <input type="text" value={contractAddress} onChange={(e) => setContractAddress(e.target.value)} placeholder="0x..." />
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
              <textarea value={askQuestion} onChange={(e) => setAskQuestion(e.target.value)} placeholder="How do I prevent reentrancy..." />
              <div className="modal-actions">
                <button onClick={() => setShowAskModal(false)}>Cancel</button>
                <button className="primary" onClick={handleAskSubmit}>Ask AI</button>
              </div>
              {askAnswer && <div className="ask-answer">{askAnswer}</div>}
            </div>
          </div>
        )}

        {loading && status && <StatusBar status={status.status} progress={status.progress} />}

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

      <ChatPanel isOpen={showChat} onClose={() => setShowChat(false)} provider={provider} model={model} />

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
              <select value={provider} onChange={(e) => handleProviderChange(e.target.value)}>
                {providersList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>

            <div className="settings-section">
              <h4>Model</h4>
              <select value={model} onChange={(e) => handleModelChange(e.target.value)}>
                {modelOptions.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>

            <div className="settings-section">
              <h4>API Key</h4>
              <input type="password" value={apiKey} onChange={(e) => handleApiKeyChange(e.target.value)} placeholder="Enter API key (optional for default)" className="api-key-input" />
              <p className="api-hint">Leave empty to use default. Add key for BYOA.</p>
            </div>

            <div className="settings-section">
              <h4>Detection Features</h4>
              <div className="features-grid">
                {['Reentrancy Detection', 'Access Control', 'Integer Overflow', 'Unchecked Calls', 'tx.origin Checks', 'Oracle Manipulation', 'Front-Run Detection', 'Gas Optimization'].map(f => (
                  <div key={f} className="feature-item">{f}</div>
                ))}
              </div>
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
                <code>audit</code> - Full contract audit<br />
                <code>hunt</code> - Hunt vulnerabilities<br />
                <code>scan</code> - Quick scan<br />
                <code>ask</code> - Ask security question<br />
                <code>chat</code> - AI chat
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
