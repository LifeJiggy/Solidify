import { useState, useCallback, useEffect } from 'react';
import ChainInput from './components/ChainInput';
import CodeEditor from './components/CodeEditor';
import FileUpload from './components/FileUpload';
import AuditReport from './components/AuditReport';
import ChatPanel from './components/ChatPanel';
import ErrorBoundary from './components/ErrorBoundary';
import ToastContainer, { showToast } from './components/Toast';
import NetworkStatus from './components/NetworkStatus';
import ThemeToggle from './components/ThemeToggle';
import KeyboardShortcuts from './components/KeyboardShortcuts';
import ContractStats from './components/ContractStats';
import AuditHistory, { saveAuditToHistory } from './components/AuditHistory';
import SeverityFilter from './components/SeverityFilter';
import CopyButton from './components/CopyButton';
import AuditTimer from './components/AuditTimer';
import SampleContracts from './components/SampleContracts';
import AutoSaveDraft, { loadDraft } from './components/AutoSaveDraft';
import BookmarkedContracts from './components/BookmarkedContracts';
import BatchAddressInput from './components/BatchAddressInput';
import ExportHtmlReport from './components/ExportHtmlReport';
import CustomRpcInput from './components/CustomRpcInput';
import ContractCompare from './components/ContractCompare';
import AutoRefreshScan, { AutoRefreshResults } from './components/AutoRefreshScan';
import { startAudit, streamAudit, getAuditReport, exportMarkdown, getPoc, detectGas, detectFrontrun, detectOracle, chat } from './api';

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

const STATUS_LABELS = {
  queued: 'Queuing audit task...',
  connecting: 'Connecting to AI provider...',
  scanning: 'Scanning contract code...',
  analyzing: 'Analyzing vulnerabilities...',
  streaming: 'Receiving AI analysis...',
  completed: 'Finalizing report...',
  failed: 'Audit failed'
};

function StatusBar({ status }) {
  const steps = ['queued', 'connecting', 'scanning', 'analyzing', 'streaming', 'completed'];
  const idx = steps.indexOf(status || 'queued');
  return (
    <div className="progress-container">
      <div className="progress-steps">
        {steps.map((s, i) => (
          <div key={s} className={`step ${i <= idx ? 'done' : ''}`}>
            <div className="step-dot" />
            <span>{s.charAt(0).toUpperCase() + s.slice(1)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState('paste');
  const [contract, setContract] = useState(() => loadDraft() || SAMPLE_CONTRACT);
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
  const [showHistory, setShowHistory] = useState(false);
  const [showBatch, setShowBatch] = useState(false);
  const [version] = useState('1.0.0');
  const [provider, setProvider] = useState(() => localStorage.getItem('provider') || 'nvidia');
  const [model, setModel] = useState(() => localStorage.getItem('model') || 'minimaxai/minimax-m2.5');
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
  const [allExpanded, setAllExpanded] = useState(false);
  const [expandAllVulns, setExpandAllVulns] = useState(false);
  const [autoRefreshResults, setAutoRefreshResults] = useState(null);

  const handleProviderChange = useCallback((newProvider) => {
    setProvider(newProvider);
    localStorage.setItem('provider', newProvider);
    const m = providersList.find(p => p.id === newProvider)?.models?.[0];
    if (m) { setModel(m); localStorage.setItem('model', m); }
  }, [providersList]);

  const handleModelChange = useCallback((m) => { setModel(m); localStorage.setItem('model', m); }, []);
  const handleApiKeyChange = useCallback((k) => { setApiKey(k); localStorage.setItem('apiKey', k); }, []);
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('apiKey') || '');

  const handleNewSession = () => {
    const id = 'sess-' + Date.now().toString(36);
    setSessions(prev => [{ id, name: 'Session ' + (prev.length + 1), created: new Date().toLocaleDateString() }, ...prev]);
    setSessionId(id);
  };

  const getCodeOrAddress = useCallback(() => {
    if (mode === 'chain') return { address: contractAddress, chain };
    return { code: contract, chain };
  }, [mode, contract, contractAddress, chain]);

  const handleCommand = useCallback(async (cmd) => {
    setLoading(true);
    setStreamOutput('');
    setStreamProgress('Queuing...');
    setReport(null);
    setStatus(null);
    setTaskId(null);
    setAutoRefreshResults(null);

    try {
      const payload = getCodeOrAddress();
      const input = payload.code || payload.address;
      if (!input || (mode === 'chain' && !payload.address)) {
        showToast('No contract code or address provided', 'error');
        setLoading(false);
        return;
      }
      if (input.length > 100000) {
        showToast('Contract code exceeds 100KB limit', 'error');
        setLoading(false);
        return;
      }

      const result = await startAudit(input, payload.chain, {
        command: cmd, provider, model,
        ...(payload.address ? { address: payload.address } : {})
      });
      setTaskId(result.task_id);

      streamAudit(
        result.task_id,
        (chunk) => {
          if (chunk.endsWith('...\n')) {
            const label = STATUS_LABELS[chunk.replace('...\n', '')];
            setStreamProgress(label || chunk);
          } else {
            setStreamOutput(prev => prev + chunk);
          }
        },
        (auditResult) => {
          setReport(auditResult);
          setStatus({ status: 'completed' });
          setStreamProgress('Complete!');
          setStreamOutput(prev =>
            prev + '\n\n✓ Audit Complete!\n\nScore: ' + auditResult.score + '/10\nVulnerabilities: ' +
            (auditResult.vulnerabilities?.length || 0) + '\n\n' + (auditResult.summary || '')
          );
          saveAuditToHistory(contract || input, auditResult);
          setLoading(false);
        },
        (error) => {
          showToast(error || 'Audit failed', 'error');
          setStreamOutput(prev => prev + '\n[Error: ' + error + ']');
          setStreamProgress('Failed');
          setLoading(false);
        }
      );
    } catch (e) {
      showToast(e.message || 'Failed to start audit', 'error');
      setStreamOutput('Error: ' + e.message);
      setStreamProgress('Failed');
      setLoading(false);
    }
  }, [getCodeOrAddress, mode, contract, contractAddress, provider, model]);

  const handleAsk = () => setShowAskModal(true);

  const handleAskSubmit = async () => {
    if (!askQuestion.trim()) return;
    setLoading(true);
    try {
      const data = await chat(askQuestion, [], provider, model);
      setAskAnswer(data.message || data.error || 'No response');
    } catch (e) {
      setAskAnswer('Error: ' + e.message);
    }
    setLoading(false);
  };

  const handleDetect = useCallback(async (fn, label) => {
    setLoading(true);
    setStreamOutput(`Scanning for ${label}...\n`);
    setStreamProgress(`Running ${label}...`);
    try {
      const payload = getCodeOrAddress();
      const result = await fn(payload.code || payload.address);
      const issues = result.optimizations || result.vulnerabilities || [];
      setStreamOutput(issues.length > 0
        ? `${label} Results:\n\n` + issues.map(i => {
          if (i.savings) return `- ${i.type}: ${i.recommendation} (${i.savings})`;
          return `- [${i.severity || 'INFO'}] ${i.type}\n  ${i.recommendation || i.issue}`;
        }).join('\n')
        : `No ${label.toLowerCase()} issues detected.`);
      setStreamProgress('Complete');
    } catch (e) {
      setStreamOutput('Error: ' + e.message);
      setStreamProgress('Failed');
    }
    setLoading(false);
  }, [getCodeOrAddress]);

  const handleExportJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audit-' + Date.now() + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('Report exported as JSON', 'success');
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
      URL.revokeObjectURL(a.href);
      showToast('Report exported as Markdown', 'success');
    } catch { showToast('Export failed', 'error'); }
  };

  const handleGetPoc = async () => {
    if (!taskId) return;
    try {
      const pocs = await getPoc(taskId);
      if (pocs.pocs?.length > 0) {
        const blob = new Blob([pocs.pocs.map(p => p.exploit_code).join('\n\n')], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'exploits-' + Date.now() + '.sol';
        a.click();
        URL.revokeObjectURL(a.href);
        showToast(`${pocs.pocs.length} exploit(s) downloaded`, 'success');
      } else {
        showToast('No critical vulnerabilities for PoC generation', 'info');
      }
    } catch { showToast('PoC generation failed', 'error'); }
  };

  const handleHistorySelect = (item) => {
    if (item.report) {
      setReport(item.report);
      setStatus({ status: 'completed' });
      setStreamOutput(`Loaded audit from ${new Date(item.timestamp).toLocaleString()}\nScore: ${item.score}/10\nVulnerabilities: ${item.vulnCount}`);
      setStreamProgress('Loaded from history');
    }
  };

  const handleBatchScan = async (addresses) => {
    setShowBatch(false);
    setLoading(true);
    setStreamOutput('');
    setStreamProgress('');
    setReport(null);

    for (let i = 0; i < addresses.length; i++) {
      const addr = addresses[i];
      setStreamOutput(prev => prev + `\n[${i + 1}/${addresses.length}] Scanning ${addr.slice(0, 10)}...\n`);
      try {
        const result = await startAudit(addr, chain, { command: 'audit', provider, model, address: addr });
        const r = await getAuditReport(result.task_id);
        if (r.vulnerabilities && r.vulnerabilities.length > 0) {
          setStreamOutput(prev => prev + `  Score: ${r.score}/10, ${r.vulnerabilities.length} vulns\n`);
        } else {
          setStreamOutput(prev => prev + `  Score: ${r.score}/10, clean\n`);
        }
        if (i === addresses.length - 1) {
          setReport(r);
          saveAuditToHistory(addr, r);
        }
      } catch (e) {
        setStreamOutput(prev => prev + `  Error: ${e.message}\n`);
      }
    }
    setStreamOutput(prev => prev + `\n✓ Batch scan complete (${addresses.length} addresses)\n`);
    setStreamProgress('Complete');
    setLoading(false);
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const addr = params.get('address');
    if (addr && /^0x[a-fA-F0-9]{40}$/.test(addr)) {
      setMode('chain');
      setContractAddress(addr);
    }
  }, []);

  return (
    <ErrorBoundary>
      <KeyboardShortcuts onAudit={() => handleCommand('audit')} onChat={() => setShowChat(true)} onSettings={() => setShowSettings(true)} />
      <ToastContainer />
      <AutoSaveDraft code={contract} />
      <div className="app">
        <header>
          <div className="logo">
            <h1>Solidify</h1>
            <span className="badge">SECURE</span>
            <NetworkStatus />
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
          {['paste', 'upload', 'chain', 'compare'].map(m => (
            <button key={m} className={`mode-tab ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
              <span>{m === 'paste' ? 'Paste Code' : m === 'upload' ? 'Upload File' : m === 'chain' ? 'On-Chain Scan' : 'Compare'}</span>
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
                <div className="header-actions">
                  <SampleContracts onSelect={(c) => { setContract(c); showToast('Sample contract loaded', 'success'); }} />
                  <BookmarkedContracts onSelect={setContract} currentCode={contract} />
                  <AutoRefreshScan code={contract} chain={chain} provider={provider} model={model} onResults={setAutoRefreshResults} />
                  <button className="secondary-btn" onClick={() => setContract(SAMPLE_CONTRACT)}>Reset Sample</button>
                </div>
              </div>
              <ContractStats code={contract} />
              {autoRefreshResults && <AutoRefreshResults results={autoRefreshResults} />}
              <CodeEditor value={contract} onChange={setContract} />
            </section>
          )}

          {mode === 'upload' && (
            <section className="upload-section">
              <FileUpload onFileLoaded={(c) => { setContract(c); showToast('File loaded', 'success'); }} />
              <ContractStats code={contract} />
              <AutoRefreshScan code={contract} chain={chain} provider={provider} model={model} onResults={setAutoRefreshResults} />
              {autoRefreshResults && <AutoRefreshResults results={autoRefreshResults} />}
              <CodeEditor value={contract} onChange={setContract} />
            </section>
          )}

          {mode === 'compare' && <ContractCompare />}

          {mode === 'chain' && (
            <section className="chain-section">
              <div className="address-input">
                <label>Contract Address</label>
                <input
                  type="text" value={contractAddress}
                  onChange={e => setContractAddress(e.target.value)}
                  placeholder="0x..."
                  style={contractAddress && !/^0x[a-fA-F0-9]{40}$/.test(contractAddress) ? { borderColor: '#f85149' } : {}}
                />
                <p className="hint">Enter verified contract address to fetch source from explorer</p>
              </div>
              <CustomRpcInput chain={chain} />
              <button className="secondary-btn" onClick={() => setShowBatch(true)}>
                Batch Scan Multiple Addresses
              </button>
            </section>
          )}

          <div className="actions">
            <button className="audit-btn" onClick={() => handleCommand('audit')} disabled={loading}>
              {loading ? <><AuditTimer running={loading} /> Running...</> : 'Audit'}
            </button>
            <button className="cmd-btn" onClick={() => handleCommand('hunt')} disabled={loading}>Hunt</button>
            <button className="cmd-btn" onClick={() => handleCommand('scan')} disabled={loading}>Scan</button>
            <button className="cmd-btn" onClick={handleAsk}>Ask</button>
            <button className="cmd-btn" onClick={() => handleDetect(detectGas, 'Gas Optimization')}>Gas</button>
            <button className="cmd-btn" onClick={() => handleDetect(detectFrontrun, 'Front-Run')}>FrontRun</button>
            <button className="cmd-btn" onClick={() => handleDetect(detectOracle, 'Oracle')}>Oracle</button>
            {report && (
              <>
                <button className="secondary-btn" onClick={handleExportJSON}>JSON</button>
                <button className="secondary-btn" onClick={handleExportMarkdown}>Markdown</button>
                <ExportHtmlReport report={report} />
                <button className="secondary-btn" onClick={handleGetPoc}>PoC</button>
                {report.vulnerabilities && report.vulnerabilities.length > 0 && (
                  <button className="secondary-btn" onClick={() => setExpandAllVulns(p => !p)}>
                    {expandAllVulns ? 'Collapse All' : 'Expand All'}
                  </button>
                )}
              </>
            )}
            <button className="secondary-btn" onClick={() => setShowHistory(true)}>History</button>
          </div>

          {showAskModal && (
            <div className="modal-overlay" onClick={() => setShowAskModal(false)}>
              <div className="modal" onClick={e => e.stopPropagation()}>
                <h3>Ask Security Question</h3>
                <textarea
                  value={askQuestion} onChange={e => setAskQuestion(e.target.value)}
                  placeholder="How do I prevent reentrancy..." rows={4}
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleAskSubmit(); } }}
                />
                <div className="modal-actions">
                  <button onClick={() => setShowAskModal(false)}>Cancel</button>
                  <button className="primary" onClick={handleAskSubmit} disabled={!askQuestion.trim() || loading}>
                    {loading ? 'Asking...' : 'Ask AI'}
                  </button>
                </div>
                {askAnswer && (
                  <div className="ask-answer">
                    <CopyButton text={askAnswer} label="Copy" />
                    {askAnswer}
                  </div>
                )}
              </div>
            </div>
          )}

          {loading && status && <StatusBar status={status.status} />}

          {(streamOutput || streamProgress) && (
            <div className="stream-panel">
              <div className="stream-header">
                <span className="stream-status">{streamProgress || 'Processing...'}</span>
                {streamOutput && <CopyButton text={streamOutput} label="Copy Output" />}
              </div>
              <pre className="stream-content">{streamOutput || 'Waiting...'}</pre>
            </div>
          )}

          {report && (
            <SeverityFilter vulnerabilities={report.vulnerabilities}>
              {(filtered) => (
                <AuditReport
                  report={{ ...report, vulnerabilities: filtered }}
                  allExpanded={expandAllVulns}
                  onToggleAll={() => setExpandAllVulns(p => !p)}
                />
              )}
            </SeverityFilter>
          )}
        </main>

        {showBatch && (
          <div className="modal-overlay" onClick={() => setShowBatch(false)}>
            <div className="modal" onClick={e => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Batch Address Scan</h3>
                <button onClick={() => setShowBatch(false)}>X</button>
              </div>
              <BatchAddressInput onScan={handleBatchScan} />
            </div>
          </div>
        )}

        {showHistory && <AuditHistory onSelectReport={handleHistorySelect} onClose={() => setShowHistory(false)} />}

        <ChatPanel isOpen={showChat} onClose={() => setShowChat(false)} provider={provider} model={model} />

        {showSettings && (
          <div className="modal-overlay" onClick={() => setShowSettings(false)}>
            <div className="modal settings-modal" onClick={e => e.stopPropagation()}>
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
                <select value={provider} onChange={e => handleProviderChange(e.target.value)}>
                  {providersList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>

              <div className="settings-section">
                <h4>Model</h4>
                <select value={model} onChange={e => handleModelChange(e.target.value)}>
                  {modelOptions.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>

              <div className="settings-section">
                <h4>API Key</h4>
                <input type="password" value={apiKey} onChange={e => handleApiKeyChange(e.target.value)} placeholder="Enter API key" className="api-key-input" />
                <p className="api-hint">Leave empty for default. Uses env vars on server.</p>
              </div>

              <div className="settings-section">
                <h4>Appearance</h4>
                <ThemeToggle />
              </div>

              <div className="settings-section">
                <h4>Detection Features</h4>
                <div className="features-grid">
                  {['Reentrancy Detection', 'Access Control', 'Integer Overflow', 'Unchecked Calls', 'tx.origin Checks', 'Oracle Manipulation', 'Front-Run Detection', 'Gas Optimization', 'Selfdestruct', 'Delegatecall'].map(f => (
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
                <h4>Keyboard Shortcuts</h4>
                <div className="commands-list">
                  <code>Ctrl+Enter</code> - Run audit<br />
                  <code>Ctrl+Shift+C</code> - Open chat<br />
                  <code>Ctrl+,</code> - Open settings
                </div>
              </div>

              <div className="settings-section">
                <h4>Commands</h4>
                <div className="commands-list">
                  <code>audit</code> - Full contract audit<br />
                  <code>hunt</code> - Hunt vulnerabilities<br />
                  <code>scan</code> - Quick scan<br />
                  <code>ask</code> - Ask security question<br />
                  <code>chat</code> - AI chat<br />
                  <code>Gas</code> - Gas optimization scan<br />
                  <code>FrontRun</code> - MEV vulnerability scan<br />
                  <code>Oracle</code> - Oracle manipulation scan
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </ErrorBoundary>
  );
}
