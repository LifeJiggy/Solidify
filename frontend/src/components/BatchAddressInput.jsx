import { useState } from 'react';
import { showToast } from './Toast';

export default function BatchAddressInput({ onScan }) {
  const [addresses, setAddresses] = useState('');
  const [parsed, setParsed] = useState([]);

  const parseAddresses = (val) => {
    setAddresses(val);
    const addrs = val.split(/[\n,;\s]+/).filter(a => /^0x[a-fA-F0-9]{40}$/.test(a.trim()));
    setParsed(addrs);
  };

  const handleScan = () => {
    if (parsed.length === 0) {
      showToast('No valid addresses found', 'error');
      return;
    }
    onScan(parsed);
  };

  return (
    <div className="batch-input">
      <textarea
        value={addresses}
        onChange={e => parseAddresses(e.target.value)}
        placeholder="Paste contract addresses (one per line or comma separated)&#10;0x123...&#10;0x456..."
        rows={4}
      />
      {parsed.length > 0 && (
        <p className="batch-count">{parsed.length} valid address{parsed.length !== 1 ? 'es' : ''} detected</p>
      )}
      <button className="audit-btn" onClick={handleScan} disabled={parsed.length === 0}>
        Scan {parsed.length > 0 ? `(${parsed.length})` : ''} Addresses
      </button>
    </div>
  );
}
