import { useState, useEffect } from 'react';
import { getChains } from '../api';

export default function ChainInput({ value, onChange }) {
  const [chains, setChains] = useState([]);

  useEffect(() => {
    getChains().then(setChains).catch(() => setChains([
      { id: 'ethereum', name: 'Ethereum' },
      { id: 'bsc', name: 'BNB Chain' },
      { id: 'polygon', name: 'Polygon' },
      { id: 'arbitrum', name: 'Arbitrum' },
      { id: 'optimism', name: 'Optimism' },
    ]));
  }, []);

  return (
    <div className="chain-input">
      <label>Blockchain</label>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Select Chain</option>
        {chains.map(c => (
          <option key={c.id} value={c.id}>{c.name}</option>
        ))}
      </select>
    </div>
  );
}
