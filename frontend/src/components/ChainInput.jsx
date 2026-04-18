import { useState, useEffect } from 'react';
import { getChains } from '../api';

export default function ChainInput({ value, onChange }) {
  const [chains, setChains] = useState([]);
  const [rpcUrl, setRpcUrl] = useState('');

  useEffect(() => {
    getChains().then(setChains).catch(() => setChains([
      { id: 'ethereum', name: 'Ethereum', rpc: 'https://eth.llamarpc.com' },
      { id: 'bsc', name: 'BNB Chain', rpc: 'https://bsc-dataseed.binance.org' },
      { id: 'polygon', name: 'Polygon', rpc: 'https://polygon-rpc.com' },
      { id: 'arbitrum', name: 'Arbitrum', rpc: 'https://arb1.arbitrum.io/rpc' },
      { id: 'optimism', name: 'Optimism', rpc: 'https://mainnet.optimism.io' },
    ]));
  }, []);

  const handleChainChange = (e) => {
    const chain = chains.find(c => c.id === e.target.value);
    onChange(e.target.value);
    if (chain?.rpc) setRpcUrl(chain.rpc);
  };

  return (
    <div className="chain-input">
      <label>Blockchain</label>
      <select value={value} onChange={handleChainChange}>
        <option value="">Select Chain</option>
        {chains.map(c => (
          <option key={c.id} value={c.id}>{c.name}</option>
        ))}
      </select>
      <label>RPC URL</label>
      <input
        type="text"
        value={rpcUrl}
        onChange={(e) => setRpcUrl(e.target.value)}
        placeholder="https://..."
      />
    </div>
  );
}