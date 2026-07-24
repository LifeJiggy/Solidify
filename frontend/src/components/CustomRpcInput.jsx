import { useState, useEffect } from 'react';

const RPC_KEY = 'solidify_custom_rpc';

const DEFAULT_RPCS = {
  ethereum: 'https://eth.llamarpc.com',
  bsc: 'https://bsc-dataseed.binance.org',
  polygon: 'https://polygon-rpc.com',
  arbitrum: 'https://arb1.arbitrum.io/rpc',
  optimism: 'https://mainnet.optimism.io',
};

export function getRpcUrl(chain) {
  try {
    const stored = localStorage.getItem(RPC_KEY);
    if (stored) return stored;
  } catch {}
  return DEFAULT_RPCS[chain] || '';
}

export default function CustomRpcInput({ chain, onRpcChange }) {
  const [rpc, setRpc] = useState(() => getRpcUrl(chain));

  useEffect(() => {
    if (rpc) localStorage.setItem(RPC_KEY, rpc);
    if (onRpcChange) onRpcChange(rpc);
  }, [rpc, chain, onRpcChange]);

  useEffect(() => {
    if (!localStorage.getItem(RPC_KEY)) {
      setRpc(DEFAULT_RPCS[chain] || '');
    }
  }, [chain]);

  return (
    <div className="rpc-input">
      <label>RPC URL</label>
      <input
        type="text"
        value={rpc}
        onChange={e => setRpc(e.target.value)}
        placeholder={DEFAULT_RPCS[chain] || 'https://...'}
      />
    </div>
  );
}
