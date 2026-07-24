import { useMemo } from 'react';

export default function ContractStats({ code }) {
  const stats = useMemo(() => {
    if (!code) return null;
    const lines = code.split('\n');
    const nonEmpty = lines.filter(l => l.trim()).length;
    const contracts = (code.match(/\bcontract\s+\w+/g) || []).length;
    const interfaces = (code.match(/\binterface\s+\w+/g) || []).length;
    const libraries = (code.match(/\blibrary\s+\w+/g) || []).length;
    const functions = (code.match(/\bfunction\s+\w+/g) || []).length;
    const mappings = (code.match(/\bmapping\s*\(/g) || []).length;
    const events = (code.match(/\bevent\s+\w+/g) || []).length;
    const modifiers = (code.match(/\bmodifier\s+\w+/g) || []).length;
    const imports = (code.match(/\bimport\s/g) || []).length;
    return { lines: lines.length, nonEmpty, contracts, interfaces, libraries, functions, mappings, events, modifiers, imports };
  }, [code]);

  if (!stats) return null;

  return (
    <div className="contract-stats">
      <span title="Total lines">{stats.lines} lines</span>
      <span title="Contracts">{stats.contracts} contract{stats.contracts !== 1 ? 's' : ''}</span>
      <span title="Functions">{stats.functions} funcs</span>
      {stats.imports > 0 && <span title="Imports">{stats.imports} imports</span>}
      {stats.mappings > 0 && <span title="Mappings">{stats.mappings} mappings</span>}
      {stats.events > 0 && <span title="Events">{stats.events} events</span>}
      {stats.modifiers > 0 && <span title="Modifiers">{stats.modifiers} modifiers</span>}
    </div>
  );
}
