import { useState } from 'react';
import type { LanguageInfo } from '../../api/client';

export interface Ruleset {
  name: string;
  value: string;
  enabled: boolean;
}

const RULESETS_BY_LANGUAGE: Record<string, Ruleset[]> = {
  typescript: [
    { name: 'XSS', value: 'p/xss', enabled: false },
    { name: 'SQL Injection', value: 'p/sql-injection', enabled: false },
    { name: 'OWASP Top 10', value: 'p/owasp-top-ten', enabled: false },
    { name: 'TypeScript', value: 'p/typescript', enabled: false },
    { name: 'JavaScript', value: 'p/javascript', enabled: false },
    { name: 'Command Injection', value: 'p/command-injection', enabled: false },
  ],
  javascript: [
    { name: 'XSS', value: 'p/xss', enabled: false },
    { name: 'SQL Injection', value: 'p/sql-injection', enabled: false },
    { name: 'OWASP Top 10', value: 'p/owasp-top-ten', enabled: false },
    { name: 'JavaScript', value: 'p/javascript', enabled: false },
    { name: 'Command Injection', value: 'p/command-injection', enabled: false },
  ],
  python: [
    { name: 'Python', value: 'p/python', enabled: false },
    { name: 'Bandit', value: 'p/bandit', enabled: false },
    { name: 'OWASP Top 10', value: 'p/owasp-top-ten', enabled: false },
    { name: 'XSS', value: 'p/xss', enabled: false },
    { name: 'Flask Security', value: 'p/flask-security', enabled: false },
  ],
};

interface ScannerConfigPanelProps {
  languages: LanguageInfo[];
  onChange: (semgrepConfig: string) => void;
}

export function ScannerConfigPanel({ languages, onChange }: ScannerConfigPanelProps) {
  const [rulesets, setRulesets] = useState<Record<string, Ruleset[]>>(() => {
    const initial: Record<string, Ruleset[]> = {};
    for (const lang of languages) {
      const defaults = RULESETS_BY_LANGUAGE[lang.language];
      if (defaults) {
        initial[lang.language] = defaults.map((r) => ({ ...r }));
      }
    }
    return initial;
  });
  const [customName, setCustomName] = useState('');
  const [customValue, setCustomValue] = useState('');

  const toggleRuleset = (lang: string, idx: number) => {
    setRulesets((prev) => {
      const next = { ...prev };
      next[lang] = [...next[lang]];
      next[lang][idx] = { ...next[lang][idx], enabled: !next[lang][idx].enabled };
      emitChange(next);
      return next;
    });
  };

  const addCustom = () => {
    if (!customName.trim() || !customValue.trim()) return;
    const newRule: Ruleset = { name: customName.trim(), value: customValue.trim(), enabled: true };
    setRulesets((prev) => {
      const next = { ...prev };
      const key = '_custom';
      next[key] = [...(next[key] || []), newRule];
      emitChange(next);
      return next;
    });
    setCustomName('');
    setCustomValue('');
  };

  const emitChange = (rs: Record<string, Ruleset[]>) => {
    const selected = Object.values(rs)
      .flat()
      .filter((r) => r.enabled)
      .map((r) => r.value);
    const unique = [...new Set(selected)];
    onChange(unique.join(' '));
  };

  const anySelected = Object.values(rulesets).flat().some((r) => r.enabled);

  const langColors: Record<string, string> = {
    typescript: 'text-blue-400 border-blue-500/30',
    javascript: 'text-yellow-400 border-yellow-500/30',
    python: 'text-green-400 border-green-500/30',
  };

  return (
    <div className="mt-3 p-3 bg-slate-800/40 border border-slate-700/50 rounded-lg space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-medium text-slate-400 uppercase tracking-wide">Scanner Configuration</h4>
        {!anySelected && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            using --config auto (default)
          </span>
        )}
      </div>

      {Object.entries(rulesets).filter(([k]) => k !== '_custom').map(([lang, rules]) => (
        <div key={lang} className={`border-l-2 pl-3 ${langColors[lang] || 'text-slate-400 border-slate-600'}`}>
          <span className="text-xs font-medium capitalize">{lang}</span>
          <div className="flex flex-wrap gap-2 mt-1.5">
            {rules.map((rule, i) => (
              <label
                key={rule.value}
                className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs cursor-pointer transition-colors ${
                  rule.enabled
                    ? 'bg-blue-500/15 text-blue-300 border border-blue-500/30'
                    : 'bg-slate-800 text-slate-500 border border-slate-700'
                }`}
              >
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={() => toggleRuleset(lang, i)}
                  className="accent-blue-500 w-3 h-3"
                />
                {rule.name}
                <span className="text-[10px] text-slate-600 ml-0.5">{rule.value}</span>
              </label>
            ))}
          </div>
        </div>
      ))}

      {(rulesets['_custom']?.length ?? 0) > 0 && (
        <div className="border-l-2 pl-3 text-slate-400 border-slate-600">
          <span className="text-xs font-medium">Custom</span>
          <div className="flex flex-wrap gap-2 mt-1.5">
            {rulesets['_custom'].map((rule, i) => (
              <label
                key={rule.value}
                className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs cursor-pointer transition-colors ${
                  rule.enabled
                    ? 'bg-blue-500/15 text-blue-300 border border-blue-500/30'
                    : 'bg-slate-800 text-slate-500 border border-slate-700'
                }`}
              >
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={() => toggleRuleset('_custom', i)}
                  className="accent-blue-500 w-3 h-3"
                />
                {rule.name}
                <span className="text-[10px] text-slate-600 ml-0.5">{rule.value}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-end gap-2 pt-1">
        <div className="flex-1">
          <label className="block text-[10px] text-slate-500 mb-0.5">Name</label>
          <input
            type="text"
            value={customName}
            onChange={(e) => setCustomName(e.target.value)}
            placeholder="My Ruleset"
            className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-300 placeholder:text-slate-600"
          />
        </div>
        <div className="flex-1">
          <label className="block text-[10px] text-slate-500 mb-0.5">Value (Semgrep config)</label>
          <input
            type="text"
            value={customValue}
            onChange={(e) => setCustomValue(e.target.value)}
            placeholder="p/my-custom-pack"
            className="w-full bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-300 placeholder:text-slate-600"
          />
        </div>
        <button
          type="button"
          onClick={addCustom}
          disabled={!customName.trim() || !customValue.trim()}
          className="px-3 py-1 text-xs bg-slate-700 hover:bg-slate-600 rounded text-slate-300 disabled:opacity-30 whitespace-nowrap"
        >
          + Add
        </button>
      </div>
    </div>
  );
}
