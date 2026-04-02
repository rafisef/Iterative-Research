import { useCallback, useEffect, useState } from 'react';
import { actionsApi, envApi, referenceApi, runsApi, type EnvVar } from '../api/client';
import { Autocomplete } from '../components/common/Autocomplete';
import { CollapsibleSection } from '../components/common/CollapsibleSection';
import { Spinner } from '../components/common/Spinner';
import { LogViewer } from '../components/logs/LogViewer';
import type { Agent, Run } from '../types';

export function ToolsPage() {
  return (
    <div className="max-w-3xl">
      <h2 className="text-2xl font-bold text-white mb-1">Tools</h2>
      <p className="text-sm text-slate-400 mb-6">Environment variables, LLM connectivity, and utilities</p>

      <EnvVarManager />
      <TestLLMSection />
      <NucleiRescanSection />
    </div>
  );
}

// ── Environment variable manager ────────────────────────────────────────────

function EnvVarManager() {
  const [vars, setVars] = useState<EnvVar[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingVar, setEditingVar] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');
  const [saving, setSaving] = useState(false);

  const fetchVars = useCallback(async () => {
    try {
      const data = await envApi.list();
      setVars(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchVars(); }, [fetchVars]);

  const handleSave = async (name: string) => {
    if (!editValue.trim()) return;
    setSaving(true);
    try {
      await envApi.set(name, editValue.trim());
      setEditingVar(null);
      setEditValue('');
      await fetchVars();
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (name: string) => {
    try {
      await envApi.delete(name);
      await fetchVars();
    } catch {
      // ignore
    }
  };

  return (
    <CollapsibleSection title="LLM Provider API Keys" count={vars.filter((v) => v.is_set).length} defaultOpen>
      {loading ? (
        <div className="flex justify-center py-4"><Spinner /></div>
      ) : (
        <div className="space-y-3">
          {vars.map((v) => (
            <div key={v.name} className="flex items-center gap-3 bg-slate-800/50 rounded-lg px-4 py-3 border border-slate-700/50">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full flex-shrink-0 ${v.is_set ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  <code className="text-sm text-slate-200 font-mono">{v.name}</code>
                </div>
                <p className="text-xs text-slate-500 mt-0.5 ml-4">
                  Model: {v.default_model}
                </p>
              </div>

              {editingVar === v.name ? (
                <div className="flex items-center gap-2">
                  <input
                    type="password"
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    placeholder="sk-..."
                    className="w-56 bg-slate-900 border border-slate-600 rounded px-2 py-1.5 text-xs text-slate-200 font-mono placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                    autoFocus
                    onKeyDown={(e) => e.key === 'Enter' && handleSave(v.name)}
                  />
                  <button
                    onClick={() => handleSave(v.name)}
                    disabled={saving || !editValue.trim()}
                    className="px-2 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 rounded text-white disabled:opacity-50"
                  >
                    {saving ? <Spinner size="sm" /> : 'Save'}
                  </button>
                  <button
                    onClick={() => { setEditingVar(null); setEditValue(''); }}
                    className="px-2 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  {v.is_set && (
                    <span className="text-xs text-emerald-400 px-2 py-0.5 bg-emerald-500/10 rounded border border-emerald-500/20">
                      configured
                    </span>
                  )}
                  <button
                    onClick={() => { setEditingVar(v.name); setEditValue(''); }}
                    className="px-2 py-1.5 text-xs text-blue-400 hover:text-blue-300 border border-blue-500/30 rounded hover:bg-blue-500/10"
                  >
                    {v.is_set ? 'Update' : 'Set'}
                  </button>
                  {v.is_set && (
                    <button
                      onClick={() => handleDelete(v.name)}
                      className="px-2 py-1.5 text-xs text-red-400 hover:text-red-300 border border-red-500/30 rounded hover:bg-red-500/10"
                    >
                      Remove
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
          <p className="text-xs text-slate-500 mt-2">
            API keys are set in the running backend process. They persist until the server restarts.
          </p>
        </div>
      )}
    </CollapsibleSection>
  );
}

// ── Test LLM connectivity ───────────────────────────────────────────────────

function TestLLMSection() {
  const [model, setModel] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activePid, setActivePid] = useState<number | null>(null);
  const [availableModels, setAvailableModels] = useState<string[]>([]);

  const refreshModels = useCallback(async () => {
    try {
      const res = await referenceApi.availableModels();
      setAvailableModels(res.models);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => { refreshModels(); }, [refreshModels]);

  const handleStart = async () => {
    setLoading(true);
    try {
      const res = await actionsApi.startTestLLM({ model: model || undefined });
      setActiveRunId(res.run_id);
      setActivePid(res.pid);
    } catch {
      // error shown in logs
    } finally {
      setLoading(false);
    }
  };

  const handleKill = async () => {
    if (activePid) {
      await actionsApi.killProcess(activePid);
      setActivePid(null);
    }
  };

  return (
    <CollapsibleSection title="Test LLM Connectivity">
      <div className="space-y-4">
        <p className="text-sm text-slate-400">
          Makes a single LLM call to verify your API key and connectivity. Nothing is written to disk.
        </p>
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs font-medium text-slate-400 mb-1">Model</label>
            <Autocomplete
              value={model}
              onChange={setModel}
              suggestions={['all', ...availableModels]}
              placeholder="gpt-4o (default from config)"
            />
            {availableModels.length === 0 && (
              <p className="text-xs text-amber-400 mt-1">No provider API keys detected. Set them above first.</p>
            )}
          </div>
          <button
            onClick={handleStart}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium disabled:opacity-50"
          >
            {loading ? <Spinner size="sm" /> : null}
            Test
          </button>
          {activePid && (
            <button
              onClick={handleKill}
              className="px-3 py-2 text-sm bg-red-600 hover:bg-red-700 rounded-lg text-white"
            >
              Kill
            </button>
          )}
        </div>
        {activeRunId && (
          <div className="mt-3">
            <LogViewer runId={activeRunId} />
          </div>
        )}
      </div>
    </CollapsibleSection>
  );
}

// ── Nuclei rescan ───────────────────────────────────────────────────────────

function NucleiRescanSection() {
  const [runId, setRunId] = useState('');
  const [scanAll, setScanAll] = useState(false);
  const [agent, setAgent] = useState('');
  const [minSeverity, setMinSeverity] = useState('low');
  const [loading, setLoading] = useState(false);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activePid, setActivePid] = useState<number | null>(null);
  const [existingRuns, setExistingRuns] = useState<Run[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);

  const refreshData = useCallback(async () => {
    const [runs, agentList] = await Promise.all([
      runsApi.list().catch(() => [] as Run[]),
      referenceApi.agents().catch(() => [] as Agent[]),
    ]);
    setExistingRuns(runs);
    setAgents(agentList);
  }, []);

  useEffect(() => { refreshData(); }, [refreshData]);

  const handleStart = async () => {
    setLoading(true);
    try {
      const res = await actionsApi.startNucleiRescan({
        run_id: runId || undefined,
        scan_all: scanAll,
        agent: agent || undefined,
        min_severity: minSeverity,
      });
      setActiveRunId(res.run_id);
      setActivePid(res.pid);
    } catch {
      // error shown in logs
    } finally {
      setLoading(false);
    }
  };

  const handleKill = async () => {
    if (activePid) {
      await actionsApi.killProcess(activePid);
      setActivePid(null);
    }
  };

  return (
    <CollapsibleSection title="Nuclei Rescan">
      <div className="space-y-4">
        <p className="text-sm text-slate-400">
          Run Nuclei dynamic scanning against snippets from a completed run. By default only scans iterations where static scanners found issues.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Run ID (blank = latest)</label>
            <Autocomplete
              value={runId}
              onChange={setRunId}
              suggestions={existingRuns.map((r) => r.id)}
              placeholder="2026-04-01_11-34-04"
              secondaryText={(id) => existingRuns.find((r) => r.id === id)?.model ?? undefined}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Agent filter (optional)</label>
            <Autocomplete
              value={agent}
              onChange={setAgent}
              suggestions={agents.map((a) => a.id)}
              placeholder="e.g. ambiguous"
              secondaryText={(id) => {
                const a = agents.find((ag) => ag.id === id);
                return a?.description ? a.description.slice(0, 40) : undefined;
              }}
            />
          </div>
        </div>
        <div className="flex items-center gap-6">
          <label className="flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
            <input type="checkbox" checked={scanAll} onChange={(e) => setScanAll(e.target.checked)} className="accent-blue-500" />
            Scan all iterations
          </label>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Min severity:</span>
            {['low', 'medium', 'high'].map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setMinSeverity(s)}
                className={`px-2 py-1 text-xs rounded border ${minSeverity === s ? 'bg-blue-500/15 border-blue-500/50 text-blue-400' : 'border-slate-700 text-slate-400 hover:text-slate-200'}`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleStart}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium disabled:opacity-50"
          >
            {loading ? <Spinner size="sm" /> : null}
            Start Nuclei Rescan
          </button>
          {activePid && (
            <button
              onClick={handleKill}
              className="px-3 py-2 text-sm bg-red-600 hover:bg-red-700 rounded-lg text-white"
            >
              Kill
            </button>
          )}
        </div>
        {activeRunId && (
          <div className="mt-3">
            <LogViewer runId={activeRunId} />
          </div>
        )}
      </div>
    </CollapsibleSection>
  );
}
