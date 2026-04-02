import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { actionsApi, referenceApi, runsApi } from '../api/client';
import { Autocomplete } from '../components/common/Autocomplete';
import { PathAutocomplete } from '../components/common/PathAutocomplete';
import { Spinner } from '../components/common/Spinner';
import type { Run } from '../types';

type RunType = 'experiment' | 'generate' | 'scan' | 'analyze' | 'test-run';
type CodeSource = 'none' | 'snippet' | 'base-code-dir';

export function NewExperimentPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [runType, setRunType] = useState<RunType>('experiment');
  const [model, setModel] = useState('');
  const [iterations, setIterations] = useState('');
  const [runId, setRunId] = useState('');
  const [codeSource, setCodeSource] = useState<CodeSource>('none');
  const [snippetPath, setSnippetPath] = useState('');
  const [baseCodeDir, setBaseCodeDir] = useState('');
  const [logName, setLogName] = useState('');
  const [existingRunId, setExistingRunId] = useState('');

  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [existingRuns, setExistingRuns] = useState<Run[]>([]);

  const refreshModels = useCallback(async () => {
    try {
      const res = await referenceApi.availableModels();
      setAvailableModels(res.models);
    } catch {
      // ignore
    }
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      const runs = await runsApi.list();
      setExistingRuns(runs);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => { refreshModels(); refreshRuns(); }, [refreshModels, refreshRuns]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const params = {
        model: model || undefined,
        iterations: iterations ? parseInt(iterations) : undefined,
        run_id: runId || undefined,
        snippet: codeSource === 'snippet' ? snippetPath : undefined,
        base_code_dir: codeSource === 'base-code-dir' ? baseCodeDir : undefined,
        log: logName || undefined,
      };

      let result: { run_id: string };

      switch (runType) {
        case 'experiment':
          result = await actionsApi.startExperiment(params);
          break;
        case 'generate':
          result = await actionsApi.startGenerate(params);
          break;
        case 'scan':
          result = await actionsApi.startScan(existingRunId);
          break;
        case 'analyze':
          await actionsApi.startAnalyze(existingRunId);
          navigate(`/runs/${existingRunId}`);
          return;
        case 'test-run':
          result = await actionsApi.startTestRun({
            snippet: codeSource === 'snippet' ? snippetPath : undefined,
            model: model || undefined,
          });
          break;
        default:
          return;
      }

      navigate(`/runs/${result.run_id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const needsExistingRun = runType === 'scan' || runType === 'analyze';
  const showCodeSource = runType === 'experiment' || runType === 'generate';
  const showModelIterations = runType !== 'scan' && runType !== 'analyze';

  return (
    <div className="max-w-2xl">
      <h2 className="text-2xl font-bold text-white mb-1">New Experiment</h2>
      <p className="text-sm text-slate-400 mb-6">Configure and start a new run</p>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Run Type */}
        <fieldset>
          <legend className="text-sm font-medium text-slate-300 mb-3">Run Type</legend>
          <div className="grid grid-cols-5 gap-2">
            {([
              ['experiment', 'Full Pipeline'],
              ['generate', 'Generate Only'],
              ['scan', 'Scan Only'],
              ['analyze', 'Analyze Only'],
              ['test-run', 'Test Run'],
            ] as [RunType, string][]).map(([val, label]) => (
              <button
                key={val}
                type="button"
                onClick={() => setRunType(val)}
                className={`px-3 py-2 text-xs rounded-lg border transition-colors ${
                  runType === val
                    ? 'bg-blue-500/15 border-blue-500/50 text-blue-400'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </fieldset>

        {/* Existing run selector */}
        {needsExistingRun && (
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Existing Run ID</label>
            <Autocomplete
              value={existingRunId}
              onChange={setExistingRunId}
              suggestions={existingRuns.map((r) => r.id)}
              placeholder="2026-04-01_11-34-04"
              secondaryText={(id) => existingRuns.find((r) => r.id === id)?.model ?? undefined}
            />
          </div>
        )}

        {/* Model & Iterations */}
        {showModelIterations && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Model</label>
              <Autocomplete
                value={model}
                onChange={setModel}
                suggestions={['all', ...availableModels]}
                placeholder="gpt-4o (default from config)"
              />
              {availableModels.length === 0 && (
                <p className="text-xs text-amber-400 mt-1">
                  No provider API keys detected. Set them on the <a href="/tools" className="underline">Tools</a> page.
                </p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Iterations</label>
              <input
                type="number"
                min={1}
                value={iterations}
                onChange={(e) => setIterations(e.target.value)}
                placeholder="5 (default from config)"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        )}

        {/* Run ID */}
        {!needsExistingRun && (
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">
              Run ID <span className="text-slate-500">(optional, auto-generated if blank)</span>
            </label>
            <input
              type="text"
              value={runId}
              onChange={(e) => setRunId(e.target.value)}
              placeholder="YYYY-MM-DD_HH-MM-SS"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        {/* Code source */}
        {showCodeSource && (
          <fieldset>
            <legend className="text-sm font-medium text-slate-300 mb-2">Code Source</legend>
            <p className="text-xs text-slate-500 mb-3">
              Leave unselected to use the configured vulnerabilities from config.yaml.
            </p>
            <div className="space-y-3">
              {([
                ['snippet', 'Single snippet file'],
                ['base-code-dir', 'Base code directory (recursive)'],
              ] as [CodeSource, string][]).map(([val, label]) => (
                <label key={val} className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="radio"
                    name="codeSource"
                    value={val}
                    checked={codeSource === val}
                    onChange={() => setCodeSource(val)}
                    className="mt-1 accent-blue-500"
                  />
                  <div className="flex-1">
                    <span className="text-sm text-slate-200">{label}</span>
                    {codeSource === val && val === 'snippet' && (
                      <div className="mt-2">
                        <PathAutocomplete
                          value={snippetPath}
                          onChange={setSnippetPath}
                          placeholder="snippets/typescript/injection/injection_sql_cmd_base.ts"
                        />
                        <p className="text-xs text-slate-500 mt-1">Type a path and press Tab to autocomplete</p>
                      </div>
                    )}
                    {codeSource === val && val === 'base-code-dir' && (
                      <div className="mt-2">
                        <PathAutocomplete
                          value={baseCodeDir}
                          onChange={setBaseCodeDir}
                          placeholder="snippets/python/"
                          dirsOnly
                        />
                        <p className="text-xs text-slate-500 mt-1">Type a path and press Tab to autocomplete</p>
                      </div>
                    )}
                  </div>
                </label>
              ))}
              {codeSource !== 'none' && (
                <button
                  type="button"
                  onClick={() => { setCodeSource('none'); setSnippetPath(''); setBaseCodeDir(''); }}
                  className="text-xs text-slate-500 hover:text-slate-300 underline ml-6"
                >
                  Clear selection (use config vulnerabilities)
                </button>
              )}
            </div>
          </fieldset>
        )}

        {/* Log name */}
        {!needsExistingRun && runType !== 'test-run' && (
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">
              Log file name <span className="text-slate-500">(optional)</span>
            </label>
            <input
              type="text"
              value={logName}
              onChange={(e) => setLogName(e.target.value)}
              placeholder="experiment-log"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium text-sm transition-colors disabled:opacity-50"
        >
          {loading ? <Spinner size="sm" /> : null}
          {runType === 'test-run' ? 'Start Test Run' : `Start ${runType.charAt(0).toUpperCase() + runType.slice(1)}`}
        </button>
      </form>
    </div>
  );
}
