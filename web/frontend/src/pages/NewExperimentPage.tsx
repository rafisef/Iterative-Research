import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  actionsApi,
  referenceApi,
  envApi,
  languageApi,
  type EnvVar,
  type LanguageInfo,
} from '../api/client';
import { PathAutocomplete } from '../components/common/PathAutocomplete';
import { FileBrowserModal } from '../components/common/FileBrowserModal';
import { LanguageBadges } from '../components/common/LanguageBadges';
import { ScannerConfigPanel } from '../components/common/ScannerConfigPanel';
import { Tooltip } from '../components/common/Tooltip';
import { Spinner } from '../components/common/Spinner';

type RunType = 'experiment' | 'generate' | 'scan' | 'analyze' | 'test-run';
type CodeSource = 'none' | 'snippet' | 'base-code-dir';

const RUN_TYPE_TOOLTIPS: Record<RunType, string> = {
  experiment: 'Generates code via LLM, runs static analysis, and produces an analysis report',
  generate: 'Generates code iterations from a base snippet using the configured LLM agents',
  scan: 'Runs static analysis (Bandit/Semgrep) on code files or an existing run directory',
  analyze: 'Analyzes existing scan results (results.jsonl) and produces trend/delta reports',
  'test-run': 'Makes a single LLM call and scans the output — verifies connectivity without writing results',
};

interface ModelOption {
  model: string;
  enabled: boolean;
}

export function NewExperimentPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [runType, setRunType] = useState<RunType>('experiment');
  const [selectedModels, setSelectedModels] = useState<Set<string>>(new Set());
  const [allModels, setAllModels] = useState<ModelOption[]>([]);
  const [iterations, setIterations] = useState('');
  const [runId, setRunId] = useState('');
  const [codeSource, setCodeSource] = useState<CodeSource>('none');
  const [snippetPath, setSnippetPath] = useState('');
  const [baseCodeDir, setBaseCodeDir] = useState('');
  const [logName, setLogName] = useState('');
  const [analyzeFilePath, setAnalyzeFilePath] = useState('');
  const [baselineScan, setBaselineScan] = useState(false);
  const [scanSourcePath, setScanSourcePath] = useState('');

  const [showBrowseModal, setShowBrowseModal] = useState(false);
  const [browseTarget, setBrowseTarget] = useState<'snippet' | 'dir' | 'scan' | 'analyze'>('snippet');
  const [detectedLanguages, setDetectedLanguages] = useState<LanguageInfo[]>([]);
  const [semgrepConfig, setSemgrepConfig] = useState('');

  const KNOWN_MODELS: Record<string, string> = {
    OPENAI_API_KEY: 'openai/gpt-4o',
    ANTHROPIC_API_KEY: 'anthropic/claude-sonnet-4-20250514',
    GEMINI_API_KEY: 'gemini/gemini-2.0-flash',
    GROQ_API_KEY: 'groq/llama-3.3-70b-versatile',
    MISTRAL_API_KEY: 'mistral/mistral-large-latest',
  };

  const refreshData = useCallback(async () => {
    try {
      const [modelsRes, envVars] = await Promise.all([
        referenceApi.availableModels(),
        envApi.list(),
      ]);
      const envSet = new Set(envVars.filter((v: EnvVar) => v.is_set).map((v: EnvVar) => v.name));

      const options: ModelOption[] = [];
      const seen = new Set<string>();

      for (const m of modelsRes.models) {
        if (!seen.has(m)) {
          seen.add(m);
          options.push({ model: m, enabled: true });
        }
      }
      for (const [key, defaultModel] of Object.entries(KNOWN_MODELS)) {
        if (!seen.has(defaultModel)) {
          seen.add(defaultModel);
          options.push({ model: defaultModel, enabled: envSet.has(key) });
        }
      }
      setAllModels(options);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => { refreshData(); }, [refreshData]);

  const detectLanguage = useCallback(async (path: string) => {
    if (!path) {
      setDetectedLanguages([]);
      return;
    }
    try {
      const res = await languageApi.detect(path);
      setDetectedLanguages(res.languages);
    } catch {
      setDetectedLanguages([]);
    }
  }, []);

  const effectivePath = codeSource === 'snippet' ? snippetPath : codeSource === 'base-code-dir' ? baseCodeDir : '';
  useEffect(() => {
    if (effectivePath) detectLanguage(effectivePath);
    else setDetectedLanguages([]);
  }, [effectivePath, detectLanguage]);

  const scanEffectivePath = baselineScan ? scanSourcePath : '';
  useEffect(() => {
    if (scanEffectivePath) detectLanguage(scanEffectivePath);
    else if (runType === 'scan') setDetectedLanguages([]);
  }, [scanEffectivePath, detectLanguage, runType]);

  const toggleModel = (model: string) => {
    setSelectedModels((prev) => {
      const next = new Set(prev);
      if (next.has(model)) next.delete(model);
      else next.add(model);
      return next;
    });
  };

  const toggleAll = () => {
    const enabled = allModels.filter((m) => m.enabled).map((m) => m.model);
    if (enabled.every((m) => selectedModels.has(m))) {
      setSelectedModels(new Set());
    } else {
      setSelectedModels(new Set(enabled));
    }
  };

  const openBrowse = (target: 'snippet' | 'dir' | 'scan' | 'analyze') => {
    setBrowseTarget(target);
    setShowBrowseModal(true);
  };

  const handleBrowseSelect = (path: string) => {
    if (browseTarget === 'snippet') {
      setSnippetPath(path);
      setCodeSource('snippet');
    } else if (browseTarget === 'dir') {
      setBaseCodeDir(path);
      setCodeSource('base-code-dir');
    } else if (browseTarget === 'scan') {
      setScanSourcePath(path);
    } else if (browseTarget === 'analyze') {
      setAnalyzeFilePath(path);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const modelParam = selectedModels.size > 0
        ? (selectedModels.size === allModels.filter((m) => m.enabled).length ? 'all' : [...selectedModels].join(','))
        : undefined;

      const params = {
        model: modelParam,
        iterations: iterations ? parseInt(iterations) : undefined,
        run_id: runId || undefined,
        snippet: codeSource === 'snippet' ? snippetPath : undefined,
        base_code_dir: codeSource === 'base-code-dir' ? baseCodeDir : undefined,
        log: logName || undefined,
      };

      let result: { run_id: string };

      switch (runType) {
        case 'experiment':
          result = await actionsApi.startExperiment({
            ...params,
            ...(semgrepConfig ? { semgrep_config: semgrepConfig } : {}),
          });
          break;
        case 'generate':
          result = await actionsApi.startGenerate(params);
          break;
        case 'scan':
          if (baselineScan && scanSourcePath) {
            const isDir = scanSourcePath.endsWith('/');
            result = await actionsApi.startBaselineScan({
              snippet: !isDir ? scanSourcePath : undefined,
              base_code_dir: isDir ? scanSourcePath : undefined,
              semgrep_config: semgrepConfig || undefined,
            });
          } else if (scanSourcePath) {
            const isDir = scanSourcePath.endsWith('/') || !scanSourcePath.includes('.');
            result = await actionsApi.startAdhocScan({
              snippet: !isDir ? scanSourcePath : undefined,
              base_code_dir: isDir ? scanSourcePath : undefined,
              semgrep_config: semgrepConfig || undefined,
            });
          } else {
            setError('Please provide a path to scan');
            setLoading(false);
            return;
          }
          break;
        case 'analyze':
          if (!analyzeFilePath) {
            setError('Please provide a results.jsonl file path');
            setLoading(false);
            return;
          }
          navigate(`/runs/${analyzeFilePath.split('/').find((p) => p.match(/^\d{4}-\d{2}-\d{2}/) || p.startsWith('baseline-')) || analyzeFilePath}`);
          return;
        case 'test-run':
          result = await actionsApi.startTestRun({
            snippet: codeSource === 'snippet' ? snippetPath : undefined,
            model: modelParam,
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

  const showCodeSource = runType === 'experiment' || runType === 'generate';
  const showModelIterations = runType !== 'scan' && runType !== 'analyze';
  const showScanConfig = (showCodeSource && detectedLanguages.length > 0 && runType === 'experiment')
    || (runType === 'scan' && baselineScan && detectedLanguages.length > 0);

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
              ['analyze', 'Analyze Scan Results Only'],
              ['test-run', 'Test Run'],
            ] as [RunType, string][]).map(([val, label]) => (
              <Tooltip key={val} content={RUN_TYPE_TOOLTIPS[val]}>
                <button
                  type="button"
                  onClick={() => setRunType(val)}
                  className={`relative w-full px-3 py-2 text-xs rounded-lg border transition-colors ${
                    runType === val
                      ? 'bg-blue-500/15 border-blue-500/50 text-blue-400'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-slate-700 text-[9px] text-slate-400 flex items-center justify-center border border-slate-600">
                    i
                  </span>
                  {label}
                </button>
              </Tooltip>
            ))}
          </div>
        </fieldset>

        {/* Scan Only: source path + baseline checkbox */}
        {runType === 'scan' && (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1">Code Source</label>
              <div className="flex gap-2">
                <div className="flex-1">
                  <PathAutocomplete
                    value={scanSourcePath}
                    onChange={setScanSourcePath}
                    placeholder="Run ID, file path, or directory..."
                  />
                </div>
                <button
                  type="button"
                  onClick={() => openBrowse('scan')}
                  className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                  title="Browse files"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                  </svg>
                </button>
              </div>
            </div>

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={baselineScan}
                onChange={(e) => setBaselineScan(e.target.checked)}
                className="accent-blue-500"
              />
              <span className="text-sm text-slate-300">Baseline Scan</span>
              <span className="text-xs text-slate-500">(creates a new run directory with findings)</span>
            </label>

            {baselineScan && scanSourcePath && (
              <>
                <LanguageBadges languages={detectedLanguages} />
                {showScanConfig && (
                  <ScannerConfigPanel languages={detectedLanguages} onChange={setSemgrepConfig} />
                )}
              </>
            )}
          </div>
        )}

        {/* Analyze Only: results.jsonl file picker */}
        {runType === 'analyze' && (
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Scan Results File</label>
            <div className="flex gap-2">
              <div className="flex-1">
                <PathAutocomplete
                  value={analyzeFilePath}
                  onChange={setAnalyzeFilePath}
                  placeholder="runs/2026-04-01_11-34-04/results.jsonl"
                />
              </div>
              <button
                type="button"
                onClick={() => openBrowse('analyze')}
                className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                title="Browse files"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              </button>
            </div>
            <p className="text-xs text-slate-500 mt-1">Point to a results.jsonl file from a previous scan</p>
          </div>
        )}

        {/* Model Checkboxes */}
        {showModelIterations && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Model</label>
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 space-y-1.5 max-h-48 overflow-auto">
                <label className="flex items-center gap-2 cursor-pointer pb-1.5 border-b border-slate-700/50">
                  <input
                    type="checkbox"
                    checked={allModels.filter((m) => m.enabled).length > 0 && allModels.filter((m) => m.enabled).every((m) => selectedModels.has(m.model))}
                    onChange={toggleAll}
                    className="accent-blue-500"
                    disabled={allModels.filter((m) => m.enabled).length === 0}
                  />
                  <span className="text-sm text-slate-300 font-medium">All</span>
                </label>
                {allModels.map((m) => (
                  <label
                    key={m.model}
                    className={`flex items-center gap-2 cursor-pointer ${!m.enabled ? 'opacity-40' : ''}`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedModels.has(m.model)}
                      onChange={() => toggleModel(m.model)}
                      disabled={!m.enabled}
                      className="accent-blue-500"
                    />
                    <span className="text-xs text-slate-300 font-mono">{m.model}</span>
                    {!m.enabled && (
                      <svg className="w-3 h-3 text-slate-600 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                    )}
                  </label>
                ))}
                {allModels.length === 0 && (
                  <p className="text-xs text-amber-400">
                    No provider API keys detected. Set them on the <a href="/tools" className="underline">Tools</a> page.
                  </p>
                )}
              </div>
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
        {runType !== 'scan' && runType !== 'analyze' && (
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
                        <div className="flex gap-2">
                          <div className="flex-1">
                            <PathAutocomplete
                              value={snippetPath}
                              onChange={setSnippetPath}
                              placeholder="snippets/typescript/injection/injection_sql_cmd_base.ts"
                            />
                          </div>
                          <button
                            type="button"
                            onClick={() => openBrowse('snippet')}
                            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                            title="Browse files"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                            </svg>
                          </button>
                        </div>
                      </div>
                    )}
                    {codeSource === val && val === 'base-code-dir' && (
                      <div className="mt-2">
                        <div className="flex gap-2">
                          <div className="flex-1">
                            <PathAutocomplete
                              value={baseCodeDir}
                              onChange={setBaseCodeDir}
                              placeholder="snippets/python/"
                              dirsOnly
                            />
                          </div>
                          <button
                            type="button"
                            onClick={() => openBrowse('dir')}
                            className="px-3 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                            title="Browse directories"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                            </svg>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </label>
              ))}
              {codeSource !== 'none' && (
                <button
                  type="button"
                  onClick={() => { setCodeSource('none'); setSnippetPath(''); setBaseCodeDir(''); setDetectedLanguages([]); }}
                  className="text-xs text-slate-500 hover:text-slate-300 underline ml-6"
                >
                  Clear selection (use config vulnerabilities)
                </button>
              )}
            </div>

            {/* Language badges & scanner config */}
            {detectedLanguages.length > 0 && (
              <div className="ml-6 mt-2">
                <LanguageBadges languages={detectedLanguages} />
                {runType === 'experiment' && (
                  <ScannerConfigPanel languages={detectedLanguages} onChange={setSemgrepConfig} />
                )}
              </div>
            )}
          </fieldset>
        )}

        {/* Log name */}
        {runType !== 'scan' && runType !== 'analyze' && runType !== 'test-run' && (
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

      <FileBrowserModal
        open={showBrowseModal}
        onClose={() => setShowBrowseModal(false)}
        onSelect={handleBrowseSelect}
        dirsOnly={browseTarget === 'dir'}
        title={browseTarget === 'analyze' ? 'Select Results File' : browseTarget === 'dir' ? 'Select Directory' : 'Select File'}
      />
    </div>
  );
}
