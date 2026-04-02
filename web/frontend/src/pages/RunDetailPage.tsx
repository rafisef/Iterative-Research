import { useCallback, useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { runsApi, actionsApi } from '../api/client';
import { StatusBadge } from '../components/common/StatusBadge';
import { CollapsibleSection } from '../components/common/CollapsibleSection';
import { Spinner } from '../components/common/Spinner';
import { LogViewer } from '../components/logs/LogViewer';
import type { Run, ResultRecord, GeneratedCode, AnalysisData, TrendGroup, DeltaEntry } from '../types';

export function RunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const navigate = useNavigate();

  const [run, setRun] = useState<Run | null>(null);
  const [results, setResults] = useState<ResultRecord[]>([]);
  const [codes, setCodes] = useState<GeneratedCode[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activePid, setActivePid] = useState<number | null>(null);
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const [expandedCode, setExpandedCode] = useState<number | null>(null);

  const isActive = run?.status === 'generating' || run?.status === 'scanning' || run?.status === 'analyzing';

  const fetchAll = useCallback(async () => {
    if (!runId) return;
    try {
      const [runData, resultsData, codesData] = await Promise.all([
        runsApi.get(runId),
        runsApi.results(runId).catch(() => []),
        runsApi.code(runId).catch(() => []),
      ]);
      setRun(runData);
      setResults(resultsData);
      setCodes(codesData);

      if (resultsData.length > 0) {
        runsApi.analysis(runId).then(setAnalysis).catch(() => {});
      }
    } catch {
      navigate('/');
    } finally {
      setLoading(false);
    }
  }, [runId, navigate]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Poll for updates while run is active
  useEffect(() => {
    if (!isActive) return;
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [isActive, fetchAll]);

  const handleScan = async () => {
    if (!runId) return;
    const res = await actionsApi.startScan(runId);
    setActivePid(res.pid);
    setRun((prev) => prev ? { ...prev, status: 'scanning' } : prev);
  };

  const handleAnalyze = async () => {
    if (!runId) return;
    const data = await actionsApi.startAnalyze(runId);
    setAnalysis(data);
  };

  const handleKill = async () => {
    if (activePid) {
      await actionsApi.killProcess(activePid);
      setActivePid(null);
    }
  };

  const hasBandit = results.some(
    (r) => r.snippet_path?.endsWith('.py') || r.bandit_issues?.length > 0
  ) || codes.some((c) => c.language === 'python');

  if (loading) return <div className="flex justify-center py-20"><Spinner size="lg" /></div>;
  if (!run || !runId) return <div className="text-slate-500">Run not found</div>;

  return (
    <div>
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <button onClick={() => navigate('/')} className="text-slate-500 hover:text-slate-300">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
            </button>
            <h2 className="text-2xl font-bold text-white font-mono">{run.id}</h2>
            <StatusBadge status={run.status} />
          </div>
          <div className="flex gap-6 text-sm text-slate-400 ml-8">
            <span>Model: <span className="text-slate-200">{run.model || '—'}</span></span>
            <span>Iterations: <span className="text-slate-200">{run.iterations ?? '—'}</span></span>
            <span>Agents: <span className="text-slate-200">{run.agents?.length}</span></span>
            <span>Vulns: <span className="text-slate-200">{run.vulnerabilities?.length}</span></span>
            {run.random_seed != null && <span>Seed: <span className="text-slate-200">{run.random_seed}</span></span>}
          </div>
        </div>
        <div className="flex gap-2">
          {run.status === 'complete' && results.length === 0 && (
            <button onClick={handleScan} className="px-3 py-2 text-sm bg-amber-600 hover:bg-amber-700 rounded-lg text-white transition-colors">
              Run Scans
            </button>
          )}
          {results.length > 0 && (
            <button onClick={handleAnalyze} className="px-3 py-2 text-sm bg-purple-600 hover:bg-purple-700 rounded-lg text-white transition-colors">
              Re-analyze
            </button>
          )}
          {isActive && activePid && (
            <button onClick={handleKill} className="px-3 py-2 text-sm bg-red-600 hover:bg-red-700 rounded-lg text-white transition-colors">
              Kill Process
            </button>
          )}
        </div>
      </div>

      {/* Generated Code */}
      <CollapsibleSection title="Generated Code" count={codes.length}>
        {codes.length === 0 ? (
          <p className="text-sm text-slate-500">No generated code files found.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-3 py-2 text-slate-400 font-medium">Agent</th>
                <th className="text-left px-3 py-2 text-slate-400 font-medium">Vulnerability</th>
                <th className="text-center px-3 py-2 text-slate-400 font-medium">Iter</th>
                <th className="text-left px-3 py-2 text-slate-400 font-medium">Language</th>
                <th className="text-center px-3 py-2 text-slate-400 font-medium">Syntax</th>
              </tr>
            </thead>
            <tbody>
              {codes.map((c) => (
                <>
                  <tr
                    key={c.id}
                    onClick={() => setExpandedCode(expandedCode === c.id ? null : c.id)}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer"
                  >
                    <td className="px-3 py-2 text-slate-300">{c.agent}</td>
                    <td className="px-3 py-2 text-slate-300">{c.vuln_id}</td>
                    <td className="px-3 py-2 text-center text-slate-300">{c.iteration}</td>
                    <td className="px-3 py-2 text-slate-400">{c.language}</td>
                    <td className="px-3 py-2 text-center">
                      {c.has_syntax_error ? (
                        <span className="text-red-400 text-xs">error</span>
                      ) : (
                        <span className="text-emerald-400 text-xs">ok</span>
                      )}
                    </td>
                  </tr>
                  {expandedCode === c.id && (
                    <tr key={`${c.id}-code`}>
                      <td colSpan={5} className="p-3 bg-slate-950">
                        <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap overflow-auto max-h-80 p-3 bg-slate-900 rounded-lg border border-slate-800">
                          {c.code_content}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </CollapsibleSection>

      {/* Scan Results */}
      <CollapsibleSection title="Scan Results" count={results.length}>
        {results.length === 0 ? (
          <p className="text-sm text-slate-500">No scan results yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-3 py-2 text-slate-400 font-medium">Agent</th>
                <th className="text-left px-3 py-2 text-slate-400 font-medium">Vulnerability</th>
                <th className="text-center px-3 py-2 text-slate-400 font-medium">Iter</th>
                {hasBandit && <th className="text-center px-3 py-2 text-red-400 font-medium">B:HIGH</th>}
                {hasBandit && <th className="text-center px-3 py-2 text-amber-400 font-medium">B:MED</th>}
                {hasBandit && <th className="text-center px-3 py-2 text-yellow-400 font-medium">B:LOW</th>}
                <th className="text-center px-3 py-2 text-purple-400 font-medium">Semgrep</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <>
                  <tr
                    key={r.id}
                    onClick={() => setExpandedResult(expandedResult === r.id ? null : r.id)}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer"
                  >
                    <td className="px-3 py-2 text-slate-300">{r.agent}</td>
                    <td className="px-3 py-2 text-slate-300">{r.vulnerability_id}</td>
                    <td className="px-3 py-2 text-center text-slate-300">{r.iteration}</td>
                    {hasBandit && (
                      <td className="px-3 py-2 text-center font-mono">
                        <span className={r.bandit_high > 0 ? 'text-red-400' : 'text-slate-600'}>{r.bandit_high}</span>
                      </td>
                    )}
                    {hasBandit && (
                      <td className="px-3 py-2 text-center font-mono">
                        <span className={r.bandit_medium > 0 ? 'text-amber-400' : 'text-slate-600'}>{r.bandit_medium}</span>
                      </td>
                    )}
                    {hasBandit && (
                      <td className="px-3 py-2 text-center font-mono">
                        <span className={r.bandit_low > 0 ? 'text-yellow-400' : 'text-slate-600'}>{r.bandit_low}</span>
                      </td>
                    )}
                    <td className="px-3 py-2 text-center font-mono">
                      <span className={r.semgrep_findings > 0 ? 'text-purple-400' : 'text-slate-600'}>{r.semgrep_findings}</span>
                    </td>
                  </tr>
                  {expandedResult === r.id && (
                    <tr key={`${r.id}-detail`}>
                      <td colSpan={hasBandit ? 7 : 4} className="p-3 bg-slate-950">
                        <FindingsDetail result={r} showBandit={hasBandit} />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </CollapsibleSection>

      {/* Analysis */}
      {analysis && !('error' in analysis) && (
        <CollapsibleSection title="Analysis" count={analysis.trends?.length}>
          <AnalysisView analysis={analysis} hasBandit={hasBandit} />
        </CollapsibleSection>
      )}

      {/* Logs */}
      <CollapsibleSection title="Logs" defaultOpen={isActive}>
        <LogViewer runId={isActive ? runId : null} />
      </CollapsibleSection>
    </div>
  );
}

function FindingsDetail({ result, showBandit }: { result: ResultRecord; showBandit: boolean }) {
  const bandit = showBandit ? (result.bandit_issues || []) : [];
  const semgrep = result.semgrep_issues || [];
  if (bandit.length === 0 && semgrep.length === 0) {
    return <p className="text-sm text-slate-500 italic">No individual findings recorded.</p>;
  }
  return (
    <div className="space-y-3 text-xs">
      {bandit.map((issue, i) => (
        <div key={`b-${i}`} className="p-2 bg-slate-900 rounded border border-slate-800">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px] font-medium">BANDIT</span>
            <span className="text-slate-300 font-medium">{issue.test_id}</span>
            <span className="text-slate-500">({issue.severity}/{issue.confidence})</span>
            {issue.cwe_id && <span className="text-slate-500">CWE-{issue.cwe_id}</span>}
            <span className="text-slate-500">line {issue.line_number}</span>
          </div>
          <p className="text-slate-400">{issue.test_name}: {issue.issue_text}</p>
        </div>
      ))}
      {semgrep.map((issue, i) => (
        <div key={`s-${i}`} className="p-2 bg-slate-900 rounded border border-slate-800">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded text-[10px] font-medium">SEMGREP</span>
            <span className="text-slate-300 font-medium">{issue.rule_id}</span>
            <span className="text-slate-500">({issue.severity})</span>
            <span className="text-slate-500">line {issue.line_number}</span>
          </div>
          <p className="text-slate-400">{issue.message}</p>
          {issue.matched_lines && (
            <pre className="mt-1 text-slate-500 bg-slate-950 rounded px-2 py-1 font-mono">{issue.matched_lines}</pre>
          )}
        </div>
      ))}
    </div>
  );
}

function AnalysisView({ analysis, hasBandit }: { analysis: AnalysisData; hasBandit: boolean }) {
  const { summary, trends, deltas } = analysis;
  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Records', value: summary.total_records },
          { label: 'Iterations', value: `${summary.iteration_range?.[0] ?? '—'} – ${summary.iteration_range?.[1] ?? '—'}` },
          { label: 'Agents', value: summary.agents?.length },
          { label: 'Vulnerabilities', value: summary.vulnerabilities?.length },
        ].map((item) => (
          <div key={item.label} className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
            <div className="text-xs text-slate-400">{item.label}</div>
            <div className="text-lg font-semibold text-white mt-1">{item.value}</div>
          </div>
        ))}
      </div>

      {/* Trend tables */}
      {trends.map((t: TrendGroup) => (
        <div key={`${t.vulnerability_id}-${t.agent}`} className="bg-slate-800/30 rounded-lg border border-slate-700/50 p-4">
          <h4 className="text-sm font-medium text-slate-200 mb-3">
            {t.vulnerability_id} / <span className="text-blue-400">{t.agent}</span>
          </h4>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-2 py-1 text-slate-400">Iter</th>
                {hasBandit && <th className="text-center px-2 py-1 text-red-400">B:HIGH</th>}
                {hasBandit && <th className="text-center px-2 py-1 text-amber-400">B:MED</th>}
                {hasBandit && <th className="text-center px-2 py-1 text-yellow-400">B:LOW</th>}
                <th className="text-center px-2 py-1 text-purple-400">Semgrep</th>
                <th className="text-left px-2 py-1 text-slate-400">Prompt</th>
              </tr>
            </thead>
            <tbody>
              {t.rows.map((row) => (
                <tr key={row.iteration} className="border-b border-slate-800/50">
                  <td className="px-2 py-1.5 text-slate-300">{row.iteration}</td>
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_high} max={Math.max(...t.rows.map((r) => r.bandit_high), 1)} color="red" />
                    </td>
                  )}
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_medium} max={Math.max(...t.rows.map((r) => r.bandit_medium), 1)} color="amber" />
                    </td>
                  )}
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_low} max={Math.max(...t.rows.map((r) => r.bandit_low), 1)} color="yellow" />
                    </td>
                  )}
                  <td className="px-2 py-1.5 text-center">
                    <MetricBar value={row.semgrep_findings} max={Math.max(...t.rows.map((r) => r.semgrep_findings), 1)} color="purple" />
                  </td>
                  <td className="px-2 py-1.5 text-slate-500 truncate max-w-[200px]">{row.prompt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {/* Delta summary */}
      {deltas.length > 0 && (
        <div className="bg-slate-800/30 rounded-lg border border-slate-700/50 p-4">
          <h4 className="text-sm font-medium text-slate-200 mb-3">Delta Summary (first → last iteration)</h4>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-2 py-1 text-slate-400">Vuln</th>
                <th className="text-left px-2 py-1 text-slate-400">Agent</th>
                {hasBandit && <th className="text-center px-2 py-1 text-red-400">B:HIGH</th>}
                {hasBandit && <th className="text-center px-2 py-1 text-amber-400">B:MED</th>}
                {hasBandit && <th className="text-center px-2 py-1 text-yellow-400">B:LOW</th>}
                <th className="text-center px-2 py-1 text-purple-400">Semgrep</th>
              </tr>
            </thead>
            <tbody>
              {deltas.map((d: DeltaEntry) => (
                <tr key={`${d.vulnerability_id}-${d.agent}`} className="border-b border-slate-800/50">
                  <td className="px-2 py-1.5 text-slate-300">{d.vulnerability_id}</td>
                  <td className="px-2 py-1.5 text-blue-400">{d.agent}</td>
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_high_delta} /></td>}
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_medium_delta} /></td>}
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_low_delta} /></td>}
                  <td className="px-2 py-1.5 text-center"><DeltaValue value={d.semgrep_delta} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function MetricBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  const colorMap: Record<string, string> = {
    red: 'bg-red-500',
    amber: 'bg-amber-500',
    yellow: 'bg-yellow-500',
    purple: 'bg-purple-500',
  };
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-5 text-right text-slate-300">{value}</span>
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden max-w-[60px]">
        <div className={`h-full rounded-full ${colorMap[color]}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function DeltaValue({ value }: { value: number }) {
  if (value === 0) return <span className="text-slate-600">0</span>;
  if (value > 0) return <span className="text-red-400">+{value}</span>;
  return <span className="text-emerald-400">{value}</span>;
}
