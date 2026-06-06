import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { runsApi, actionsApi } from '../api/client';
import { StatusBadge } from '../components/common/StatusBadge';
import { Spinner } from '../components/common/Spinner';
import { LogViewer } from '../components/logs/LogViewer';
import type { Run, ResultRecord, GeneratedCode, AnalysisData, TrendGroup, DeltaEntry } from '../types';

type Tab = 'code' | 'results' | 'analysis';

export function RunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const navigate = useNavigate();

  const [run, setRun] = useState<Run | null>(null);
  const [results, setResults] = useState<ResultRecord[]>([]);
  const [codes, setCodes] = useState<GeneratedCode[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(true);
  const [activePid, setActivePid] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('results');
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set());
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

  useEffect(() => {
    if (!isActive) return;
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, [isActive, fetchAll]);

  useEffect(() => {
    if (results.length > 0) setActiveTab('results');
    else if (codes.length > 0) setActiveTab('code');
  }, [results.length, codes.length]);

  const handleKill = async () => {
    if (activePid) {
      await actionsApi.killProcess(activePid);
      setActivePid(null);
    }
  };

  const hasBandit = results.some(
    (r) => r.snippet_path?.endsWith('.py') || (r.bandit_issues?.length ?? 0) > 0
  ) || codes.some((c) => c.language === 'python');

  const toggleAgent = (agentKey: string) => {
    setExpandedAgents((prev) => {
      const next = new Set(prev);
      if (next.has(agentKey)) next.delete(agentKey);
      else next.add(agentKey);
      return next;
    });
  };

  const codesByAgent = useMemo(() => {
    const groups: Record<string, GeneratedCode[]> = {};
    for (const c of codes) {
      const key = c.agent;
      if (!groups[key]) groups[key] = [];
      groups[key].push(c);
    }
    return groups;
  }, [codes]);

  if (loading) return <div className="flex justify-center py-20"><Spinner size="lg" /></div>;
  if (!run || !runId) return <div className="text-slate-500">Run not found</div>;

  const agentCount = run.agents?.length ?? 0;
  const vulnCount = run.vulnerabilities?.length ?? 0;
  const modelDisplay = run.model || 'gpt-4o (default)';
  const iterDisplay = run.iterations ?? '5 (default)';

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'code', label: 'AI Generated Code', count: codes.length },
    { id: 'results', label: 'Scan Results', count: results.length },
    { id: 'analysis', label: 'Analysis', count: analysis?.trends?.length },
  ];

  return (
    <div className="flex flex-col min-h-0">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <button onClick={() => navigate('/')} className="text-slate-500 hover:text-slate-300">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
            </button>
            <h2 className="text-2xl font-bold text-white font-mono">{run.id}</h2>
            <StatusBadge status={run.status} />
          </div>
          <div className="flex gap-6 text-sm text-slate-400 ml-8">
            <span>Model: <span className="text-slate-200">{modelDisplay}</span></span>
            <span>Iterations: <span className="text-slate-200">{iterDisplay}</span></span>
            <span>Agents: <span className="text-slate-200">{agentCount}</span></span>
            <span>Vulns: <span className="text-slate-200">{vulnCount}</span></span>
            {run.random_seed != null && <span>Seed: <span className="text-slate-200">{run.random_seed}</span></span>}
          </div>
        </div>
        <div className="flex gap-2">
          {isActive && activePid && (
            <button onClick={handleKill} className="px-3 py-2 text-sm bg-red-600 hover:bg-red-700 rounded-lg text-white transition-colors">
              Kill Process
            </button>
          )}
        </div>
      </div>

      {/* Tab Bar */}
      <div className="flex border-b border-slate-700 mb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600'
            }`}
          >
            {tab.label}
            {tab.count != null && (
              <span className={`ml-2 px-1.5 py-0.5 text-xs rounded-full ${
                activeTab === tab.id ? 'bg-blue-500/20 text-blue-300' : 'bg-slate-800 text-slate-500'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 min-h-0 overflow-auto mb-4">
        {activeTab === 'code' && (
          <div>
            {codes.length === 0 ? (
              <p className="text-sm text-slate-500">No generated code files found.</p>
            ) : (
              <div className="space-y-1">
                {Object.entries(codesByAgent).map(([agent, agentCodes]) => {
                  const isOpen = expandedAgents.has(agent);
                  return (
                    <div key={agent} className="border border-slate-700/50 rounded-lg overflow-hidden">
                      <button
                        onClick={() => toggleAgent(agent)}
                        className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-800/50 hover:bg-slate-800/80 transition-colors"
                      >
                        <div className="flex items-center gap-2">
                          <svg
                            className={`w-4 h-4 text-slate-400 transition-transform ${isOpen ? 'rotate-90' : ''}`}
                            fill="none" viewBox="0 0 24 24" stroke="currentColor"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          <span className="text-sm font-medium text-blue-400">{agent}</span>
                        </div>
                        <span className="text-xs text-slate-500">{agentCodes.length} iteration{agentCodes.length !== 1 ? 's' : ''}</span>
                      </button>
                      {isOpen && (
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="border-b border-slate-700/50">
                              <th className="text-center px-3 py-2 text-slate-400 font-medium w-16">Iter</th>
                              <th className="text-left px-3 py-2 text-slate-400 font-medium">Vulnerability</th>
                              <th className="text-left px-3 py-2 text-slate-400 font-medium">Language</th>
                              <th className="text-center px-3 py-2 text-slate-400 font-medium">Syntax</th>
                            </tr>
                          </thead>
                          <tbody>
                            {agentCodes.map((c) => (
                              <tr key={c.id}>
                                <td className="px-3 py-2 text-center text-slate-300">{c.iteration}</td>
                                <td className="px-3 py-2 text-slate-300">{c.vuln_id}</td>
                                <td className="px-3 py-2">
                                  <LanguageTag language={c.language} />
                                </td>
                                <td className="px-3 py-2 text-center">
                                  {c.has_syntax_error ? (
                                    <span className="text-red-400 text-xs">error</span>
                                  ) : (
                                    <span className="text-emerald-400 text-xs">ok</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'results' && (
          <div>
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
                    <th className="text-center px-3 py-2 text-red-400 font-medium">S:HIGH</th>
                    <th className="text-center px-3 py-2 text-amber-400 font-medium">S:MED</th>
                    <th className="text-center px-3 py-2 text-blue-400 font-medium">S:LOW</th>
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
                            <span className={(r.bandit_high ?? 0) > 0 ? 'text-red-400' : 'text-slate-600'}>{r.bandit_high ?? 0}</span>
                          </td>
                        )}
                        {hasBandit && (
                          <td className="px-3 py-2 text-center font-mono">
                            <span className={(r.bandit_medium ?? 0) > 0 ? 'text-amber-400' : 'text-slate-600'}>{r.bandit_medium ?? 0}</span>
                          </td>
                        )}
                        {hasBandit && (
                          <td className="px-3 py-2 text-center font-mono">
                            <span className={(r.bandit_low ?? 0) > 0 ? 'text-yellow-400' : 'text-slate-600'}>{r.bandit_low ?? 0}</span>
                          </td>
                        )}
                        <td className="px-3 py-2 text-center font-mono">
                          <span className={(r.semgrep_high ?? r.semgrep_error ?? 0) > 0 ? 'text-red-400' : 'text-slate-600'}>{r.semgrep_high ?? r.semgrep_error ?? 0}</span>
                        </td>
                        <td className="px-3 py-2 text-center font-mono">
                          <span className={(r.semgrep_medium ?? r.semgrep_warning ?? 0) > 0 ? 'text-amber-400' : 'text-slate-600'}>{r.semgrep_medium ?? r.semgrep_warning ?? 0}</span>
                        </td>
                        <td className="px-3 py-2 text-center font-mono">
                          <span className={(r.semgrep_low ?? r.semgrep_info ?? 0) > 0 ? 'text-blue-400' : 'text-slate-600'}>{r.semgrep_low ?? r.semgrep_info ?? 0}</span>
                        </td>
                      </tr>
                      {expandedResult === r.id && (
                        <tr key={`${r.id}-detail`}>
                          <td colSpan={hasBandit ? 9 : 6} className="p-3 bg-slate-950">
                            <FindingsDetail result={r} showBandit={hasBandit} />
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'analysis' && (
          <div>
            {analysis && !('error' in analysis) ? (
              <AnalysisView analysis={analysis} hasBandit={hasBandit} />
            ) : (
              <p className="text-sm text-slate-500">No analysis data available.</p>
            )}
          </div>
        )}
      </div>

      {/* Logs — always visible at bottom, expanded by default */}
      <div className="border-t border-slate-700 pt-3">
        <details open>
          <summary className="text-sm font-medium text-slate-300 cursor-pointer mb-2 select-none">
            Logs
          </summary>
          <LogViewer runId={isActive ? runId : null} />
        </details>
      </div>
    </div>
  );
}

function LanguageTag({ language }: { language: string }) {
  const colors: Record<string, string> = {
    typescript: 'bg-blue-500/20 text-blue-400',
    javascript: 'bg-yellow-500/20 text-yellow-400',
    python: 'bg-green-500/20 text-green-400',
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${colors[language] ?? 'bg-slate-700 text-slate-400'}`}>
      {language}
    </span>
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
      {semgrep.map((issue, i) => {
        // Prefer the canonical HIGH/MEDIUM/LOW severity; fall back to the raw
        // rule level (ERROR/WARNING/INFO) for records written before metadata.
        const levelToHml: Record<string, string> = { ERROR: 'HIGH', WARNING: 'MEDIUM', INFO: 'LOW' };
        const sev = issue.severity_normalized || levelToHml[issue.severity] || issue.severity;
        const sevColors: Record<string, string> = {
          HIGH: 'bg-red-500/20 text-red-400',
          MEDIUM: 'bg-amber-500/20 text-amber-400',
          LOW: 'bg-blue-500/20 text-blue-400',
        };
        const sevStyle = sevColors[sev] || 'bg-slate-500/20 text-slate-400';
        const cwe = (issue.cwe && issue.cwe.length > 0) ? issue.cwe.join(', ') : null;
        return (
        <div key={`s-${i}`} className="p-2 bg-slate-900 rounded border border-slate-800">
          <div className="flex items-center gap-2 mb-1">
            <span className="px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded text-[10px] font-medium">SEMGREP</span>
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${sevStyle}`}>{sev}</span>
            <span className="text-slate-300 font-medium">{issue.rule_id}</span>
            {cwe && <span className="text-slate-500">{cwe}</span>}
            <span className="text-slate-500">line {issue.line_number}</span>
          </div>
          <p className="text-slate-400">{issue.message}</p>
          {issue.matched_lines && (
            <pre className="mt-1 text-slate-500 bg-slate-950 rounded px-2 py-1 font-mono">{issue.matched_lines}</pre>
          )}
        </div>
        );
      })}
    </div>
  );
}

function AnalysisView({ analysis, hasBandit }: { analysis: AnalysisData; hasBandit: boolean }) {
  const { summary, trends, deltas } = analysis;
  return (
    <div className="space-y-6">
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
                <th className="text-center px-2 py-1 text-red-400">S:HIGH</th>
                <th className="text-center px-2 py-1 text-amber-400">S:MED</th>
                <th className="text-center px-2 py-1 text-blue-400">S:LOW</th>
                <th className="text-left px-2 py-1 text-slate-400">Prompt</th>
              </tr>
            </thead>
            <tbody>
              {t.rows.map((row) => (
                <tr key={row.iteration} className="border-b border-slate-800/50">
                  <td className="px-2 py-1.5 text-slate-300">{row.iteration}</td>
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_high ?? 0} max={Math.max(...t.rows.map((r) => r.bandit_high ?? 0), 1)} color="red" />
                    </td>
                  )}
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_medium ?? 0} max={Math.max(...t.rows.map((r) => r.bandit_medium ?? 0), 1)} color="amber" />
                    </td>
                  )}
                  {hasBandit && (
                    <td className="px-2 py-1.5 text-center">
                      <MetricBar value={row.bandit_low ?? 0} max={Math.max(...t.rows.map((r) => r.bandit_low ?? 0), 1)} color="yellow" />
                    </td>
                  )}
                  <td className="px-2 py-1.5 text-center">
                    <MetricBar value={row.semgrep_high ?? 0} max={Math.max(...t.rows.map((r) => r.semgrep_high ?? 0), 1)} color="red" />
                  </td>
                  <td className="px-2 py-1.5 text-center">
                    <MetricBar value={row.semgrep_medium ?? 0} max={Math.max(...t.rows.map((r) => r.semgrep_medium ?? 0), 1)} color="amber" />
                  </td>
                  <td className="px-2 py-1.5 text-center">
                    <MetricBar value={row.semgrep_low ?? 0} max={Math.max(...t.rows.map((r) => r.semgrep_low ?? 0), 1)} color="blue" />
                  </td>
                  <td className="px-2 py-1.5 text-slate-500 truncate max-w-[200px]">{row.prompt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

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
                <th className="text-center px-2 py-1 text-red-400">S:HIGH</th>
                <th className="text-center px-2 py-1 text-amber-400">S:MED</th>
                <th className="text-center px-2 py-1 text-blue-400">S:LOW</th>
              </tr>
            </thead>
            <tbody>
              {deltas.map((d: DeltaEntry) => (
                <tr key={`${d.vulnerability_id}-${d.agent}`} className="border-b border-slate-800/50">
                  <td className="px-2 py-1.5 text-slate-300">{d.vulnerability_id}</td>
                  <td className="px-2 py-1.5 text-blue-400">{d.agent}</td>
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_high_delta ?? 0} /></td>}
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_medium_delta ?? 0} /></td>}
                  {hasBandit && <td className="px-2 py-1.5 text-center"><DeltaValue value={d.bandit_low_delta ?? 0} /></td>}
                  <td className="px-2 py-1.5 text-center"><DeltaValue value={d.semgrep_high_delta} /></td>
                  <td className="px-2 py-1.5 text-center"><DeltaValue value={d.semgrep_medium_delta} /></td>
                  <td className="px-2 py-1.5 text-center"><DeltaValue value={d.semgrep_low_delta} /></td>
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
    blue: 'bg-blue-500',
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
