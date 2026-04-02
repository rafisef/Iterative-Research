import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { runsApi } from '../api/client';
import { StatusBadge } from '../components/common/StatusBadge';
import { Spinner } from '../components/common/Spinner';
import type { Run } from '../types';

export function DashboardPage() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const navigate = useNavigate();

  const fetchRuns = useCallback(async () => {
    try {
      const data = await runsApi.list();
      setRuns(data);
    } catch (err) {
      console.error('Failed to load runs:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRuns(); }, [fetchRuns]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const { synced } = await runsApi.sync();
      if (synced > 0) await fetchRuns();
    } finally {
      setSyncing(false);
    }
  };

  const handleDelete = async (runId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete run "${runId}" and all its data?`)) return;
    try {
      await runsApi.delete(runId);
      setRuns((prev) => prev.filter((r) => r.id !== runId));
    } catch (err) {
      console.error('Failed to delete run:', err);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white">Dashboard</h2>
          <p className="text-sm text-slate-400 mt-1">All experiment runs</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-slate-300 transition-colors disabled:opacity-50"
          >
            {syncing ? <Spinner size="sm" /> : null}
            Sync from filesystem
          </button>
          <Link
            to="/new"
            className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Experiment
          </Link>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-20"><Spinner size="lg" /></div>
      ) : runs.length === 0 ? (
        <div className="text-center py-20 text-slate-500">
          <p className="text-lg mb-2">No runs found</p>
          <p className="text-sm">Start a new experiment or sync existing runs from the filesystem.</p>
        </div>
      ) : (
        <div className="bg-slate-900/50 border border-slate-700/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-4 py-3 text-slate-400 font-medium">Run ID</th>
                <th className="text-left px-4 py-3 text-slate-400 font-medium">Model</th>
                <th className="text-center px-4 py-3 text-slate-400 font-medium">Iterations</th>
                <th className="text-center px-4 py-3 text-slate-400 font-medium">Agents</th>
                <th className="text-center px-4 py-3 text-slate-400 font-medium">Vulns</th>
                <th className="text-left px-4 py-3 text-slate-400 font-medium">Status</th>
                <th className="text-left px-4 py-3 text-slate-400 font-medium">Started</th>
                <th className="text-right px-4 py-3 text-slate-400 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr
                  key={run.id}
                  onClick={() => navigate(`/runs/${run.id}`)}
                  className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-blue-400 text-xs">{run.id}</td>
                  <td className="px-4 py-3 text-slate-300">{run.model || '—'}</td>
                  <td className="px-4 py-3 text-center text-slate-300">{run.iterations ?? '—'}</td>
                  <td className="px-4 py-3 text-center text-slate-300">{run.agents?.length ?? 0}</td>
                  <td className="px-4 py-3 text-center text-slate-300">{run.vulnerabilities?.length ?? 0}</td>
                  <td className="px-4 py-3"><StatusBadge status={run.status} /></td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    {run.started_at ? new Date(run.started_at).toLocaleString() : '—'}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={(e) => handleDelete(run.id, e)}
                      className="text-slate-500 hover:text-red-400 transition-colors p-1"
                      title="Delete run"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
