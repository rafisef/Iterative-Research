import type {
  AnalysisData,
  Agent,
  ConfigData,
  GeneratedCode,
  ProcessInfo,
  ResultRecord,
  Run,
  Vulnerability,
} from '../types';

const BASE = '';

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  return res.json();
}

// ── Config ──────────────────────────────────────────────────────────────────

export const configApi = {
  get: () => request<ConfigData>('/api/config'),
  put: (content: string) =>
    request<{ status: string; parsed: Record<string, unknown> }>('/api/config', {
      method: 'PUT',
      body: JSON.stringify({ content }),
    }),
};

// ── Runs ────────────────────────────────────────────────────────────────────

export const runsApi = {
  list: () => request<Run[]>('/api/runs'),
  get: (runId: string) => request<Run>(`/api/runs/${runId}`),
  delete: (runId: string) => request<{ status: string }>(`/api/runs/${runId}`, { method: 'DELETE' }),
  sync: () => request<{ synced: number }>('/api/runs/sync', { method: 'POST' }),

  results: (runId: string, agent?: string, vuln?: string) => {
    const params = new URLSearchParams();
    if (agent) params.set('agent', agent);
    if (vuln) params.set('vuln', vuln);
    const qs = params.toString();
    return request<ResultRecord[]>(`/api/runs/${runId}/results${qs ? `?${qs}` : ''}`);
  },
  updateResult: (runId: string, resultId: number, data: Partial<ResultRecord>) =>
    request<ResultRecord>(`/api/runs/${runId}/results/${resultId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  deleteResult: (runId: string, resultId: number) =>
    request<{ status: string }>(`/api/runs/${runId}/results/${resultId}`, { method: 'DELETE' }),

  code: (runId: string, agent?: string, vuln?: string) => {
    const params = new URLSearchParams();
    if (agent) params.set('agent', agent);
    if (vuln) params.set('vuln', vuln);
    const qs = params.toString();
    return request<GeneratedCode[]>(`/api/runs/${runId}/code${qs ? `?${qs}` : ''}`);
  },
  updateCode: (runId: string, agent: string, vulnId: string, iteration: number, code: string) =>
    request<GeneratedCode>(`/api/runs/${runId}/code/${agent}/${vulnId}/${iteration}`, {
      method: 'PUT',
      body: JSON.stringify({ code_content: code }),
    }),
  deleteCode: (runId: string, agent: string, vulnId: string, iteration: number) =>
    request<{ status: string }>(`/api/runs/${runId}/code/${agent}/${vulnId}/${iteration}`, {
      method: 'DELETE',
    }),

  analysis: (runId: string) => request<AnalysisData>(`/api/runs/${runId}/analysis`),
};

// ── Actions ─────────────────────────────────────────────────────────────────

export interface ExperimentParams {
  model?: string;
  iterations?: number;
  run_id?: string;
  snippet?: string;
  base_code_dir?: string;
  log?: string;
  config?: string;
}

export const actionsApi = {
  startExperiment: (params: ExperimentParams) =>
    request<{ run_id: string; pid: number }>('/api/experiment', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  startGenerate: (params: ExperimentParams) =>
    request<{ run_id: string; pid: number }>('/api/runs/generate', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  startScan: (runId: string, config?: string) =>
    request<{ run_id: string; pid: number }>(`/api/runs/${runId}/scan`, {
      method: 'POST',
      body: JSON.stringify({ config: config || 'config/config.yaml' }),
    }),
  startBaselineScan: (params: { snippet?: string; base_code_dir?: string; semgrep_config?: string; config?: string }) =>
    request<{ run_id: string; pid: number }>('/api/scan/baseline', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  startAdhocScan: (params: { snippet?: string; base_code_dir?: string; semgrep_config?: string; config?: string }) =>
    request<{ run_id: string; pid: number }>('/api/scan/adhoc', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  startTestRun: (params: { snippet?: string; model?: string; config?: string }) =>
    request<{ run_id: string; pid: number }>('/api/test-run', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  startTestLLM: (params: { model?: string; config?: string }) =>
    request<{ run_id: string; pid: number }>('/api/test-llm', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
  startNucleiRescan: (params: { run_id?: string; scan_all?: boolean; agent?: string; min_severity?: string; config?: string }) =>
    request<{ run_id: string; pid: number }>('/api/nuclei-rescan', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  killProcess: (pid: number) =>
    request<{ status: string }>(`/api/process/${pid}/kill`, { method: 'POST' }),
  activeProcesses: () => request<ProcessInfo[]>('/api/process/active'),
};

// ── Reference ───────────────────────────────────────────────────────────────

export const referenceApi = {
  vulnerabilities: () => request<Vulnerability[]>('/api/vulnerabilities'),
  agents: () => request<Agent[]>('/api/agents'),
  availableModels: () => request<{ models: string[] }>('/api/models/available'),
};

// ── Environment Variables ───────────────────────────────────────────────────

export interface EnvVar {
  name: string;
  is_set: boolean;
  default_model: string;
}

export const envApi = {
  list: () => request<EnvVar[]>('/api/env'),
  set: (name: string, value: string) =>
    request<{ status: string; name: string; is_set: boolean }>('/api/env', {
      method: 'PUT',
      body: JSON.stringify({ name, value }),
    }),
  delete: (name: string) =>
    request<{ status: string; name: string; is_set: boolean }>(`/api/env/${name}`, {
      method: 'DELETE',
    }),
};

// ── Language detection ───────────────────────────────────────────────────────

export interface LanguageInfo {
  language: string;
  count: number;
}

export const languageApi = {
  detect: (path: string) =>
    request<{ languages: LanguageInfo[] }>(`/api/detect-language?path=${encodeURIComponent(path)}`),
};

// ── Filesystem autocomplete ─────────────────────────────────────────────────

export interface PathEntry {
  path: string;
  is_dir: boolean;
}

export const pathApi = {
  autocomplete: (prefix: string, dirsOnly = false) => {
    const params = new URLSearchParams({ prefix });
    if (dirsOnly) params.set('dirs_only', 'true');
    return request<PathEntry[]>(`/api/autocomplete/path?${params}`);
  },
};
