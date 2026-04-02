export interface Run {
  id: string;
  started_at: string | null;
  model: string | null;
  temperature: number | null;
  max_tokens: number | null;
  iterations: number | null;
  agents: string[];
  vulnerabilities: string[];
  random_seed: number | null;
  status: string;
  snippet: string | null;
  base_code_dir: string | null;
  result_count?: number;
  code_count?: number;
}

export interface ResultRecord {
  id: number;
  run_id: string;
  agent: string;
  vulnerability_id: string;
  iteration: number;
  prompt: string;
  model: string;
  success: boolean;
  server_started: boolean;
  nuclei_exit_code: number | null;
  snippet_path: string;
  log_path: string;
  bandit_high: number;
  bandit_medium: number;
  bandit_low: number;
  semgrep_findings: number;
  static_log_path: string;
  bandit_issues: BanditIssue[];
  semgrep_issues: SemgrepIssue[];
}

export interface BanditIssue {
  test_id: string;
  test_name: string;
  severity: string;
  confidence: string;
  line_number: number;
  issue_text: string;
  cwe_id: number | null;
}

export interface SemgrepIssue {
  rule_id: string;
  severity: string;
  message: string;
  line_number: number;
  matched_lines: string;
}

export interface GeneratedCode {
  id: number;
  run_id: string;
  agent: string;
  vuln_id: string;
  iteration: number;
  language: string;
  file_path: string;
  code_content: string;
  has_syntax_error: boolean;
}

export interface Vulnerability {
  id: string;
  description: string;
  base_snippet_path: string;
  semgrep_config: string;
  language: string;
}

export interface Agent {
  id: string;
  description: string;
  instructions: string[];
}

export interface ConfigData {
  raw: string;
  parsed: Record<string, unknown> | null;
  error: string | null;
}

export interface AnalysisData {
  summary: {
    run_id: string | null;
    results_path: string;
    total_records: number;
    agents: string[];
    vulnerabilities: string[];
    models: string[];
    iteration_range: number[];
    distinct_iterations: number;
    has_static_scans: boolean;
    has_nuclei_scans: boolean;
    random_seed: number | null;
    started_at: string | null;
  };
  trends: TrendGroup[];
  deltas: DeltaEntry[];
  findings: FindingGroup[];
}

export interface TrendGroup {
  vulnerability_id: string;
  agent: string;
  rows: TrendRow[];
}

export interface TrendRow {
  iteration: number;
  bandit_high: number;
  bandit_medium: number;
  bandit_low: number;
  semgrep_findings: number;
  prompt: string;
  model: string;
}

export interface DeltaEntry {
  vulnerability_id: string;
  agent: string;
  bandit_high_delta: number;
  bandit_medium_delta: number;
  bandit_low_delta: number;
  semgrep_delta: number;
}

export interface FindingGroup {
  vulnerability_id: string;
  agent: string;
  iteration: number;
  bandit_issues: BanditIssue[];
  semgrep_issues: SemgrepIssue[];
}

export interface ProcessInfo {
  pid: number;
  run_id: string;
  command: string;
  started_at: number;
  status: string;
}
