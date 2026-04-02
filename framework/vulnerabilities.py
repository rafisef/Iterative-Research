from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Vulnerability:
  id: str
  description: str
  base_snippet_path: str
  # Optional per-vulnerability Semgrep rule pack override.  Empty string means
  # use the language-default packs from static_scanner._DEFAULT_SEMGREP_PACKS.
  # Space-separated for multiple packs (e.g. "p/typescript p/owasp-top-ten").
  semgrep_config: str = ""


def get_all_vulnerabilities() -> Dict[str, Vulnerability]:
  """
  Registry of vulnerabilities known to the framework.

  Directory layout mirrors this structure:
    snippets/
      python/
        <category>/
          <name>_base.py
      typescript/
        <category>/
          <name>_base.ts
  """
  return {
    # -----------------------------------------------------------------------
    # Python
    # -----------------------------------------------------------------------
    "injection_xss_comment_page": Vulnerability(
      id="injection_xss_comment_page",
      description="XSS-hardened comment page accepting user input and displaying comments.",
      base_snippet_path="snippets/python/injection/xss_comment_page_base.py",
      semgrep_config="p/xss p/flask-security",
    ),

    # -----------------------------------------------------------------------
    # TypeScript
    # -----------------------------------------------------------------------
    "ts_input_validation": Vulnerability(
      id="ts_input_validation",
      description="Input validation — strip insecure patterns introduced by LLM refactoring.",
      base_snippet_path="snippets/typescript/validation/input_validation_register_base.ts",
    ),
    "ts_concurrency": Vulnerability(
      id="ts_concurrency",
      description="Concurrency — detect race conditions and unsafe shared-state mutations.",
      base_snippet_path="snippets/typescript/concurrency/concurrency_safe_counter_base.ts",
      semgrep_config="p/typescript",
    ),
    "ts_information_leakage": Vulnerability(
      id="ts_information_leakage",
      description="Information leakage — catch accidental exposure of sensitive fields or stack traces.",
      base_snippet_path="snippets/typescript/leakage/info_leakage_user_safe_base.ts",
    ),
    "ts_access_control": Vulnerability(
      id="ts_access_control",
      description="Access control — identify broken authorization and privilege escalation paths.",
      base_snippet_path="snippets/typescript/access_control/access_control_rbac_ownership_base.ts",
      semgrep_config="p/owasp-top-ten p/typescript",
    ),
    "ts_injection": Vulnerability(
      id="ts_injection",
      description="Injection — SQL injection, command injection via child_process in Node.",
      base_snippet_path="snippets/typescript/injection/injection_sql_cmd_base.ts",
    ),
    "ts_race_condition": Vulnerability(
      id="ts_race_condition",
      description="Race conditions — optimistic-lock bypass and TOCTOU in async code.",
      base_snippet_path="snippets/typescript/race_condition/race_condition_transfer_base.ts",
      semgrep_config="p/typescript p/javascript",
    ),
    "ts_error_handling": Vulnerability(
      id="ts_error_handling",
      description="Error handling — prevent stack trace / internal path leakage in responses.",
      base_snippet_path="snippets/typescript/error_handling/error_handling_app_error_base.ts",
      semgrep_config="p/typescript p/owasp-top-ten",
    ),
  }


def resolve_vulnerabilities_from_config(vuln_ids: List[str]) -> List[Vulnerability]:
  all_vulns = get_all_vulnerabilities()
  resolved: List[Vulnerability] = []
  for vid in vuln_ids:
    if vid not in all_vulns:
      raise KeyError(f"Unknown vulnerability id: {vid}")
    resolved.append(all_vulns[vid])
  return resolved
