from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Vulnerability:
  id: str
  description: str
  base_snippet_path: str


def get_all_vulnerabilities() -> Dict[str, Vulnerability]:
  """
  Registry of vulnerabilities known to the framework.
  """
  return {
    "injection_xss_comment_page": Vulnerability(
      id="injection_xss_comment_page",
      description="XSS-hardened comment page accepting user input and displaying comments.",
      base_snippet_path="snippets/injection/xss_comment_page_base.py",
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

