#!/usr/bin/env python3
"""
nuclei_rescan.py — Re-run Nuclei dynamic scanning against snippets from a completed run.

Reads results.jsonl from a timestamped run directory, filters to iterations where
Bandit/Semgrep found something (or all of them with --all), then for each matched
snippet:
  1. Starts the Flask snippet server on a dedicated local port
  2. Waits for the /health endpoint to confirm it is ready
  3. Runs Nuclei with -j (JSON output) to capture structured findings
  4. Stops the server and saves raw + parsed output
  5. Appends a record to runs/<run_id>/nuclei_results.jsonl
  6. Prints a findings summary table on completion

Nuclei logs land at:  runs/<run_id>/logs/<agent>/<vuln>/nuclei_iteration_N.log
Structured results at: runs/<run_id>/nuclei_results.jsonl

Usage:
  python nuclei_rescan.py --run 2026-03-18_14-30-00
  python nuclei_rescan.py --run 2026-03-18_14-30-00 --all
  python nuclei_rescan.py --run 2026-03-18_14-30-00 --agent ambiguous
  python nuclei_rescan.py --run 2026-03-18_14-30-00 --min-severity medium
  python nuclei_rescan.py --list-runs
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

RUNS_DIR = "runs"
DEFAULT_PORT = 9900
DEFAULT_HOST = "127.0.0.1"
STARTUP_TIMEOUT = 10   # seconds to wait for /health
NUCLEI_TIMEOUT = 120   # seconds before giving up on a nuclei process

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("nuclei_rescan")


# ---------------------------------------------------------------------------
# Run / results helpers
# ---------------------------------------------------------------------------

def _all_run_dirs(runs_dir: str = RUNS_DIR) -> List[Path]:
    p = Path(runs_dir)
    if not p.exists():
        return []
    return sorted(d for d in p.iterdir() if d.is_dir() and (d / "results.jsonl").exists())


def _load_metadata(run_dir: Path) -> Dict[str, Any]:
    meta = run_dir / "run_metadata.json"
    if meta.exists():
        try:
            return json.loads(meta.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _count_lines(p: Path) -> int:
    try:
        return sum(1 for ln in p.open(encoding="utf-8") if ln.strip())
    except Exception:
        return 0


def list_runs(runs_dir: str = RUNS_DIR) -> None:
    dirs = _all_run_dirs(runs_dir)
    if not dirs:
        print(f"[info] No runs found in '{runs_dir}/'. Run the experiment first.")
        return
    print(f"\n{'=' * 70}")
    print(f"  Available runs ({len(dirs)} total)  —  pass --run <RUN_ID>")
    print(f"{'=' * 70}")
    print(f"  {'Run ID':<26}  {'Records':>7}  {'Nuclei rescan':>14}  {'Model'}")
    print(f"  {'-' * 26}  {'-' * 7}  {'-' * 14}  {'-' * 20}")
    latest = dirs[-1].name if dirs else ""
    for d in reversed(dirs):
        records = _count_lines(d / "results.jsonl")
        nuclei = _count_lines(d / "nuclei_results.jsonl") if (d / "nuclei_results.jsonl").exists() else "-"
        meta = _load_metadata(d)
        model = meta.get("model", "?")
        marker = " ← latest" if d.name == latest else ""
        print(f"  {d.name:<26}  {records:>7}  {str(nuclei):>14}  {model}{marker}")
    print()


def load_results(run_dir: Path) -> List[Dict[str, Any]]:
    results_file = run_dir / "results.jsonl"
    if not results_file.exists():
        log.error("results.jsonl not found in %s", run_dir)
        sys.exit(1)
    records = []
    with results_file.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                log.warning("Skipping malformed line %d: %s", i, e)
    return records


def _severity_rank(s: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(s.lower(), 0)


def filter_records(
    records: List[Dict[str, Any]],
    scan_all: bool,
    agent_filter: Optional[str],
    min_severity: str,
) -> List[Dict[str, Any]]:
    """Return the subset of records that should be re-scanned."""
    out = []
    rank = _severity_rank(min_severity)
    for r in records:
        if agent_filter and r.get("agent") != agent_filter:
            continue
        if not r.get("snippet_path"):
            continue
        if not Path(r["snippet_path"]).exists():
            log.warning(
                "Snippet not found, skipping: %s (agent=%s iter=%s)",
                r["snippet_path"], r.get("agent"), r.get("iteration"),
            )
            continue
        if scan_all:
            out.append(r)
            continue
        # Include if static scanners found anything at or above the threshold.
        b_high = int(r.get("bandit_high", 0))
        b_med = int(r.get("bandit_medium", 0))
        b_low = int(r.get("bandit_low", 0))
        sg = int(r.get("semgrep_findings", 0))
        if rank <= 3 and b_high > 0:
            out.append(r)
        elif rank <= 2 and b_med > 0:
            out.append(r)
        elif rank <= 1 and (b_low > 0 or sg > 0):
            out.append(r)
        elif rank == 0 and (b_high + b_med + b_low + sg) > 0:
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def start_server(snippet_path: str, port: int) -> subprocess.Popen:
    log.info("Starting server: %s on port %d", snippet_path, port)
    return subprocess.Popen(
        [sys.executable, snippet_path, "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def wait_for_health(host: str, port: int, timeout: int) -> bool:
    url = f"http://{host}:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2).status_code == 200:
                log.info("Server ready at %s", url)
                return True
        except Exception:
            pass
        time.sleep(1)
    log.warning("Server did not become healthy at %s within %ds", url, timeout)
    return False


def stop_server(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    if proc.poll() is not None:
        try:
            proc.communicate(timeout=0.1)
        except Exception:
            pass
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    try:
        proc.communicate(timeout=0.1)
    except Exception:
        pass
    log.info("Server pid=%s stopped", proc.pid)


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

def _nuclei_binary(config_path: str = "config/config.yaml") -> str:
    """Read binary path from config, fall back to 'nuclei' on PATH."""
    try:
        import yaml
        cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
        path = cfg.get("nuclei", {}).get("binary_path", "")
        if path and Path(path).exists():
            return path
    except Exception:
        pass
    import shutil
    found = shutil.which("nuclei")
    return found or "nuclei"


def _nuclei_tags(config_path: str = "config/config.yaml") -> List[str]:
    try:
        import yaml
        cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
        return cfg.get("nuclei", {}).get("tags", ["xss"]) or ["xss"]
    except Exception:
        return ["xss"]


def run_nuclei(
    target_url: str,
    binary: str,
    tags: List[str],
    log_path: Path,
) -> Tuple[Optional[int], List[Dict[str, Any]], str]:
    """
    Run Nuclei against target_url.

    Returns (exit_code, findings_list, raw_output).

    Findings are parsed from Nuclei's -j (JSON Lines) output.  Each line that
    is valid JSON and contains a 'template-id' key is treated as a finding.
    """
    cmd = [
        binary,
        "-u", target_url,
        "-vv",
        "-headless",
        "-c", "50",
        "-j",                   # JSON Lines output — one finding per line
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    log.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
        )
        raw = proc.stdout or ""
        # stderr contains progress/status lines; combine for the saved log.
        full_log = (proc.stderr or "") + raw
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        raw = ""
        full_log = f"NUCLEI TIMEOUT after {NUCLEI_TIMEOUT}s"
        exit_code = None
        log.warning("Nuclei timed out after %ds", NUCLEI_TIMEOUT)
    except FileNotFoundError:
        raw = ""
        full_log = f"NUCLEI ERROR: binary not found at '{binary}'"
        exit_code = None
        log.error("Nuclei binary not found: %s", binary)

    # Parse structured findings from JSON Lines output.
    findings: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if "template-id" in obj:
                findings.append(obj)
        except json.JSONDecodeError:
            pass

    # Save full log to disk.
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(full_log, encoding="utf-8")
    log.info("Nuclei log written to %s  (findings=%d)", log_path, len(findings))

    return exit_code, findings, full_log


def _summarise_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract the key fields from each raw Nuclei JSON finding."""
    out = []
    for f in findings:
        info = f.get("info") or {}
        out.append({
            "template_id": f.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "tags": info.get("tags", []),
            "matched_at": f.get("matched-at", ""),
            "type": f.get("type", ""),
        })
    return out


# ---------------------------------------------------------------------------
# Results recording
# ---------------------------------------------------------------------------

def append_nuclei_record(results_file: Path, record: Dict[str, Any]) -> None:
    results_file.parent.mkdir(parents=True, exist_ok=True)
    with results_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(results: List[Dict[str, Any]]) -> None:
    print(f"\n{'=' * 75}")
    print(f"  Nuclei Rescan Summary")
    print(f"{'=' * 75}")
    print(f"  {'Agent':<14} {'Iter':>5}  {'Server':>8}  {'Exit':>5}  {'Findings':>9}  Matched Templates")
    print(f"  {'-' * 14} {'-' * 5}  {'-' * 8}  {'-' * 5}  {'-' * 9}  {'-' * 30}")

    total_findings = 0
    for r in results:
        agent = r.get("agent", "?")
        it = r.get("iteration", "?")
        started = "yes" if r.get("server_started") else "NO"
        exit_code = str(r.get("nuclei_exit_code", "n/a"))
        findings = r.get("findings", [])
        count = len(findings)
        total_findings += count
        templates = ", ".join(f.get("template_id", "?") for f in findings[:3])
        if len(findings) > 3:
            templates += f" (+{len(findings) - 3} more)"
        print(f"  {agent:<14} {str(it):>5}  {started:>8}  {exit_code:>5}  {count:>9}  {templates or '—'}")

    print(f"\n  Total Nuclei findings: {total_findings}")
    if total_findings:
        print(f"\n  Severity breakdown:")
        sev_count: Dict[str, int] = {}
        for r in results:
            for f in r.get("findings", []):
                sev = f.get("severity", "unknown").lower()
                sev_count[sev] = sev_count.get(sev, 0) + 1
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev in sev_count:
                print(f"    {sev:<10}: {sev_count[sev]}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Re-run Nuclei against snippets from a completed experiment run. "
            "By default only scans iterations where Bandit/Semgrep found something."
        )
    )
    parser.add_argument(
        "--run",
        type=str,
        default="",
        metavar="RUN_ID",
        help="Run ID to rescan (e.g. 2026-03-18_14-30-00). Defaults to most recent run.",
    )
    parser.add_argument(
        "--runs-dir",
        type=str,
        default=RUNS_DIR,
        help=f"Root directory containing run folders (default: {RUNS_DIR}).",
    )
    parser.add_argument(
        "--list-runs",
        action="store_true",
        help="List all available runs and exit.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan every iteration, not just those with static findings.",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default="",
        help="Limit rescan to a single agent (e.g. ambiguous).",
    )
    parser.add_argument(
        "--min-severity",
        type=str,
        default="low",
        choices=["low", "medium", "high"],
        help=(
            "Minimum Bandit severity that triggers a rescan. "
            "Semgrep findings always count regardless of severity. "
            "(default: low — any static finding triggers Nuclei)"
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Local port used to serve each snippet (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/config.yaml",
        help="Path to config.yaml (used to read nuclei binary path and tags).",
    )
    args = parser.parse_args()

    if args.list_runs:
        list_runs(args.runs_dir)
        return

    # Resolve run directory.
    if args.run:
        run_dir = Path(args.runs_dir) / args.run
    else:
        dirs = _all_run_dirs(args.runs_dir)
        if not dirs:
            log.error("No runs found in '%s/'. Run the experiment first.", args.runs_dir)
            sys.exit(1)
        run_dir = dirs[-1]
        log.info("Auto-selected most recent run: %s", run_dir.name)

    if not run_dir.exists():
        log.error("Run directory not found: %s", run_dir)
        sys.exit(1)

    # Load static scan results.
    records = load_results(run_dir)
    to_scan = filter_records(
        records,
        scan_all=args.all,
        agent_filter=args.agent or None,
        min_severity=args.min_severity,
    )

    if not to_scan:
        if args.all:
            log.info("No records with snippet paths found in this run.")
        else:
            log.info(
                "No iterations met the --min-severity=%s threshold. "
                "Use --all to force-scan every snippet.",
                args.min_severity,
            )
        return

    # Resolve Nuclei binary and tags.
    nuclei_bin = _nuclei_binary(args.config)
    nuclei_tags = _nuclei_tags(args.config)
    logs_dir = run_dir / "logs"
    nuclei_results_file = run_dir / "nuclei_results.jsonl"

    log.info("=" * 60)
    log.info("Run ID        : %s", run_dir.name)
    log.info("Snippets found: %d  (from %d total records)", len(to_scan), len(records))
    log.info("Nuclei binary : %s", nuclei_bin)
    log.info("Nuclei tags   : %s", nuclei_tags)
    log.info("Port          : %d", args.port)
    log.info("Results file  : %s", nuclei_results_file)
    log.info("=" * 60)

    scan_results: List[Dict[str, Any]] = []

    for idx, rec in enumerate(to_scan):
        agent = rec.get("agent", "unknown")
        vuln_id = rec.get("vulnerability_id", "unknown")
        iteration = rec.get("iteration", -1)
        snippet_path = rec["snippet_path"]

        log.info(
            "[%d/%d] agent=%-12s  iter=%d  snippet=%s",
            idx + 1, len(to_scan), agent, iteration, snippet_path,
        )

        nuclei_log_path = logs_dir / agent / vuln_id / f"nuclei_iteration_{iteration}.log"
        proc = None
        server_started = False
        exit_code = None
        findings: List[Dict[str, Any]] = []
        raw_output = ""

        try:
            proc = start_server(snippet_path, args.port)
            server_started = wait_for_health(DEFAULT_HOST, args.port, STARTUP_TIMEOUT)

            if not server_started:
                log.warning("Server did not start — skipping Nuclei for this snippet.")
                nuclei_log_path.parent.mkdir(parents=True, exist_ok=True)
                nuclei_log_path.write_text(
                    f"SERVER_START_FAILED: {snippet_path}\n", encoding="utf-8"
                )
            else:
                target_url = f"http://{DEFAULT_HOST}:{args.port}/"
                exit_code, raw_findings, raw_output = run_nuclei(
                    target_url=target_url,
                    binary=nuclei_bin,
                    tags=nuclei_tags,
                    log_path=nuclei_log_path,
                )
                findings = _summarise_findings(raw_findings)

        finally:
            stop_server(proc)

        result_record = {
            "scanned_at": datetime.now().isoformat(),
            "run_id": run_dir.name,
            "agent": agent,
            "vulnerability_id": vuln_id,
            "iteration": iteration,
            "snippet_path": snippet_path,
            "server_started": server_started,
            "nuclei_exit_code": exit_code,
            "nuclei_log_path": str(nuclei_log_path),
            "finding_count": len(findings),
            "findings": findings,
            # Static context from the original run record.
            "static_bandit_high": rec.get("bandit_high", 0),
            "static_bandit_medium": rec.get("bandit_medium", 0),
            "static_bandit_low": rec.get("bandit_low", 0),
            "static_semgrep_findings": rec.get("semgrep_findings", 0),
        }
        append_nuclei_record(nuclei_results_file, result_record)
        scan_results.append(result_record)

    print_summary(scan_results)
    print(f"  Full results: {nuclei_results_file}")
    print(f"  Nuclei logs : {logs_dir}/")


if __name__ == "__main__":
    main()
