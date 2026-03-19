# 1. Run the full experiment
python -m framework.runner

# 2. See what static findings came back
python analyze.py

# 3. Run Nuclei only on the flagged iterations
python nuclei_rescan.py --run 2026-03-19_08-57-11

# 4. Re-analyze — nuclei_results.jsonl is now in the run folder too
python nuclei_rescan.py --list-runs   # shows nuclei rescan count per run