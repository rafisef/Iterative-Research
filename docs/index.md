# Iterative Research — Documentation

Iterative Research is a Python-based experimental framework for recreating and extending the study described in:

> **Security Degradation in Iterative AI Code Generation — A Systematic Analysis of the Paradox**
> Shivani Shukla, Himanshu Joshi, Romilla Syed
> [arXiv:2506.11022](https://arxiv.org/abs/2506.11022)

The paper's central finding is that iterative LLM-driven code "improvement" paradoxically _introduces_ security vulnerabilities — observing a **37.6% increase in critical vulnerabilities** after just five rounds of supposed improvement, across 400 code samples and four prompting strategies.

This framework automates that experimental loop: it feeds a known-secure base code snippet to an LLM, saves each generated version, spins it up as a live web server, scans it with [Nuclei](https://github.com/projectdiscovery/nuclei) for security regressions, and feeds the output back as the next iteration's input.

---

## Documentation Pages

| Page | Description |
|---|---|
| [Architecture](./architecture.md) | Module breakdown, data flow, and the full iteration pipeline |
| [Configuration](./configuration.md) | Complete reference for every key in `config/config.yaml` |
| [Agents](./agents.md) | Prompting strategies, instruction pools, and agent design |
| [Vulnerabilities](./vulnerabilities.md) | Vulnerability registry, base snippet analysis, adding new targets |
| [Running the Experiment](./running.md) | Installation, prerequisites, CLI flags, and example commands |
| [Results & Output](./results.md) | Output directory layout, `results.jsonl` schema, and log files |
| [Extending the Framework](./extending.md) | Adding new LLM providers, agents, vulnerabilities, and scanners |

---

## Quick Start

```bash
# 1. Install dependencies
python3 -m venv ai-research-env && source ai-research-env/bin/activate
pip install -r requirements.txt

# 2. Set your OpenAI key
export OPENAI_API_KEY="sk-..."

# 3. Update the nuclei binary path in config/config.yaml
#    nuclei.binary_path: /path/to/nuclei

# 4. Run a dry-run first to verify LLM connectivity
python -m framework.runner --dry-run

# 5. Run the full experiment
python -m framework.runner
```

---

## Research Context

The original paper ran 10 iterations across four prompting strategies against multiple vulnerability categories, producing 400 code samples in total. The key findings relevant to this framework:

- **Security-focused prompts** did not reliably improve security posture and sometimes degraded it.
- **Ambiguous prompts** ("Please improve this code") produced the most unpredictable and damaging results.
- **Feature-focused prompts** introduced the most novel attack surface by adding code complexity.
- **Efficiency-focused prompts** sometimes removed defensive checks in the name of optimization.

Iterative Research is designed to reproduce and extend these experiments with configurable models, iteration counts, vulnerability targets, and prompting strategies.
