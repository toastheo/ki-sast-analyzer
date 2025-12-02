# KI-Sast-Analyzer

**KI-SAST-Analyzer** is a modular command-line tool that enriches traditional static analysis (SAST) results with
heuristic and AI-based risk evaluation.
It is designed for CI pipelines and currently supports **Brakeman** reports in JSON/SARIF format.

The tool normalizes findings from SAST tools, enriches them with Git metadata, applies a deterministic
heuristic model and optionally refines the evaluation using an LLM (OpenAI). Finally, it produces prioritized
markdown and JSON reports suitable for developer workflows and automated policy checks.

## Features

- 🧩 **Unified SAST finding model** (tool-agnostic design)
- 🧠 **Hybrid risk scoring**
  - Deterministic heuristic scoring
  - Optional AI-based refinement (risk score, false-positive probability, severity label, rationale)
- 🕵️ **Git context integration** (git blame per finding)
- 📊 **Prioritized markdown and JSON reports**
- 🔧 **CI-friendly exit policies** (--fail-on-policy-violation)
- 🚫 **Offline / deterministic mode** (--ai-disabled)
- 🧱 **Extensible architecture** (additional SAST tools can be integrated easily)

## Installation

Clone the repository and install the project using Python 3.11+:

```sh
pip install .
```

Or run directly from the source tree:

```sh
python -m ki_sast_analyzer --help
```

## Usage

Basic example:

```sh
ki-sast-analyzer \
  --brakeman-report brakeman-output.json \
  --output-markdown report.md
```

With optional JSON output:

```sh
ki-sast-analyzer \
  --brakeman-report brakeman-output.json \
  --output-json report.json \
  --output-markdown report.md
```

**Disable AI scoring (heuristic-only mode)**

```sh
ki-sast-analyzer \
  --brakeman-report brakeman-output.json \
  --ai-disabled
```

**Enforce CI policy**

Returns a non-zero exit code if highly critical findings are present (default threshold: >= 8.0)

```sh
ki-sast-analyzer \
  --brakeman-report brakeman-output.json \
  --fail-on-policy-violation
```

## Output

### Markdown report

A sortable, human-friendly table summarizing:

- Combined final score (0-10)
- Normalized severity
- Rule ID & category
- File path & line
- AI risk score (0-10)
- AI false-positive probability (0-1)
- Short finding message

### JSON report

A structured representation including:

- Raw finding data
- Heuristic score breakdown
- AI fields (risk, FP probability, rationale)
- Final combined score

## Architecutre Overview

The tool is structured into modular components:

```
input/    -> report loaders, SAST adapters, git blame integration
core/     -> heuristic model, AI scorer, risk scoring, ranking engine
output/   -> markdown & JSON report generation
models.py -> unified Finding model
cli.py    -> command-line interface
```

This separation allows replacing or extending individual components without affecting the entire system.
