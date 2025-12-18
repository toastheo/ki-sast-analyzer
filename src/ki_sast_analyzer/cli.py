import argparse
import sys
from dataclasses import dataclass

from .input.sast_report_loader import SastReportLoader
from .input.brakeman_adapter import BrakemanAdapter
from .input.git_context_fetcher import GitContextFetcher
from .core.ranking_engine import RankingEngine, PrioritizedFinding
from .core.ai_scorer import OpenAiScorer
from .core.risk_scoring_service import RiskScoringService
from .output.report_generator import ReportGenerator

@dataclass
class CliConfig:
  brakeman_report: str
  git_root: str
  output_markdown: str | None
  output_json: str | None
  fail_on_policy_violation: bool
  ai_disabled: bool
  context_files: list[str]

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="ki-sast-analyzer",
    description="AI-assisted evaluation of SAST reports (e.g., Brakeman) for CI pipelines",
  )

  parser.add_argument(
    "--brakeman-report",
    required=True,
    help="Path to the Brakeman JSON report.",
  )
  parser.add_argument(
    "--git-root",
    default=".",
    help="Root directory of the Git repository (default: current directory)",
  )
  parser.add_argument(
    "--output-markdown",
    default="ki-sast-report.md",
    help="Path for a markdown report with all findings (default: ki-sast-report.md)",
  )
  parser.add_argument(
    "--output-json",
    default=None,
    help="Optional path for a JSON report with all findings.",
  )
  parser.add_argument(
    "--fail-on-policy-violation",
    action="store_true",
    help="Sets a non-zero exit code if the CI policy is violated.",
  )
  parser.add_argument(
    "--ai-disabled",
    action="store_true",
    help="Disable AI scoring completely and use only heuristic scores.",
  )
  parser.add_argument(
    "--context-file",
    action="append",
    default=[],
    help=(
      "Additional project files to include as AI context. "
      "Can be specified multiple times."
    ),
  )

  return parser

def parse_args(argv: list[str] | None = None) -> CliConfig:
  parser = build_parser()
  args = parser.parse_args(argv)

  return CliConfig(
    brakeman_report=args.brakeman_report,
    git_root=args.git_root,
    output_markdown=args.output_markdown,
    output_json=args.output_json,
    fail_on_policy_violation=args.fail_on_policy_violation,
    ai_disabled=args.ai_disabled,
    context_files=args.context_file,
  )

POLICY_THRESHOLD = 8.0

def _check_policy(prioritized: list[PrioritizedFinding]) -> bool:
  """
  Returns True if the CI policy is violated.
  """
  return any(pf.final_score >= POLICY_THRESHOLD for pf in prioritized)

def main(argv: list[str] | None = None) -> None:
  config = parse_args(argv)

  loader = SastReportLoader()
  adapter = BrakemanAdapter()
  git_ctx = GitContextFetcher(config.git_root)

  if config.ai_disabled:
    ai_scorer = None
  else:
    ai_scorer = OpenAiScorer(
      project_root=config.git_root,
      context_files=config.context_files,
    )

  risk_scorer = RiskScoringService(
    ai_scorer=ai_scorer
  )

  ranking = RankingEngine(risk_scorer)
  reporter = ReportGenerator()

  try:
    raw_report = loader.load_json(config.brakeman_report)
  except FileNotFoundError as e:
    print(f"Error: {e}", file=sys.stderr)
    raise SystemExit(2)
  except OSError as e:
    print(f"Error reading SAST report: {e}", file=sys.stderr)
    raise SystemExit(3)

  findings = adapter.from_report(raw_report)

  git_ctx.enrich_findings(findings)

  print("AI-SAST Analyzer CLI started.")
  if not config.ai_disabled:
    print("Running AI ...")
  prioritized = ranking.rank(findings)

  if config.output_markdown:
    reporter.write_markdown(prioritized, config.output_markdown)

  if config.output_json:
    reporter.write_json(prioritized, config.output_json)

  print(f"  Brakeman-Report: {config.brakeman_report}")
  print(f"  Findings: {len(findings)}")
  print(f"  MD-Report: {config.output_markdown}")
  if config.output_json:
    print(f"  JSON-Report: {config.output_json}")

  if config.ai_disabled:
    print("  AI scoring: DISABLED (heuristic only)")
  else:
    print("  AI scoring: ENABLED")

  if config.fail_on_policy_violation and _check_policy(prioritized):
    print(f"CI policy violated (score >= {POLICY_THRESHOLD}).", file=sys.stderr)
    raise SystemExit(1)
