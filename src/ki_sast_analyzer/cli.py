import argparse
from dataclasses import dataclass

from .input.sast_report_loader import SastReportLoader
from .input.brakeman_adapter import BrakemanAdapter

@dataclass
class CliConfig:
  brakeman_report: str
  git_root: str
  output_markdown: str | None
  output_json: str | None
  fail_on_policy_violation: bool

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="ki-sast-analyzer",
    description="AI-assisted evaluation of SAST reports (e.g., Brakeman) for CI pipelines",
  )

  parser.add_argument(
    "--brakeman-report",
    required=True,
    help="Path to the Brakeman SARIF report.",
  )
  parser.add_argument(
    "--git-root",
    default=".",
    help="Root-Verzeichnis des Git Repos (Standart: aktuelles Verzeichnis)",
  )
  parser.add_argument(
    "--output-markdown",
    default="ki-sast-report.md",
    help="Root directory of the Git repository (default: current directory)",
  )
  parser.add_argument(
    "--output-json",
    default=None,
    help="Optional path for a JSON report with all findings."
  )
  parser.add_argument(
    "--fail-on-policy-violation",
    action="store_true",
    help="Sets a non-zero exit code if the CI policy is violated."
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
    fail_on_policy_violation=args.fail_on_policy_violation
  )

def main(argv: list[str] | None = None) -> None:
  config = parse_args(argv)

  loader = SastReportLoader()
  adapter = BrakemanAdapter()

  raw_report = loader.load_json(config.brakeman_report)
  findings = adapter.from_report(raw_report)

  print("AI-SAST Analyzer CLI started.")
  print(f"  Brakeman-Report: {config.brakeman_report}")
  print(f"  Git-Root: {config.git_root}")
  print(f"  Findings: {len(findings)}")

  for f in findings[:5]:
    print(
      f"- [{f.severity_normalized.value}] {f.file_path}:{f.line_start} "
      f"rule={f.rule_id} category={f.category} msg={f.message[:80]!r}"
    )
