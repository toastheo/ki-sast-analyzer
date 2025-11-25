from ki_sast_analyzer.cli import parse_args

def test_parse_args_minimal():
  cfg = parse_args([
    "--brakeman-report", "brakeman.sarif.json"
  ])

  assert cfg.brakeman_report == "brakeman.sarif.json"
  assert cfg.git_root == "."
  assert cfg.output_markdown == "ki-sast-report.md"
