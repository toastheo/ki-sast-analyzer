from ki_sast_analyzer.input.brakeman_adapter import BrakemanAdapter
from ki_sast_analyzer.models import Severity

def test_brakeman_adapter_creates_finding():
  raw_report = {
    "warnings": [
      {
        "warning_type": "SQL Injection",
        "warning_code": 1,
        "fingerprint": "abc123",
        "message": "Possible SQL injection",
        "file": "app/models/user.rb",
        "line": 42,
        "link": "https://example.com",
        "code": "User.where(\"id = #{params[:id]}\")",
        "confidence": "High",
      }
    ]
  }

  adapter = BrakemanAdapter()
  findings = adapter.from_report(raw_report)

  assert len(findings) == 1
  f = findings[0]

  assert f.id == "abc123"
  assert f.tool == "brakeman"
  assert f.rule_id == "1"
  assert f.category == "SQL Injection"
  assert f.severity_raw == "High"
  assert f.severity_normalized == Severity.HIGH
  assert str(f.file_path) == "app/models/user.rb"
  assert f.line_start == 42
  assert f.message == "Possible SQL injection"
  assert f.code_context is not None and f.code_context.startswith("User.where")
  assert f.link == "https://example.com"
