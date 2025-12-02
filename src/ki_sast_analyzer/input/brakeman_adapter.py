from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..models import Finding, Severity

class BrakemanAdapter:
  """
  Converts a Brakeman JSON report into a list of findings.
  """

  TOOL_NAME = "brakeman"

  def from_report(self, raw_report: dict[str, Any]) -> list[Finding]:
    warnings: Iterable[dict[str, Any]] = raw_report.get("warnings", []) or []

    findings: list[Finding] = []
    for w in warnings:
      finding = self._warning_to_finding(w)
      findings.append(finding)

    return findings

  def _warning_to_finding(self, warning: dict[str, Any]) -> Finding:
    fingerprint = warning.get("fingerprint")
    warning_code = warning.get("warning_code")
    file_path = warning.get("file")
    line = warning.get("line")

    if fingerprint:
      finding_id = fingerprint
    else:
      finding_id = f"{self.TOOL_NAME}-{warning_code}-{file_path}-{line}"

    severity_norm = self._map_confidence_to_severity(
      str(warning.get("confidence", "")).lower()
    )

    return Finding(
      id=finding_id,
      tool=self.TOOL_NAME,
      rule_id=str(warning_code) if warning_code is not None else None,
      category=warning.get("warning_type"),
      severity_raw=str(warning.get("confidence")) if warning.get("confidence") is not None else None,
      severity_normalized=severity_norm,
      file_path=Path(file_path) if file_path else None,
      line_start=int(line) if line is not None else None,
      line_end=int(line) if line is not None else None,
      message=warning.get("message") or "",
      code_context=warning.get("code"),
      link=warning.get("link"),
    )

  @staticmethod
  def _map_confidence_to_severity(confidence: str) -> Severity:
    if confidence == "high":
      return Severity.HIGH
    if confidence == "medium":
      return Severity.MEDIUM
    if confidence == "weak":
      return Severity.LOW
    return Severity.UNKNOWN
