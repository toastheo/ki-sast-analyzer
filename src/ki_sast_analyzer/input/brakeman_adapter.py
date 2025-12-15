from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..models import Finding, Confidence

class BrakemanAdapter:
  """
  Converts a Brakeman JSON report into a list of findings.
  """

  TOOL_NAME = "brakeman"

  def from_report(self, raw_report: dict[str, Any]) -> list[Finding]:
    warnings: Iterable[dict[str, Any]] = raw_report.get("warnings", []) or []
    return [self._warning_to_finding(w) for w in warnings]

  def _warning_to_finding(self, warning: dict[str, Any]) -> Finding:
    fingerprint = warning.get("fingerprint")
    warning_code = warning.get("warning_code")
    file_path = warning.get("file")
    line = warning.get("line")

    finding_id = fingerprint or f"{self.TOOL_NAME}-{warning_code}-{file_path}-{line}"

    conf = self._map_confidence(str(warning.get("confidence", "")).lower())

    return Finding(
      id=finding_id,
      tool=self.TOOL_NAME,
      rule_id=str(warning_code) if warning_code is not None else None,
      category=warning.get("warning_type"),
      confidence_raw=str(warning.get("confidence")) if warning.get("confidence") is not None else None,
      confidence=conf,
      file_path=Path(file_path) if file_path else None,
      line_start=int(line) if line is not None else None,
      line_end=int(line) if line is not None else None,
      message=warning.get("message") or "",
      code_context=warning.get("code"),
      link=warning.get("link"),
    )

  @staticmethod
  def _map_confidence(confidence: str) -> Confidence:
    if confidence == "high":
      return Confidence.HIGH
    if confidence == "medium":
      return Confidence.MEDIUM
    if confidence == "weak":
      return Confidence.LOW
    return Confidence.UNKNOWN
