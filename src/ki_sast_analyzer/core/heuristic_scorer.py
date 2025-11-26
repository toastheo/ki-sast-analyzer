from __future__ import annotations

from dataclasses import dataclass

from ..models import Finding, Severity

@dataclass
class HeuristicScore:
  finding_id: str
  base_score: float

class HeuristicScorer:
  """
  Simple heuristic evaluation of Findings.
  """

  SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 4.0,
    Severity.LOW: 1.0,
    Severity.UNKNOWN: 0.0
  }

  def score(self, finding: Finding) -> HeuristicScore:
    weight = self.SEVERITY_WEIGHTS.get(finding.severity_normalized, 0.0)
    return HeuristicScore(
      finding_id=finding.id,
      base_score=weight,
    )