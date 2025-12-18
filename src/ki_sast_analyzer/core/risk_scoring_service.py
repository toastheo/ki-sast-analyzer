from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..models import Finding, Severity
from .heuristic_scorer import HeuristicScorer, HeuristicScore
from .ai_scorer import AiScorer, AiScore

@dataclass
class RiskScoringResult:
  """
  Complete evaluation result for a finding.
  """

  finding: Finding
  heuristic: HeuristicScore
  ai_score: Optional[AiScore]
  final_score: float
  final_severity: Severity

class RiskScoringService:
  """
  Orchestrates heuristic evaluation and AI evaluation.
  """

  def __init__(
    self,
    heuristic_scorer: Optional[HeuristicScorer] = None,
    ai_scorer: Optional[AiScorer] = None,
  ) -> None:
    self._heuristic_scorer = heuristic_scorer or HeuristicScorer()
    self._ai_scorer = ai_scorer

  def score_findings(self, findings: Iterable[Finding]) -> list[RiskScoringResult]:
    results: list[RiskScoringResult] = []

    for f in findings:
      heuristic = self._heuristic_scorer.score(f)
      ai_score: Optional[AiScore] = self._ai_scorer.score(f, heuristic) if self._ai_scorer else None

      if ai_score is not None:
        final_score = self._clamp_0_10(ai_score.risk_score)
        final_sev = ai_score.severity or heuristic.severity
      else:
        final_score = self._clamp_0_10(heuristic.normalized_score)
        final_sev = heuristic.severity

      results.append(RiskScoringResult(
        finding=f,
        heuristic=heuristic,
        ai_score=ai_score,
        final_score=final_score,
        final_severity=final_sev,
      ))

    return results

  @staticmethod
  def _clamp_0_10(value: float) -> float:
    if value < 0.0:
      return 0.0
    if value > 10.0:
      return 10.0
    return value
