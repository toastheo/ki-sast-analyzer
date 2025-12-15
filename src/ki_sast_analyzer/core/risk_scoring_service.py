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
  Orchestrates heuristic evaluation and AI evaluation and combines both into a final score.
  """

  def __init__(
    self,
    heuristic_scorer: Optional[HeuristicScorer] = None,
    ai_scorer: Optional[AiScorer] = None,
    alpha: float = 0.7,
    beta: float = 0.3,
    gamma: float = 0.5,
  ) -> None:
    self._heuristic_scorer = heuristic_scorer or HeuristicScorer()
    self._ai_scorer = ai_scorer

    self._alpha = alpha
    self._beta = beta
    self._gamma = gamma


  def score_findings(self, findings: Iterable[Finding]) -> list[RiskScoringResult]:
    results: list[RiskScoringResult] = []

    for f in findings:
      heuristic = self._heuristic_scorer.score(f)
      ai_score: Optional[AiScore] = self._ai_scorer.score(f, heuristic) if self._ai_scorer else None
      final_score = self._combine_scores(heuristic, ai_score)

      final_sev = (
        ai_score.severity
        if (ai_score is not None and ai_score.severity is not None)
        else heuristic.severity
      )

      results.append(RiskScoringResult(
        finding=f,
        heuristic=heuristic,
        ai_score=ai_score,
        final_score=final_score,
        final_severity=final_sev,
      ))

    return results

  def _combine_scores(
    self,
    heuristic: HeuristicScore,
    ai_score: Optional[AiScore]
  ) -> float:
    """
    Combines heuristic score and (optional) ai score to a final value.
    """

    if ai_score is None:
      return self._clamp_0_10(heuristic.normalized_score)

    h = heuristic.normalized_score
    a_risk = ai_score.risk_score
    a_fp = ai_score.fp_probability

    raw = (
      self._alpha * h
      + self._beta * a_risk
      - self._gamma * (a_fp * 10.0)
    )

    return self._clamp_0_10(raw)

  @staticmethod
  def _clamp_0_10(value: float) -> float:
    if value < 0.0:
      return 0.0
    if value > 10.0:
      return 10.0
    return value