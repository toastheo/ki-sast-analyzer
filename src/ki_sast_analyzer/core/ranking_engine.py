from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..models import Finding
from .heuristic_scorer import HeuristicScorer, HeuristicScore

@dataclass
class PrioritizedFinding:
  finding: Finding
  base_score: float
  normalized_score: float
  # TODO: placeholder for later ai-field
  ai_risk_score: float | None = None
  ai_fp_probability: float | None = None
  final_score: float | None = None

class RankingEngine:
  """
  Combines Heuristic (and later ai) and sorts Findings by relevance.
  """

  def __init__(self, heuristic_scorer: HeuristicScorer | None = None) -> None:
    self._heuristic_scorer = heuristic_scorer or HeuristicScorer()

  def rank(self, findings: list[Finding]) -> List[PrioritizedFinding]:
    prioritized: List[PrioritizedFinding] = []

    for f in findings:
      h_score: HeuristicScore = self._heuristic_scorer.score(f)

      # TODO: Consider AI results
      pf = PrioritizedFinding(
        finding=f,
        base_score=h_score.base_score,
        normalized_score=h_score.normalized_score,
        final_score=h_score.normalized_score,
      )
      prioritized.append(pf)

    prioritized.sort(
      key=lambda pf: (
        -(pf.final_score or 0.0),
        pf.finding.severity_normalized.value,
        str(pf.finding.file_path or ""),
        pf.finding.line_start or 0,
      )
    )

    return prioritized
