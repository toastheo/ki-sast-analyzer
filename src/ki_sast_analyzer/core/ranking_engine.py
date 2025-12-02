from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import Finding
from .risk_scoring_service import RiskScoringService, RiskScoringResult

@dataclass
class PrioritizedFinding:
  finding: Finding
  base_score: float
  normalized_score: float

  ai_risk_score: float | None = None
  ai_fp_probability: float | None = None
  ai_severity_label: str | None = None
  ai_rationale: str | None = None

  final_score: float | None = None

class RankingEngine:
  """
  Combines Heuristic (and later ai) and sorts Findings by relevance.
  """

  def __init__(self, risk_scorer: Optional[RiskScoringService] = None) -> None:
    self._risk_scorer = risk_scorer or RiskScoringService()

  def rank(self, findings: list[Finding]) -> list[PrioritizedFinding]:
    results: list[RiskScoringResult] = self._risk_scorer.score_findings(findings)
    prioritized: list[PrioritizedFinding] = []

    for r in results:
      heuristic = r.heuristic
      ai_score = r.ai_score

      pf = PrioritizedFinding(
        finding=r.finding,
        base_score=heuristic.base_score,
        normalized_score=heuristic.normalized_score,
        ai_risk_score=ai_score.risk_score if ai_score is not None else None,
        ai_fp_probability=ai_score.fp_probability if ai_score is not None else None,
        ai_severity_label=ai_score.severity_label if ai_score is not None else None,
        ai_rationale=ai_score.rationale if ai_score is not None else None,
        final_score=r.final_score,
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
