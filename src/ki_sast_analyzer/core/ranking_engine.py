from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..models import Finding, Severity
from .risk_scoring_service import RiskScoringService
from .heuristic_scorer import HeuristicScorer

@dataclass
class PrioritizedFinding:
  finding: Finding
  base_score: float
  normalized_score: float
  final_score: float
  final_severity: Severity

  ai_risk_score: float | None = None
  ai_fp_probability: float | None = None
  ai_severity: Severity | None = None
  ai_rationale: str | None = None

class RankingEngine:
  """
  Combines Heuristic (and later ai) and sorts Findings by relevance.
  """

  def __init__(self, risk_scorer: Optional[RiskScoringService] = None) -> None:
    self._risk_scorer = risk_scorer or RiskScoringService()

  def _severity_weight(self, pf: PrioritizedFinding) -> float:
    return HeuristicScorer.SEVERITY_WEIGHTS.get(pf.final_severity, 0.0)

  def rank(self, findings: list[Finding]) -> list[PrioritizedFinding]:
    results = self._risk_scorer.score_findings(findings)
    prioritized: list[PrioritizedFinding] = []

    for r in results:
      ai = r.ai_score
      pf = PrioritizedFinding(
        finding=r.finding,
        base_score=r.heuristic.base_score,
        normalized_score=r.heuristic.normalized_score,
        final_score=r.final_score,
        final_severity=r.final_severity,
        ai_risk_score=ai.risk_score if ai else None,
        ai_fp_probability=ai.fp_probability if ai else None,
        ai_severity=ai.severity if ai else None,
        ai_rationale=ai.rationale if ai else None,
      )
      prioritized.append(pf)

    prioritized.sort(
      key=lambda pf: (
        -pf.final_score,
        -self._severity_weight(pf),
        str(pf.finding.file_path or ""),
        pf.finding.line_start or 0,
      )
    )
    return prioritized
