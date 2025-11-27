from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

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

  def __init__(self, now: Optional[datetime] = None) -> None:
    self._now = now or datetime.now(timezone.utc)

  def score(self, finding: Finding) -> HeuristicScore:
    severity_weight = self.SEVERITY_WEIGHTS.get(finding.severity_normalized, 0.0)
    recency_bonus = self._recency_bonus(finding)

    return HeuristicScore(
      finding_id=finding.id,
      base_score=severity_weight + recency_bonus,
    )

  def _recency_bonus(self, finding: Finding) -> float:
    """
    Bonus depending on the age of the commit.

    Idea: Recent Code is more "alive" and should be prioritized.
    """

    if not finding.commit_date:
      return 0.0

    try:
      dt = datetime.fromisoformat(finding.commit_date)
    except ValueError:
      return 0.0

    if dt.tzinfo is None:
      dt = dt.replace(tzinfo=timezone.utc)

    age_days = (self._now - dt).total_seconds() / 86400.0

    if age_days < 0:
      return 0.0
    if age_days <= 30:
      return 2.0
    if age_days <= 180:
      return 1.0
    return 0.0
