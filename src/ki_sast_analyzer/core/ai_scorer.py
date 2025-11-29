from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ..models import Finding
from .heuristic_scorer import HeuristicScore

@dataclass
class AiScore:
  """
  Result of the AI evaluation for a single finding.
  """

  risk_score: float
  """
  Estimated risk of the finding.
  """

  fp_probability: float
  """
  Estimated false positive probability for a finding.
  """

  severity_label: Optional[str] = None
  """
  Optionally derived severity.
  """

  rationale: Optional[str] = None
  """
  Optional free text explaining why the AI made this decision.
  """

class AiScorer(ABC):
  """
  Abstract interface for all AI scorers.
  """

  @abstractmethod
  def score(self, finding: Finding, heuristic: HeuristicScore) -> AiScore:
    raise NotImplementedError

class DummyAiScorer(AiScorer):
  "Dummy Implementation without real AI."

  def score(self, finding: Finding, heuristic: HeuristicScore) -> AiScore:
    base = heuristic.normalized_score

    if base >= 7.0:
      fp_prob = 0.2
    elif base >= 4.0:
      fp_prob = 0.4
    else:
      fp_prob = 0.6

    return AiScore(
      risk_score=base,
      fp_probability=fp_prob,
      severity_label=finding.severity_normalized.value,
      rationale="Dummy AI: Derives the score directly from the heuristic model."
    )