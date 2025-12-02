from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import json
import logging
import os

import openai
from openai import OpenAI

from ..models import Finding
from .heuristic_scorer import HeuristicScore

logger = logging.getLogger(__name__)

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

class OpenAiScorer(AiScorer):
  """
  AiScorer implementation that calls the OpenAI API.
  """

  def __init__(
    self,
    model: str | None = None,
    temperature: float = 0.1,
    max_code_chars: int = 2000,
  ) -> None:
    self._client = OpenAI()
    self._model = (
      model
      or os.environ.get("KISAST_OPENAI_MODEL")
      or "gpt-5-nano"
    )
    self._temperature = temperature
    self._max_code_chars = max_code_chars

  def score(self, finding: Finding, heuristic: HeuristicScore) -> AiScore:
    """
    Calls the LLM and maps the result to AiScore.
    """
    try:
      payload = self._build_prompt_payload(finding, heuristic)
      raw_json = self._call_model(payload)
      data = json.loads(raw_json)

      risk_score = float(data.get("risk_score", heuristic.normalized_score))
      fp_prob = float(data.get("fp_probability", 0.5))
      severity_label = data.get("severity_label") or finding.severity_normalized.value
      rationale = data.get("rationale") or "No rationale provided by AI."

      risk_score = max(0.0, min(10.0, risk_score))
      fp_prob = max(0.0, min(1.0, fp_prob))

      return AiScore(
        risk_score=risk_score,
        fp_probability=fp_prob,
        severity_label=severity_label,
        rationale=rationale,
      )

    except(json.JSONDecodeError, KeyError, ValueError) as e:
      logger.warning("Failed to parse OpenAI, response, falling back to heuristic: %s", e)
    except openai.APIError as e:
      logger.warning("OpenAI API error, falling back to heuristic: %s", e)
    except Exception as e:
      logger.warning("Unexpected error in OpenAiScorer, falling back to heuristic: %s", e)

    return AiScore(
      risk_score=heuristic.normalized_score,
      fp_probability=0.5,
      severity_label=finding.severity_normalized.value,
      rationale="Fallback: Heuristic score only (OpenAI call failed).",
    )

  # --- Helper Methods ---

  def _truncate_code(self, code: str | None) -> str:
    if not code:
      return ""
    code = code.replace("\r\n", "\n")
    if len(code) <= self._max_code_chars:
      return code
    return code[: self._max_code_chars] + "\n# ... truncated ..."

  def _build_prompt_payload(self, finding: Finding, heuristic: HeuristicScore) -> str:
    """
    Builds the text for the user message.
    """
    code_snippet = self._truncate_code(finding.code_context)

    parts: list[str] = []

    parts.append("You are an application security expert used in a CI pipeline.")
    parts.append("You get a single SAST finding and a heuristic risk estimate.")
    parts.append("")
    parts.append("Your tasks:")
    parts.append("1. Estimate a refined risk_score between 0 and 10.")
    parts.append("   - 0 = harmless / pure false positive.")
    parts.append("   - 10 = critical vulnerability with high impact (e.g. RCE, SQLi on sensitive data).")
    parts.append("2. Estimate fp_probability between 0 and 1 (likelihood that the finding is a false positive).")
    parts.append("3. Provide severity_label as one of: LOW, MEDIUM, HIGH, CRITICAL.")
    parts.append("4. Provide a short rationale (max. 4 sentences).")
    parts.append("")
    parts.append("Always answer as a single JSON object with exactly these keys:")
    parts.append('{')
    parts.append('  "risk_score": <float between 0 and 10>,')
    parts.append('  "fp_probability": <float between 0 and 1>,')
    parts.append('  "severity_label": "<LOW|MEDIUM|HIGH|CRITICAL>",')
    parts.append('  "rationale": "<short explanation>"')
    parts.append('}')
    parts.append("")
    parts.append("Context of the finding:")
    parts.append(f"- Tool: {finding.tool}")
    parts.append(f"- Rule ID: {finding.rule_id}")
    parts.append(f"- Category: {finding.category}")
    parts.append(f"- Tool severity_raw / confidence: {finding.severity_raw}")
    parts.append(f"- Normalized severity: {finding.severity_normalized.value}")
    parts.append(f"- Heuristic normalized_score (0-10): {heuristic.normalized_score:.2f}")
    parts.append(f"- File path: {finding.file_path}")
    parts.append(f"- Line start: {finding.line_start}")
    parts.append(f"- Commit SHA: {finding.commit_sha}")
    parts.append(f"- Author: {finding.author}")
    parts.append(f"- Commit date (ISO 8601): {finding.commit_date}")
    parts.append("")
    parts.append("Tool message:")
    parts.append(f"{finding.message}")
    parts.append("")
    parts.append("Code snippet:")
    parts.append("```")
    parts.append(code_snippet or "<no code snippet available>")
    parts.append("```")

    return "\n".join(parts)

  def _call_model(self, user_payload: str) -> str:
    """
    Calls the OpenAI model and returns the JSON string.
    """
    completion = self._client.chat.completions.create(
      model=self._model,
      temperature=self._temperature,
      response_format={"type": "json_object"},
      messages=[
        {
          "role": "system",
          "content": (
            "You are an application security expert helping to prioritize "
            "static analysis findings in a CI pipeline."
          ),
        },
        {
          "role": "user",
          "content": user_payload,
        },
      ],
    )

    content = completion.choices[0].message.content
    if content is None:
      raise ValueError("OpenAI response has no content")

    return content