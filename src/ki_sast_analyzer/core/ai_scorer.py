from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable

import json
import logging
import os

from openai import OpenAI, APIError

from ..models import Finding, Severity
from .heuristic_scorer import HeuristicScore

logger = logging.getLogger(__name__)

@dataclass
class AiContextFile:
  path: Path
  content: str

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

  severity: Optional[Severity] = None
  """
  Optionally derived severity.
  """

  rationale: Optional[str] = None
  """
  Optional free text explaining why the AI made this decision.
  """

def _parse_severity(label: str | None) -> Optional[Severity]:
  if not label:
    return None
  try:
    return Severity[label.strip().upper()]
  except KeyError:
    return None

class AiScorer(ABC):
  """
  Abstract interface for all AI scorers.
  """

  @abstractmethod
  def score(self, finding: Finding, heuristic: HeuristicScore) -> AiScore:
    raise NotImplementedError

class DummyAiScorer(AiScorer):
  """
  Dummy Implementation without real AI.
  """

  def score(self, finding: Finding, heuristic: HeuristicScore) -> AiScore:
    base = heuristic.normalized_score
    fp_prob = 0.2 if base >= 7.0 else (0.4 if base >= 4.0 else 0.6)

    return AiScore(
      risk_score=base,
      fp_probability=fp_prob,
      severity=heuristic.severity,
      rationale="Dummy AI: Derives the score directly from the heuristic model."
    )

class OpenAiScorer(AiScorer):
  """
  AiScorer implementation that calls the OpenAI API.
  """

  def __init__(
    self,
    model: str | None = None,
    max_code_chars: int = 2000,
    project_root: str | Path | None = None,
    context_files: Optional[Iterable[str]] = None,
    max_context_chars_per_file: int = 2000,
  ) -> None:
    self._client = OpenAI()
    self._model = (
      model
      or os.environ.get("KISAST_OPENAI_MODEL")
      or "gpt-5-mini"
    )
    self._max_code_chars = max_code_chars

    self._project_root = Path(project_root) if project_root is not None else Path(".")
    self._max_context_chars_per_file = max_context_chars_per_file
    self._context_files: list[AiContextFile] = []

    if context_files:
      self._load_context_files(context_files)

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

      sev = _parse_severity(data.get("severity_label")) or heuristic.severity
      rationale = data.get("rationale") or "No rationale provided by AI."

      risk_score = max(0.0, min(10.0, risk_score))
      fp_prob = max(0.0, min(1.0, fp_prob))

      return AiScore(
        risk_score=risk_score,
        fp_probability=fp_prob,
        severity=sev,
        rationale=rationale,
      )
    except Exception as e:
      logger.warning("OpenAiScorer failed, falling back: %s", e)

    return AiScore(
      risk_score=heuristic.normalized_score,
      fp_probability=0.5,
      severity=heuristic.severity,
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
    parts.append(f"- Tool confidence: {finding.confidence_raw}")
    parts.append(f"- Normalized confidence: {finding.confidence.value}")
    parts.append(f"- Heuristic severity: {heuristic.severity.value}")
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

    context_section = self._build_context_files_section()
    if context_section:
      parts.append(context_section)

    return "\n".join(parts)

  def _call_model(self, user_payload: str) -> str:
    """
    Calls the OpenAI model and returns the JSON string.
    """
    completion = self._client.chat.completions.create(
      model=self._model,
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

  def _load_context_files(self, files: Iterable[str]) -> None:
    for f in files:
      p = (self._project_root / f).resolve()
      try:
        content = p.read_text(encoding="utf-8", errors="replace")
      except OSError:
        logger.warning("Could not read context file '%s'", p)
        continue

      if len(content) > self._max_context_chars_per_file:
        content = (
          content[: self._max_context_chars_per_file]
          + "\n# ... truncated ..."
        )

      self._context_files.append(AiContextFile(path=p, content=content))

  def _build_context_files_section(self) -> str:
    if not self._context_files:
      return ""

    parts: list[str] = []
    parts.append("")
    parts.append("Additional project context files (may be truncated):")

    for cf in self._context_files:
      parts.append("")
      parts.append(f"--- File: {cf.path} ---")
      parts.append("```")
      parts.append(cf.content)
      parts.append("```")

    return "\n".join(parts)
