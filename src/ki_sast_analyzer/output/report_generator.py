from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..models import Finding
from ..core.ranking_engine import PrioritizedFinding

class ReportGenerator:
  """
  Creates artifacts from the prioritized findings.
  """

  @staticmethod
  def _md_escape(text: str) -> str:
    return(
      (text or "")
      .replace("\r\n", "\n").replace("\r", "\n")
      .replace("|", r"\|")
      .replace("\n", " ")
    )

  def write_markdown(
    self,
    prioritized: Iterable[PrioritizedFinding],
    output_path: str | Path,
  ) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append("# KI-SAST-Analyzer Report\n")
    lines.append("")
    lines.append(
      "| Score | Severity | Tool | File | Line | Rule | Category | AI Risk | AI FP | Message |"
    )
    lines.append(
      "|-------|----------|------|------|------|------|----------|---------|-------|---------|"
    )

    for pf in prioritized:
      f: Finding = pf.finding
      score = pf.final_score

      file_str = str(f.file_path) if f.file_path is not None else ""
      line_str = str(f.line_start) if f.line_start is not None else ""
      msg_short = self._md_escape(f.message or "")
      if len(msg_short) > 80:
        msg_short = msg_short[:77] + "..."

      ai_risk_str = (
        f"{pf.ai_risk_score:.1f}" if pf.ai_risk_score is not None else ""
      )
      ai_fp_str = (
        f"{pf.ai_fp_probability:.2f}" if pf.ai_fp_probability is not None else ""
      )

      lines.append(
        "| {score:.1f} | {sev} | {tool} | {file} | {line} | {rule} | {cat} | {ai_risk} | {ai_fp} | {msg} |".format(
          score=score,
          sev=self._md_escape(f.confidence_normalized.value),
          tool=self._md_escape(f.tool),
          file=self._md_escape(file_str),
          line=line_str,
          rule=self._md_escape(f.rule_id or ""),
          cat=self._md_escape(f.category or ""),
          ai_risk=ai_risk_str,
          ai_fp=ai_fp_str,
          msg=msg_short,
        )
      )

    lines.append("")
    lines.append("_Score = final combined score (0-10), "
                 "AI Risk = AI risk assessment (0-10), "
                 "AI FP = estimated false positive probability (0-1)._")
    lines.append("")

    content = "\n".join(lines) + "\n"
    p.write_text(content, encoding="utf-8")

  def write_json(
    self,
    prioritized: Iterable[PrioritizedFinding],
    output_path: str | Path,
  ) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    data = []
    for pf in prioritized:
      f = pf.finding
      entry = {
        "finding": f.to_dict(),
        "scores": {
          "heuristic": {
            "base_score": pf.base_score,
            "normalized_score": pf.normalized_score
          },
          "ai": {
            "risk_score": pf.ai_risk_score,
            "fp_probability": pf.ai_fp_probability,
            "severity_label": pf.ai_severity_label,
            "rationale": pf.ai_rationale,
          },
          "final_score": pf.final_score
        },
      }
      data.append(entry)

    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
