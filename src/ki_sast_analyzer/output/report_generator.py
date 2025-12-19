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
      "| Risk | FP Prob | Severity | Confidence | Tool | File | Line | Rule | Category | Heuristic | Message |"
    )
    lines.append(
      "|------|---------|----------|------------|------|------|------|------|----------|-----------|---------|"
    )

    for pf in prioritized:
      f: Finding = pf.finding

      file_str = str(f.file_path) if f.file_path is not None else ""
      line_str = str(f.line_start) if f.line_start is not None else ""
      msg_short = self._md_escape(f.message or "")
      if len(msg_short) > 80:
        msg_short = msg_short[:77] + "..."

      risk = pf.final_score
      fp_str = f"{pf.ai_fp_probability:.2f}" if pf.ai_fp_probability is not None else ""
      heur_str = f"{pf.normalized_score:.1f}"

      lines.append(
        "| {risk:.1f} | {fp} | {sev} | {conf} | {tool} | {file} | {line} | {rule} | {cat} | {heur} | {msg} |".format(
          risk=risk,
          fp=fp_str,
          sev=self._md_escape(pf.final_severity.value),
          conf=self._md_escape(f.confidence.value),
          tool=self._md_escape(f.tool),
          file=self._md_escape(file_str),
          line=line_str,
          rule=self._md_escape(f.rule_id or ""),
          cat=self._md_escape(f.category or ""),
          heur=heur_str,
          msg=msg_short,
        )
      )

    lines.append("")
    lines.append(
      "_Risk = AI risk_score (0-10) if available, otherwise heuristic fallback. "
      "FP Prob = AI false-positive probability (0-1). "
      "Heuristic is informational / fallback only._"
    )
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
            "severity": pf.ai_severity.value if pf.ai_severity else None,
            "rationale": pf.ai_rationale,
          },
          "final": {
            "risk_score": pf.final_score,
            "fp_probability": pf.ai_fp_probability,
            "severity": pf.final_severity.value,
            "basis": "ai" if pf.ai_risk_score is not None else "heuristic_fallback",
          },
        },
      }
      data.append(entry)

    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
