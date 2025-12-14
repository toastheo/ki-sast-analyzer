from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

class Severity(str, Enum):
  UNKNOWN = "UNKNOWN"
  LOW = "LOW"
  MEDIUM = "MEDIUM"
  HIGH = "HIGH"
  CRITICAL = "CRITICAL"

@dataclass
class Finding:
  """
  Normalized representation of a SAST finding.

  Deliberately chosen to be generic so that other tools
  besides Brakeman can be integrated in the future.
  """

  id: str

  # Origin
  tool: str
  rule_id: Optional[str]
  category: Optional[str]

  # Severity
  confidence_raw: Optional[str]
  confidence_normalized: Severity

  # Code context
  file_path: Optional[Path]
  line_start: Optional[int]
  line_end: Optional[int]
  message: str
  code_context: Optional[str]

  # docs & links
  link: Optional[str]

  # git context
  commit_sha: Optional[str] = None
  author: Optional[str] = None
  commit_date: Optional[str] = None

  def to_dict(self) -> dict:
    return {
      "id": self.id,
      "tool": self.tool,
      "rule_id": self.rule_id,
      "category": self.category,
      "confidence_raw": self.confidence_raw,
      "confidence_normalized": self.confidence_normalized.value,
      "file_path": str(self.file_path) if self.file_path is not None else None,
      "line_start": self.line_start,
      "line_end": self.line_end,
      "message": self.message,
      "code_context": self.code_context,
      "link": self.link,
      "commit_sha": self.commit_sha,
      "author": self.author,
      "commit_date": self.commit_date
    }
