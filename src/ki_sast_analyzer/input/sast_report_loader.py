from __future__ import annotations

import json
from pathlib import Path
from typing import Any

class SastReportLoader:
  """
  Loads a SAST report from disk.
  """

  def load_json(self, path: str | Path) -> dict[str, Any]:
    p = Path(path)

    if not p.is_file():
      raise FileNotFoundError(f"SAST-Report not found: {p}")

    with p.open("r", encoding="utf-8") as f:
      return json.load(f)
