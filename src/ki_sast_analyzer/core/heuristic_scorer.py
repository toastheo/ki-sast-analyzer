from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from ..models import Finding, Severity
from ..input.brakeman_codes import BRAKEMAN_CODE_SYMBOLS

@dataclass
class HeuristicScore:
  finding_id: str
  base_score: float
  normalized_score: float

class HeuristicScorer:
  """
  Simple heuristic evaluation of Findings.
  """

  SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 8.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.UNKNOWN: 0.0,
  }

  MAX_TYPE_WEIGHT: float = 2.5
  MAX_RECENCY_BONUS: float = 1.0
  MAX_CONTEXT_WEIGHT: float = 1.0

  MAX_BASE_SCORE: float = (
    SEVERITY_WEIGHTS[Severity.CRITICAL]
    + MAX_TYPE_WEIGHT
    + MAX_RECENCY_BONUS
    + MAX_CONTEXT_WEIGHT
  )

  def __init__(self, now: Optional[datetime] = None) -> None:
    self._now = now or datetime.now(timezone.utc)

  def score(self, finding: Finding) -> HeuristicScore:
    severity_weight = self.SEVERITY_WEIGHTS.get(finding.severity_normalized, 0.0)
    type_weight = self._rule_id_weight(finding)
    recency_bonus = self._recency_bonus(finding)
    context_weight = self._context_weight(finding)

    base_score = severity_weight + type_weight + recency_bonus + context_weight
    normalized_score = self._normalize_base_score(base_score)

    return HeuristicScore(
      finding_id=finding.id,
      base_score=base_score,
      normalized_score=normalized_score,
    )

  def _normalize_base_score(self, base_score: float) -> float:
    """
    Map base_score to [0, 10]
    """
    if base_score <= 0.0:
      return 0.0

    if self.MAX_BASE_SCORE <= 0.0:
      return 0.0

    normalized = (base_score / self.MAX_BASE_SCORE) * 10.0
    return normalized

  # --- Rule / type weight ---

  def _rule_id_weight(self, finding: Finding) -> float:
    if not finding.rule_id:
      return 0.0

    try:
      code = int(finding.rule_id)
    except ValueError:
      return 0.0

    name = BRAKEMAN_CODE_SYMBOLS.get(code)
    if not name:
      return 0.0

    return self._symbol_weight(name)

  def _symbol_weight(self, name: str) -> float:
    """
    Weight based on the brakeman symbol names.
    """
    n = name.lower()

    # 1) really nasty stuff
    if (
      n.startswith("sql_injection")
      or n in {
        "command_injection",
        "code_eval",
        "dangerous_send",
        "unsafe_deserialize",
        "dynamic_render_path_rce",
        "unsafe_cookie_serialization",
        "unsafe_method_reflection",
        "erb_template_injection",
        "pathname_traversal",
      }
    ):
      return 2.5

    # 2) classic web vulnerabilities / important issues
    if (
      n.startswith("cross_site_scripting")
      or n.startswith("xss_")
      or n.startswith("csrf_")
      or n in {
        "open_redirect",
        "file_access",
        "unscoped_find",
        "dangerous_permit_key",
        "mass_assign_call",
        "mass_assign_without_protection",
        "mass_assign_permit_all",
        "session_key_manipulation",
        "ssl_verification_bypass",
        "force_ssl_disabled",
        "regex_dos",
        "reverse_tabnabbing",
        "ransack_search",
      }
    ):
      return 1.5

    # 3) CVEs in general
    if n.startswith("cve_"):
      return 1.5

    # 4) hardening / cryptography / eol / weaker but relevant topics
    if n in {
      "eol_rails",
      "eol_ruby",
      "pending_eol_rails",
      "pending_eol_ruby",
      "weak_hash_digest",
      "weak_hash_hmac",
      "small_rsa_key_size",
      "insecure_rsa_padding_mode",
      "missing_rsa_padding_mode",
      "validation_regex",
      "divide_by_zero",
      "secret_in_source",
      "http_cookies",
      "secure_cookies",
    }:
      return 1.0

    return 0.0

  # --- Recency / git metadata ---

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
      age_days = 0

    if age_days <= 7:
      return 1.0
    if age_days <= 30:
      return 0.5
    if age_days <= 180:
      return 0.25

    return 0.0

  # --- context: path / rails structure ---

  def _context_weight(self, finding: Finding) -> float:
    """
    Contextual weight based on file path (Rails conventions).
    """

    path = getattr(finding, "file_path", None)
    if not path:
      return 0.0

    if isinstance(path, Path):
      p = path.as_posix().lower()
    else:
      p = str(path).replace("\\", "/").lower()

    if "/test/" in p or "/spec/" in p or "/features/" in p:
      return -0.5

    if "/app/controllers/" in p:
      return 1.0

    if (
      "/app/models/" in p
      or "/app/views/" in p
      or "/app/channels/" in p
      or "/app/mailers" in p
    ):
      return 0.75

    if (
      "/app/jobs/" in p
      or "/app/services/" in p
      or "/lib/" in p
    ):
      return 0.5

    if (
      "/config/" in p
      or "/app/serializers/" in p
      or "/app/presenters/" in p
      or "/db/migrate/" in p
    ):
      return 0.25

    return 0.0
