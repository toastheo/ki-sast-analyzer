from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models import Finding, Severity, Confidence
from ..input.brakeman_codes import BRAKEMAN_CODE_SYMBOLS

@dataclass
class HeuristicScore:
  finding_id: str
  severity: Severity
  base_score: float          # unclamped, for debugging
  normalized_score: float    # clamped to [0, 10]

class HeuristicScorer:
  """
  Deterministic baseline scorer.
  Produces an interpretable 0..10 risk estimate (fallback + AI prior).
  """

  # Severity as an "anchor" on the same 0..10 scale as the AI score.
  SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.UNKNOWN: 0.5,
  }

  # Small adjustment based on tool confidence (never dominates severity).
  CONFIDENCE_ADJUST: dict[Confidence, float] = {
    Confidence.HIGH: 0.25,
    Confidence.MEDIUM: 0.0,
    Confidence.LOW: -0.25,
    Confidence.UNKNOWN: 0.0,
  }

  # Bounded bonuses
  MAX_RULE_BONUS: float = 1.0
  MAX_RECENCY_BONUS: float = 0.5
  MAX_CONTEXT_BONUS: float = 0.5

  def __init__(self, now: Optional[datetime] = None) -> None:
    self._now = now or datetime.now(timezone.utc)

  def score(self, finding: Finding) -> HeuristicScore:
    sev, rule_bonus = self._severity_and_rule_bonus(finding)

    severity_base = self.SEVERITY_WEIGHTS.get(sev, self.SEVERITY_WEIGHTS[Severity.UNKNOWN])
    recency_bonus = self._recency_bonus(finding)
    context_bonus = self._context_bonus(finding)
    confidence_adj = self.CONFIDENCE_ADJUST.get(finding.confidence, 0.0)

    base_score = severity_base + rule_bonus + recency_bonus + context_bonus + confidence_adj
    normalized_score = self._clamp_0_10(base_score)

    return HeuristicScore(
      finding_id=finding.id,
      severity=sev,
      base_score=base_score,
      normalized_score=normalized_score,
    )

  @staticmethod
  def _clamp_0_10(x: float) -> float:
    if x < 0.0:
      return 0.0
    if x > 10.0:
      return 10.0
    return x

  # --- Severity + Rule bonus (no double counting) ---

  def _severity_and_rule_bonus(self, finding: Finding) -> tuple[Severity, float]:
    """
    Determine severity primarily from known rule symbol (Brakeman),
    otherwise fall back to keyword heuristics over category/message.
    Returns (severity, rule_bonus).
    """

    symbol = self._brakeman_symbol(finding)
    if symbol:
      sev, bonus = self._classify_symbol(symbol)
      return sev, bonus

    sev = self._keyword_severity(finding.category, finding.message)
    return sev, 0.0

  def _brakeman_symbol(self, finding: Finding) -> str | None:
    if not finding.rule_id:
      return None
    try:
      code = int(finding.rule_id)
    except ValueError:
      return None
    return BRAKEMAN_CODE_SYMBOLS.get(code)

  def _classify_symbol(self, name: str) -> tuple[Severity, float]:
    """
    Map known symbol families to (Severity, rule_bonus).
    rule_bonus is ONLY used to differentiate within the same general band.
    """
    n = name.lower()

    # 1) really nasty stuff (RCE/SQLi/Deserialization/etc.)
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
      return Severity.CRITICAL, 1.0

    # 2) classic web vulns / important issues
    if (
      n.startswith("cross_site_scripting")
      or n.startswith("xss_")
      or n.startswith("csrf_")
      or n.startswith("cve_")
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
      return Severity.HIGH, 0.5

    # 3) hardening / crypto / eol / weaker but relevant
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
      return Severity.MEDIUM, 0.25

    return Severity.LOW, 0.0

  @staticmethod
  def _keyword_severity(category: str | None, message: str) -> Severity:
    text = f"{category or ''} {message or ''}".lower()

    # crude but robust tool-agnostic fallback
    if ("sql" in text and "inject" in text) or "command injection" in text or "remote code" in text:
      return Severity.CRITICAL

    if "xss" in text or "cross site scripting" in text or "csrf" in text:
      return Severity.HIGH

    if "open redirect" in text or "redirect" in text or "session" in text:
      return Severity.MEDIUM

    if "secret" in text or "token" in text or "password" in text or "weak hash" in text:
      return Severity.MEDIUM

    # If we have literally no signal at all:
    if not category and not message:
      return Severity.UNKNOWN

    return Severity.LOW

  # --- Recency (bounded small bonus) ---

  def _recency_bonus(self, finding: Finding) -> float:
    if not finding.commit_date:
      return 0.0

    raw = finding.commit_date.strip()

    if raw.endswith("Z"):
      raw = raw[:-1] + "+00:00"

    try:
      dt = datetime.fromisoformat(raw)
    except ValueError:
      return 0.0

    if dt.tzinfo is None:
      dt = dt.replace(tzinfo=timezone.utc)

    age_days = (self._now - dt).total_seconds() / 86400.0
    if age_days < 0:
      age_days = 0.0

    if age_days <= 7:
      return 0.5
    if age_days <= 30:
      return 0.25
    if age_days <= 180:
      return 0.1
    return 0.0

  # --- Context (bounded small bonus/malus) ---

  def _context_bonus(self, finding: Finding) -> float:
    path = getattr(finding, "file_path", None)
    if not path:
      return 0.0

    if isinstance(path, Path):
      p = path.as_posix().lower()
    else:
      p = str(path).replace("\\", "/").lower()

    # de-prioritize non-prod / external code
    if "/test/" in p or "/spec/" in p or "/features/" in p:
      return -0.5
    if "/vendor/" in p:
      return -0.25

    # rough attack surface heuristic (Rails-ish but not insane)
    if "/app/controllers/" in p:
      return 0.5

    if any(x in p for x in ["/app/models/", "/app/views/", "/app/channels/", "/app/mailers/"]):
      return 0.25

    if any(x in p for x in ["/app/jobs/", "/app/services/", "/lib/"]):
      return 0.15

    # config/migrations are often lower “direct exploitability”
    if any(x in p for x in ["/config/", "/db/migrate/"]):
      return 0.05

    return 0.0
