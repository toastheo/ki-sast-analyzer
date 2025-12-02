from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..models import Finding

@dataclass
class GitContext:
  commit_sha: str
  author_name: Optional[str]
  author_email: Optional[str]
  author_time: Optional[datetime]

class GitContextFetcher:
  """
  Gets the git context of a file/line via `git blame`.
  """

  def __init__(self, git_root: str | Path = ".") -> None:
    self.git_root = Path(git_root)

  def _run_git(self, args: list[str]) -> str | None:
    try:
      result = subprocess.run(
        ["git", *args],
        cwd=self.git_root,
        capture_output=True,
        text=True,
        check=False,
      )
    except FileNotFoundError:
      # git not installed or not found
      return None

    if result.returncode != 0:
      return None

    return result.stdout

  def get_context_for_line(self, file_path: Path, line: int) -> Optional[GitContext]:
    """
    Extract author/commit from git blame output.
    """
    rel_path = file_path
    try:
      rel_path = file_path.relative_to(self.git_root)
    except ValueError:
      # file_path probably is already relative or somewhere else - we just try it
      pass

    output = self._run_git(
      ["blame", "--line-porcelain", "-L", f"{line},{line}", "--", str(rel_path)]
    )
    if output is None:
      return None

    commit_sha: Optional[str] = None
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    author_time: Optional[datetime] = None

    for i, raw_line in enumerate(output.splitlines()):
      line_str = raw_line.strip()

      if i == 0:
        parts = line_str.split()
        if parts:
          commit_sha = parts[0]
        continue

      if line_str.startswith("author "):
        author_name = line_str[len("author ") :]
      elif line_str.startswith("author-mail "):
        author_email = line_str[len("author-mail ") :].strip("<>")
      elif line_str.startswith("author-time "):
        ts_str = line_str[len("author-time ") :]
        try:
          ts = int(ts_str)
          author_time = datetime.fromtimestamp(ts, tz=timezone.utc)
        except ValueError:
          pass

    if not commit_sha:
      return None

    return GitContext(
      commit_sha=commit_sha,
      author_name=author_name,
      author_email=author_email,
      author_time=author_time
    )

  def enrich_findings(self, findings: list[Finding]) -> None:
    """
    Mutates the findings in-place and adds commit_sha, author and commit_date
    """
    for f in findings:
      if f.file_path is None or f.line_start is None:
        continue

      ctx = self.get_context_for_line(f.file_path, f.line_start)
      if ctx is None:
        continue

      f.commit_sha = ctx.commit_sha
      if ctx.author_name and ctx.author_email:
        f.author = f"{ctx.author_name} <{ctx.author_email}>"
      elif ctx.author_name:
        f.author = ctx.author_name
      elif ctx.author_email:
        f.author = ctx.author_email

      if ctx.author_time is not None:
        f.commit_date = ctx.author_time.isoformat()
