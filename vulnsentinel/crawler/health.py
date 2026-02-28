"""Shared health checker for all ecosystem crawlers.

Checks whether Event Collector can fetch all event types from each repo
and outputs a Markdown report table.

Reusable across ecosystems — each ecosystem just provides its name and repos.json path.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

EVENT_ENDPOINTS = {
    "commit": "/repos/{owner}/{repo}/commits?per_page=1",
    "pr": "/repos/{owner}/{repo}/pulls?state=closed&per_page=1",
    "tag": "/repos/{owner}/{repo}/tags?per_page=1",
    "ghsa": "/repos/{owner}/{repo}/security-advisories?per_page=1",
}

BATCH_SIZE = 20
BATCH_PAUSE = 1.5


@dataclass
class CheckResult:
    name: str
    repo_url: str
    platform: str
    ok: bool
    expected_branch: str
    actual_branch: str | None = None
    actual_url: str | None = None
    branch_mismatch: bool = False
    redirected: bool = False
    not_found: bool = False
    disabled: bool = False
    endpoints: dict[str, bool] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Report:
    ecosystem: str = ""
    total: int = 0
    ok: int = 0
    results: list[CheckResult] = field(default_factory=list)
    problems: list[CheckResult] = field(default_factory=list)

    def add(self, result: CheckResult) -> None:
        self.total += 1
        self.results.append(result)
        if result.ok:
            self.ok += 1
        else:
            self.problems.append(result)

    def write_markdown(self, path: Path) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = []
        lines.append(f"# {self.ecosystem} Library Health Report")
        lines.append("")
        lines.append(f"> Generated: {now}  ")
        lines.append(
            f"> Total: {self.total} | Healthy: {self.ok} | Problems: {len(self.problems)}"
        )
        lines.append("")
        lines.append("| # | Name | URL | Platform | Commit | PR | Tag | GHSA | Notes |")
        lines.append("|---|------|-----|----------|--------|----|-----|------|-------|")

        for i, r in enumerate(self.results, 1):
            ep = r.endpoints
            commit = self._icon(ep.get("commit"))
            pr = self._icon(ep.get("pr"))
            tag = self._icon(ep.get("tag"))
            ghsa = self._icon(ep.get("ghsa"))
            notes = self._notes(r)
            name_link = f"[{r.name}]({r.repo_url})"
            owner_repo = r.repo_url.replace("https://github.com/", "")
            lines.append(
                f"| {i} | {name_link} | {owner_repo} | {r.platform} "
                f"| {commit} | {pr} | {tag} | {ghsa} | {notes} |"
            )

        if self.problems:
            lines.append("")
            lines.append("## Problems")
            lines.append("")
            for r in self.problems:
                notes = self._notes(r)
                lines.append(f"- **{r.name}**: {notes}")

        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _icon(reachable: bool | None) -> str:
        if reachable is None:
            return "-"
        return "\u2705" if reachable else "\u274c"

    @staticmethod
    def _notes(r: CheckResult) -> str:
        parts: list[str] = []
        if r.not_found:
            parts.append("repo not found")
        if r.disabled:
            parts.append("repo disabled")
        if r.redirected:
            parts.append(f"redirected -> {r.actual_url}")
        if r.branch_mismatch:
            parts.append(f"branch: expected={r.expected_branch} actual={r.actual_branch}")
        blocked = [k for k, v in r.endpoints.items() if not v]
        if blocked:
            parts.append(f"blocked: {', '.join(blocked)}")
        if r.error:
            parts.append(r.error)
        return "; ".join(parts) if parts else ""

    def print_console(self) -> None:
        print(f"\n  Total: {self.total}  Healthy: {self.ok}  Problems: {len(self.problems)}")
        if self.problems:
            for r in self.problems:
                notes = self._notes(r)
                print(f"    {r.name:<25} {notes}")
        print()


def parse_owner_repo(repo_url: str) -> tuple[str, str] | None:
    parsed = urlparse(repo_url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None
    parts = parsed.path.strip("/").removesuffix(".git").split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _gh_api_raw(endpoint: str) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["gh", "api", endpoint],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode, result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError:
        return -1, "gh CLI not found"


def _gh_api_jq(endpoint: str, jq: str) -> dict | None:
    try:
        result = subprocess.run(
            ["gh", "api", endpoint, "--jq", jq],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def probe_endpoint(owner: str, repo: str, event_type: str) -> bool:
    path = EVENT_ENDPOINTS[event_type].format(owner=owner, repo=repo)
    code, _ = _gh_api_raw(path)
    return code == 0


def check_one(entry: dict) -> CheckResult:
    name = entry["name"]
    repo_url = entry["repo_url"]
    platform = entry.get("platform", "github")
    expected_branch = entry["default_branch"]

    parsed = parse_owner_repo(repo_url)
    if not parsed:
        return CheckResult(
            name=name, repo_url=repo_url, platform=platform, ok=False,
            expected_branch=expected_branch, error=f"Cannot parse URL: {repo_url}",
        )

    owner, repo = parsed

    data = _gh_api_jq(
        f"repos/{owner}/{repo}",
        "{default_branch, disabled, full_name, html_url}",
    )
    if not data:
        return CheckResult(
            name=name, repo_url=repo_url, platform=platform, ok=False,
            expected_branch=expected_branch, not_found=True,
        )

    actual_branch = data.get("default_branch")
    is_disabled = data.get("disabled", False)
    full_name = data.get("full_name", "")
    actual_url = data.get("html_url", "")

    if is_disabled:
        return CheckResult(
            name=name, repo_url=repo_url, platform=platform, ok=False,
            expected_branch=expected_branch, disabled=True,
        )

    result = CheckResult(
        name=name, repo_url=repo_url, platform=platform, ok=True,
        expected_branch=expected_branch, actual_branch=actual_branch,
        actual_url=actual_url,
    )

    if full_name and f"{owner}/{repo}".lower() != full_name.lower():
        result.redirected = True
        result.ok = False

    if actual_branch and actual_branch != expected_branch:
        result.branch_mismatch = True
        result.ok = False

    for event_type in EVENT_ENDPOINTS:
        reachable = probe_endpoint(owner, repo, event_type)
        result.endpoints[event_type] = reachable
        if not reachable:
            result.ok = False

    return result


def auto_fix_branches(repos_json: Path, problems: list[CheckResult]) -> int:
    branch_fixes = {
        r.name: r.actual_branch for r in problems if r.branch_mismatch and r.actual_branch
    }
    if not branch_fixes:
        return 0

    with open(repos_json) as f:
        entries = json.load(f)

    fixed = 0
    for entry in entries:
        if entry["name"] in branch_fixes:
            entry["default_branch"] = branch_fixes[entry["name"]]
            fixed += 1

    with open(repos_json, "w") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return fixed


def run_health_check(ecosystem: str, repos_json: Path, report_md: Path) -> None:
    """Shared CLI entry point for health checking any ecosystem's repos.json."""
    parser = argparse.ArgumentParser(description=f"{ecosystem} library health checker")
    parser.add_argument(
        "--fix", action="store_true",
        help="Auto-fix branch mismatches in repos.json",
    )
    args = parser.parse_args()

    if not repos_json.exists():
        print(f"Error: {repos_json} not found", file=sys.stderr)
        sys.exit(1)

    with open(repos_json) as f:
        entries = json.load(f)

    print(
        f"Checking {len(entries)} {ecosystem} libraries "
        f"({len(EVENT_ENDPOINTS)} endpoints each)...\n"
    )

    report = Report(ecosystem=ecosystem)
    for i, entry in enumerate(entries):
        result = check_one(entry)
        report.add(result)

        icon = "." if result.ok else "X"
        print(icon, end="", flush=True)
        if (i + 1) % 50 == 0:
            print(f"  [{i + 1}/{len(entries)}]")

        if (i + 1) % BATCH_SIZE == 0:
            time.sleep(BATCH_PAUSE)

    print()
    report.print_console()

    report.write_markdown(report_md)
    print(f"  Report saved to {report_md}\n")

    if args.fix:
        fixed = auto_fix_branches(repos_json, report.problems)
        if fixed:
            print(f"  Auto-fixed {fixed} branch mismatches in repos.json\n")
        else:
            print("  No branch mismatches to fix.\n")

    sys.exit(0 if not report.problems else 1)
