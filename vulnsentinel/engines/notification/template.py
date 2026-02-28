"""Email template rendering for vulnerability notifications."""

from __future__ import annotations

from typing import Any

from vulnsentinel.models.client_vuln import ClientVuln
from vulnsentinel.models.library import Library
from vulnsentinel.models.project import Project
from vulnsentinel.models.upstream_vuln import UpstreamVuln

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#388e3c",
}


def render_notification(
    project: Project,
    library: Library,
    upstream_vuln: UpstreamVuln,
    client_vuln: ClientVuln,
) -> tuple[str, str]:
    """Return (subject, html_body) for a vulnerability notification email."""
    severity = upstream_vuln.severity or "unknown"
    subject = (
        f"[VulnSentinel] {severity.upper()} vulnerability in {library.name} affects {project.name}"
    )

    color = _SEVERITY_COLORS.get(severity, "#757575")
    affected_funcs = _format_affected_functions(upstream_vuln.affected_functions)
    call_chain = _format_reachable_path(client_vuln.reachable_path)

    td_hdr = 'style="padding: 6px 12px; font-weight: bold; border-bottom: 1px solid #e0e0e0;"'
    td_val = 'style="padding: 6px 12px; border-bottom: 1px solid #e0e0e0;"'
    sev_span = f'<span style="color: {color}; font-weight: bold;">{severity.upper()}</span>'
    body_style = (
        "font-family: -apple-system, BlinkMacSystemFont,"
        " 'Segoe UI', Roboto, sans-serif;"
        " color: #212121; max-width: 640px; margin: 0 auto;"
    )

    html_body = f"""\
<html>
<body style="{body_style}">
<h2 style="color: {color};">{severity.upper()} Vulnerability Detected</h2>
<table style="border-collapse: collapse; width: 100%; margin-bottom: 16px;">
  <tr><td {td_hdr}>Project</td>
      <td {td_val}>{_esc(project.name)}</td></tr>
  <tr><td {td_hdr}>Library</td>
      <td {td_val}>{_esc(library.name)}</td></tr>
  <tr><td {td_hdr}>Vulnerability Type</td>
      <td {td_val}>{_esc(upstream_vuln.vuln_type or "N/A")}</td></tr>
  <tr><td {td_hdr}>Severity</td>
      <td {td_val}>{sev_span}</td></tr>
  <tr><td {td_hdr}>Commit SHA</td>
      <td {td_val}><code>{_esc(upstream_vuln.commit_sha)}</code></td></tr>
  <tr><td {td_hdr}>Fix Version</td>
      <td {td_val}>{_esc(client_vuln.fix_version or "N/A")}</td></tr>
</table>

<h3>Summary</h3>
<p>{_esc(upstream_vuln.summary or "No summary available.")}</p>

<h3>Affected Functions</h3>
{affected_funcs}

<h3>Reachable Path</h3>
{call_chain}

<hr style="border: none; border-top: 1px solid #e0e0e0; margin: 24px 0;">
<p style="color: #757575; font-size: 12px;">This is an automated notification from VulnSentinel.</p>
</body>
</html>"""

    return subject, html_body


def _esc(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _format_affected_functions(funcs: list[str] | None) -> str:
    if not funcs:
        return "<p>No affected functions identified.</p>"
    items = "".join(f"<li><code>{_esc(f)}</code></li>" for f in funcs)
    return f"<ul>{items}</ul>"


def _format_reachable_path(path: dict[str, Any] | None) -> str:
    if not path:
        return "<p>No reachable path data.</p>"

    parts: list[str] = []

    if path.get("found"):
        parts.append('<p style="color: #d32f2f; font-weight: bold;">Reachable: YES</p>')
    else:
        parts.append('<p style="color: #388e3c;">Reachable: NO</p>')

    if path.get("strategy"):
        parts.append(f"<p>Strategy: <code>{_esc(str(path['strategy']))}</code></p>")

    if path.get("depth") is not None:
        parts.append(f"<p>Call depth: {path['depth']}</p>")

    call_chain = path.get("call_chain")
    if call_chain:
        items = "".join(f"<li><code>{_esc(str(step))}</code></li>" for step in call_chain)
        parts.append(f"<p>Call chain:</p><ol>{items}</ol>")

    return "\n".join(parts)
