"""Impact assessor — pure-function mode for matching vulns to project deps."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from vulnsentinel.models.project_dependency import ProjectDependency


@dataclass
class ImpactResult:
    """A single upstream_vuln ↔ project match."""

    upstream_vuln_id: uuid.UUID
    project_id: uuid.UUID
    constraint_expr: str | None
    resolved_version: str | None
    constraint_source: str | None


def assess_impact(
    upstream_vuln_id: uuid.UUID,
    dependencies: list[ProjectDependency],
) -> list[ImpactResult]:
    """Return an :class:`ImpactResult` for every dependency (pass-through).

    Current strategy: all projects that depend on the affected library are
    considered potentially impacted.  Version matching is intentionally
    deferred to the Reachability Analyzer.

    When version-constraint parsing matures, filtering logic can be added
    here to perform fast negation (skip projects whose resolved version is
    outside the affected range).
    """
    return [
        ImpactResult(
            upstream_vuln_id=upstream_vuln_id,
            project_id=dep.project_id,
            constraint_expr=dep.constraint_expr,
            resolved_version=dep.resolved_version,
            constraint_source=dep.constraint_source,
        )
        for dep in dependencies
    ]
