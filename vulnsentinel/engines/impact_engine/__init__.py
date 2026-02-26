"""Impact engine — connect upstream vulns to affected client projects."""

from vulnsentinel.engines.impact_engine.assessor import ImpactResult, assess_impact
from vulnsentinel.engines.impact_engine.runner import ImpactRunner

__all__ = [
    "ImpactResult",
    "ImpactRunner",
    "assess_impact",
]
