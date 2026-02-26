"""VulnSentinelAgent — BaseAgent subclass with DB-persistent context."""

from __future__ import annotations

from typing import Any

from shared.agent.base import BaseAgent
from shared.agent.context import AgentContext
from vulnsentinel.agent.context import PersistentAgentContext


class VulnSentinelAgent(BaseAgent):
    """BaseAgent that automatically uses PersistentAgentContext for DB persistence."""

    def create_context(self, **kwargs: Any) -> AgentContext:
        return PersistentAgentContext(**kwargs)
