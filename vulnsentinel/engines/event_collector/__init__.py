"""Event collector engine — GitHub event collection without DB access."""

from vulnsentinel.engines.event_collector.collector import collect, count_by_type
from vulnsentinel.engines.event_collector.github_client import GitHubClient, RateLimitError
from vulnsentinel.engines.event_collector.models import CollectedEvent, CollectResult
from vulnsentinel.engines.event_collector.runner import EventCollectorRunner

__all__ = [
    "CollectedEvent",
    "CollectResult",
    "EventCollectorRunner",
    "GitHubClient",
    "RateLimitError",
    "collect",
    "count_by_type",
]
