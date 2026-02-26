"""Event classifier engine — LLM-based event classification."""

from vulnsentinel.engines.event_classifier.classifier import EventInput, classify
from vulnsentinel.engines.event_classifier.runner import EventClassifierRunner

__all__ = [
    "EventClassifierRunner",
    "EventInput",
    "classify",
]
