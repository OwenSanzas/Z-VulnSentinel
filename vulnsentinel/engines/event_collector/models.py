"""Data models for the event collector engine."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

EventType = Literal["commit", "pr_merge", "tag", "bug_issue"]


@dataclass
class CollectedEvent:
    """A single event collected from the GitHub API.

    This is a pure data structure — no DB dependencies.
    """

    type: EventType
    ref: str  # SHA / PR number / tag name / issue number
    title: str
    source_url: str | None = None
    author: str | None = None
    event_at: datetime | None = None
    message: str | None = None
    related_issue_ref: str | None = None
    related_issue_url: str | None = None
    related_pr_ref: str | None = None
    related_pr_url: str | None = None
    related_commit_sha: str | None = None


@dataclass
class CollectResult:
    """Summary of a single collect() run."""

    library_id: uuid.UUID
    fetched: int = 0
    inserted: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
