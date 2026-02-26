"""Shared pytest fixtures for Z-Code-Analyzer-Station tests."""

import os

import pytest


@pytest.fixture
def neo4j_uri():
    return os.environ.get("NEO4J_URI", "bolt://localhost:7687")


@pytest.fixture
def neo4j_auth():
    auth_env = os.environ.get("NEO4J_AUTH", "none")
    if auth_env.lower() == "none":
        return None
    if ":" in auth_env:
        return tuple(auth_env.split(":", 1))
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "testpassword")
    return (user, password)


@pytest.fixture
def pg_session_factory():
    """Create a session factory for snapshot tests (uses local PostgreSQL)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.models.snapshot import ZCABase

    pg_url = os.environ.get(
        "ZCA_DATABASE_URL",
        "postgresql://vulnsentinel:vulnsentinel@localhost:5432/vulnsentinel_test",
    )
    engine = create_engine(pg_url)
    ZCABase.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    yield factory
    ZCABase.metadata.drop_all(engine)
    engine.dispose()
