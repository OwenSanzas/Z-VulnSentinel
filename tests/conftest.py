"""Shared pytest fixtures for Z-Code-Analyzer-Station tests."""

import os

import pytest


@pytest.fixture
def neo4j_uri():
    return os.environ.get("NEO4J_URI", "bolt://localhost:7687")


@pytest.fixture
def neo4j_auth():
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "testpassword")
    return (user, password)


@pytest.fixture
def mongo_uri():
    return os.environ.get("MONGO_URI", "mongodb://localhost:27017")
