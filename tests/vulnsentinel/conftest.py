"""Shared fixtures for vulnsentinel tests.

Requires a running PostgreSQL instance. Default connection:
    postgresql+asyncpg://vulnsentinel:vulnsentinel@localhost:5432/vulnsentinel_test

Override with the ``TEST_DATABASE_URL`` environment variable.

Start the database:
    docker compose up -d postgres
"""

import os

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from vulnsentinel.core.database import Base

DEFAULT_DB_URL = (
    "postgresql+asyncpg://vulnsentinel:vulnsentinel@localhost:5432/vulnsentinel_test"
)

_needs_pg = pytest.mark.skipif(
    os.environ.get("SKIP_PG") == "1",
    reason="SKIP_PG=1 — PostgreSQL tests disabled",
)


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def db_url():
    return os.environ.get("TEST_DATABASE_URL", DEFAULT_DB_URL)


@pytest_asyncio.fixture(scope="session")
async def engine(db_url):
    """Create an async engine that lives for the entire test session."""
    eng = create_async_engine(db_url, echo=False)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database(engine):
    """Create all tables (including ENUMs) before tests, drop after."""
    async with engine.begin() as conn:
        # Create custom ENUMs used by models
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE event_type AS ENUM "
            "    ('commit','pr_merge','tag','bug_issue'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE event_classification AS ENUM "
            "    ('security_bugfix','normal_bugfix','refactor','feature','other'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE severity_level AS ENUM "
            "    ('critical','high','medium','low'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE upstream_vuln_status AS ENUM "
            "    ('analyzing','published'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE client_vuln_status AS ENUM "
            "    ('recorded','reported','confirmed','fixed','not_affect'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE pipeline_status AS ENUM "
            "    ('pending','path_searching','poc_generating','verified','not_affect'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE snapshot_status AS ENUM ('building','completed'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE snapshot_backend AS ENUM "
            "    ('svf','joern','introspector','prebuild'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.execute(text(
            "DO $$ BEGIN "
            "  CREATE TYPE snapshot_trigger AS ENUM "
            "    ('tag_push','manual','scheduled','on_upstream_vuln_analysis'); "
            "EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def session(engine):
    """Provide a transactional session that rolls back after each test."""
    async with async_sessionmaker(engine, class_=AsyncSession)() as sess:
        async with sess.begin():
            yield sess
            await sess.rollback()
