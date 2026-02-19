"""Tests for UserDAO."""

import pytest

from vulnsentinel.dao.user_dao import UserDAO


@pytest.fixture
def dao():
    return UserDAO()


# ── get_by_username ──────────────────────────────────────────────────────


class TestGetByUsername:
    async def test_found(self, dao, session):
        await dao.create(session, username="alice", email="alice@example.com", password_hash="h")
        user = await dao.get_by_username(session, "alice")
        assert user is not None
        assert user.username == "alice"
        assert user.email == "alice@example.com"

    async def test_not_found(self, dao, session):
        result = await dao.get_by_username(session, "ghost")
        assert result is None

    async def test_case_sensitive(self, dao, session):
        """Username lookup must be exact — 'Alice' != 'alice'."""
        await dao.create(session, username="alice", email="alice@example.com", password_hash="h")
        assert await dao.get_by_username(session, "Alice") is None
        assert await dao.get_by_username(session, "ALICE") is None

    async def test_returns_correct_user_among_many(self, dao, session):
        """Must not return a different user when multiple exist."""
        await dao.create(session, username="bob", email="bob@example.com", password_hash="h")
        await dao.create(session, username="bobby", email="bobby@example.com", password_hash="h")
        user = await dao.get_by_username(session, "bob")
        assert user is not None
        assert user.username == "bob"
        assert user.email == "bob@example.com"


# ── upsert ───────────────────────────────────────────────────────────────


class TestUpsert:
    async def test_insert_new_user(self, dao, session):
        """First upsert should create the user."""
        user = await dao.upsert(
            session,
            username="admin",
            email="admin@example.com",
            password_hash="hashed",
            role="admin",
        )
        assert user is not None
        assert user.username == "admin"
        assert user.role == "admin"
        assert user.id is not None

    async def test_upsert_existing_returns_original(self, dao, session):
        """Second upsert with same username should return the existing row unchanged."""
        user1 = await dao.upsert(
            session,
            username="admin",
            email="admin@example.com",
            password_hash="hashed_v1",
            role="admin",
        )
        user2 = await dao.upsert(
            session,
            username="admin",
            email="changed@example.com",  # different email
            password_hash="hashed_v2",  # different hash
            role="viewer",  # different role
        )
        # Should return the ORIGINAL, not overwrite
        assert user2.id == user1.id
        assert user2.email == "admin@example.com"
        assert user2.password_hash == "hashed_v1"
        assert user2.role == "admin"

    async def test_upsert_does_not_create_duplicate(self, dao, session):
        """After two upserts, only one row should exist."""
        await dao.upsert(
            session,
            username="admin",
            email="admin@example.com",
            password_hash="h",
        )
        await dao.upsert(
            session,
            username="admin",
            email="other@example.com",
            password_hash="h2",
        )
        total = await dao.count(session)
        assert total == 1

    async def test_upsert_default_role_is_admin(self, dao, session):
        """Default role should be 'admin' (startup admin creation use case)."""
        user = await dao.upsert(
            session,
            username="default_role",
            email="dr@example.com",
            password_hash="h",
        )
        assert user.role == "admin"

    async def test_upsert_different_usernames_both_created(self, dao, session):
        """Upsert with different usernames should create separate users."""
        u1 = await dao.upsert(session, username="admin1", email="a1@example.com", password_hash="h")
        u2 = await dao.upsert(session, username="admin2", email="a2@example.com", password_hash="h")
        assert u1.id != u2.id
        assert await dao.count(session) == 2


# ── inherited BaseDAO methods work correctly ─────────────────────────────


class TestInheritedMethods:
    async def test_get_by_id(self, dao, session):
        """Inherited get_by_id should work on UserDAO."""
        user = await dao.create(
            session, username="inherit", email="inherit@example.com", password_hash="h"
        )
        found = await dao.get_by_id(session, user.id)
        assert found is not None
        assert found.username == "inherit"

    async def test_delete_then_get_by_username(self, dao, session):
        """After deleting a user, get_by_username must return None."""
        user = await dao.create(
            session, username="to_delete", email="td@example.com", password_hash="h"
        )
        await dao.delete(session, user.id)
        assert await dao.get_by_username(session, "to_delete") is None
