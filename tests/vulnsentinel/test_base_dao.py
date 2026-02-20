"""Tests for BaseDAO — CRUD + cursor pagination + exists + get_by_field + bulk_create."""

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from vulnsentinel.dao.base import (
    BaseDAO,
    InvalidCursorError,
    _sign,
    decode_cursor,
    encode_cursor,
)
from vulnsentinel.models.user import User


def _forge_cursor(payload: str) -> str:
    """Create a cursor with a valid HMAC signature but arbitrary payload."""
    sig = _sign(payload)
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


class UserDAO(BaseDAO[User]):
    model = User


@pytest.fixture
def dao():
    return UserDAO()


# ── cursor encode / decode ───────────────────────────────────────────────


class TestCursorCodec:
    def test_roundtrip(self):
        dt = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        uid = uuid.uuid4()
        encoded = encode_cursor(dt, uid)
        decoded = decode_cursor(encoded)
        assert decoded.created_at == dt
        assert decoded.id == uid

    def test_naive_datetime_gets_utc(self):
        naive = datetime(2026, 1, 15, 10, 30, 0)
        uid = uuid.uuid4()
        decoded = decode_cursor(encode_cursor(naive, uid))
        assert decoded.created_at.tzinfo is not None

    def test_invalid_cursor_garbage(self):
        with pytest.raises(InvalidCursorError):
            decode_cursor("garbage")

    def test_invalid_cursor_empty(self):
        with pytest.raises(InvalidCursorError):
            decode_cursor("")

    def test_invalid_cursor_bad_json(self):
        """Payload passes HMAC but is not valid JSON."""
        bad = _forge_cursor("not json")
        with pytest.raises(InvalidCursorError, match="invalid cursor"):
            decode_cursor(bad)

    def test_invalid_cursor_missing_keys(self):
        """Payload passes HMAC but lacks required 'c' / 'i' keys."""
        bad = _forge_cursor(json.dumps({"x": 1}))
        with pytest.raises(InvalidCursorError, match="invalid cursor"):
            decode_cursor(bad)

    def test_tampered_cursor_rejected(self):
        """Modifying the payload should invalidate the HMAC signature."""
        dt = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        uid = uuid.uuid4()
        encoded = encode_cursor(dt, uid)
        # Decode, tamper with payload, re-encode
        raw = base64.urlsafe_b64decode(encoded.encode()).decode()
        payload, sig = raw.rsplit("|", 1)
        tampered_payload = payload.replace(str(uid), str(uuid.uuid4()))
        tampered = base64.urlsafe_b64encode(f"{tampered_payload}|{sig}".encode()).decode()
        with pytest.raises(InvalidCursorError, match="signature mismatch"):
            decode_cursor(tampered)

    def test_forged_cursor_without_signature_rejected(self):
        """A cursor crafted without knowing the secret should be rejected."""
        payload = json.dumps(
            {
                "c": datetime.now(timezone.utc).isoformat(),
                "i": str(uuid.uuid4()),
            }
        )
        forged = base64.urlsafe_b64encode(f"{payload}|fakesig000000000".encode()).decode()
        with pytest.raises(InvalidCursorError, match="signature mismatch"):
            decode_cursor(forged)

    def test_oversized_cursor_rejected(self):
        """Extremely long cursor string must not hang or OOM — just fail."""
        huge = base64.urlsafe_b64encode(b"A" * 100_000).decode()
        with pytest.raises(InvalidCursorError):
            decode_cursor(huge)


# ── CRUD ─────────────────────────────────────────────────────────────────


class TestCreate:
    async def test_create_returns_model_with_server_defaults(self, dao, session):
        user = await dao.create(
            session,
            username="alice",
            email="alice@example.com",
            password_hash="hashed",
        )
        assert isinstance(user, User)
        assert user.username == "alice"
        # server_default fields should be populated after refresh
        assert user.id is not None
        assert user.created_at is not None
        assert user.role == "viewer"

    async def test_create_missing_required_field(self, dao, session):
        """Missing NOT NULL column must raise, not silently insert NULL."""
        with pytest.raises(IntegrityError):
            await dao.create(session, username="no_email", password_hash="h")

    async def test_create_duplicate_unique_key(self, dao, session):
        """Inserting a duplicate unique value must raise IntegrityError."""
        await dao.create(session, username="dup", email="dup@example.com", password_hash="h")
        with pytest.raises(IntegrityError):
            await dao.create(session, username="dup", email="dup2@example.com", password_hash="h")


class TestGetById:
    async def test_found(self, dao, session):
        user = await dao.create(session, username="bob", email="bob@example.com", password_hash="h")
        found = await dao.get_by_id(session, user.id)
        assert found is not None
        assert found.id == user.id

    async def test_not_found(self, dao, session):
        result = await dao.get_by_id(session, uuid.uuid4())
        assert result is None


class TestUpdate:
    async def test_update_field(self, dao, session):
        user = await dao.create(
            session, username="carol", email="carol@example.com", password_hash="h"
        )
        updated = await dao.update(session, user.id, email="carol2@example.com")
        assert updated is not None
        assert updated.email == "carol2@example.com"
        # Unchanged fields must remain intact
        assert updated.username == "carol"
        assert updated.password_hash == "h"

    async def test_update_not_found(self, dao, session):
        result = await dao.update(session, uuid.uuid4(), email="x@x.com")
        assert result is None

    async def test_update_invalid_column(self, dao, session):
        user = await dao.create(
            session, username="dave", email="dave@example.com", password_hash="h"
        )
        with pytest.raises(AttributeError, match="has no column"):
            await dao.update(session, user.id, nonexistent="val")

    async def test_update_immutable_id(self, dao, session):
        user = await dao.create(session, username="eve", email="eve@example.com", password_hash="h")
        with pytest.raises(AttributeError, match="immutable"):
            await dao.update(session, user.id, id=uuid.uuid4())

    async def test_update_immutable_created_at(self, dao, session):
        user = await dao.create(
            session, username="frank", email="frank@example.com", password_hash="h"
        )
        with pytest.raises(AttributeError, match="immutable"):
            await dao.update(session, user.id, created_at=datetime.now(timezone.utc))

    async def test_update_multiple_fields(self, dao, session):
        """Updating multiple fields at once must apply all changes."""
        user = await dao.create(
            session,
            username="multi_upd",
            email="mu@example.com",
            password_hash="h",
            role="viewer",
        )
        updated = await dao.update(session, user.id, email="mu2@example.com", role="admin")
        assert updated.email == "mu2@example.com"
        assert updated.role == "admin"
        assert updated.username == "multi_upd"  # untouched

    async def test_update_empty_values_is_noop(self, dao, session):
        """update() with no values should return the object unchanged."""
        user = await dao.create(
            session, username="noop", email="noop@example.com", password_hash="h"
        )
        result = await dao.update(session, user.id)
        assert result is not None
        assert result.username == "noop"


class TestDelete:
    async def test_delete_existing(self, dao, session):
        user = await dao.create(
            session, username="grace", email="grace@example.com", password_hash="h"
        )
        user_id = user.id
        assert await dao.delete(session, user_id) is True
        # Verify with raw SQL — don't rely on DAO to validate itself
        result = await session.execute(select(User).where(User.id == user_id))
        assert result.scalars().first() is None

    async def test_delete_not_found(self, dao, session):
        assert await dao.delete(session, uuid.uuid4()) is False

    async def test_double_delete(self, dao, session):
        """Deleting the same row twice: first True, second False."""
        user = await dao.create(
            session, username="dbl_del", email="dd@example.com", password_hash="h"
        )
        assert await dao.delete(session, user.id) is True
        assert await dao.delete(session, user.id) is False


# ── Exists ───────────────────────────────────────────────────────────────


class TestExists:
    async def test_exists_true(self, dao, session):
        user = await dao.create(
            session, username="exist_yes", email="ey@example.com", password_hash="h"
        )
        assert await dao.exists(session, user.id) is True

    async def test_exists_false(self, dao, session):
        assert await dao.exists(session, uuid.uuid4()) is False

    async def test_exists_after_delete(self, dao, session):
        """exists must return False after the row is deleted."""
        user = await dao.create(
            session, username="exist_del", email="ed@example.com", password_hash="h"
        )
        await dao.delete(session, user.id)
        assert await dao.exists(session, user.id) is False


# ── GetByField ───────────────────────────────────────────────────────────


class TestGetByField:
    async def test_found_single_filter(self, dao, session):
        await dao.create(session, username="findme", email="findme@example.com", password_hash="h")
        found = await dao.get_by_field(session, username="findme")
        assert found is not None
        assert found.username == "findme"

    async def test_found_multiple_filters(self, dao, session):
        await dao.create(
            session,
            username="multi",
            email="multi@example.com",
            password_hash="h",
            role="admin",
        )
        found = await dao.get_by_field(session, username="multi", role="admin")
        assert found is not None

    async def test_not_found(self, dao, session):
        result = await dao.get_by_field(session, username="nonexistent")
        assert result is None

    async def test_partial_match_not_returned(self, dao, session):
        await dao.create(
            session,
            username="partial",
            email="partial@example.com",
            password_hash="h",
            role="viewer",
        )
        result = await dao.get_by_field(session, username="partial", role="admin")
        assert result is None

    async def test_empty_filters_raises(self, dao, session):
        with pytest.raises(ValueError, match="requires at least one filter"):
            await dao.get_by_field(session)

    async def test_nonexistent_column_raises(self, dao, session):
        """Filtering by a column that doesn't exist must raise AttributeError."""
        with pytest.raises(AttributeError):
            await dao.get_by_field(session, nonexistent_col="val")


# ── BulkCreate ───────────────────────────────────────────────────────────


class TestBulkCreate:
    async def test_bulk_create_multiple(self, dao, session):
        items = [
            {"username": f"bulk_{i}", "email": f"bulk_{i}@example.com", "password_hash": "h"}
            for i in range(5)
        ]
        objs = await dao.bulk_create(session, items)
        assert len(objs) == 5
        # Verify each row has correct data, not just a non-null id
        created_usernames = {obj.username for obj in objs}
        expected_usernames = {f"bulk_{i}" for i in range(5)}
        assert created_usernames == expected_usernames
        for obj in objs:
            assert obj.id is not None

    async def test_bulk_create_empty_list(self, dao, session):
        objs = await dao.bulk_create(session, [])
        assert objs == []

    async def test_bulk_create_single(self, dao, session):
        objs = await dao.bulk_create(
            session, [{"username": "single", "email": "single@example.com", "password_hash": "h"}]
        )
        assert len(objs) == 1
        assert objs[0].username == "single"

    async def test_bulk_create_count(self, dao, session):
        items = [
            {"username": f"bc_{i}", "email": f"bc_{i}@example.com", "password_hash": "h"}
            for i in range(3)
        ]
        await dao.bulk_create(session, items)
        total = await dao.count(session)
        assert total == 3

    async def test_bulk_create_duplicate_key_rolls_back_all(self, dao, session):
        """If one row violates unique constraint, no rows should be inserted."""
        items = [
            {"username": "bk_ok", "email": "bk_ok@example.com", "password_hash": "h"},
            {"username": "bk_ok", "email": "bk_dup@example.com", "password_hash": "h"},
        ]
        with pytest.raises(IntegrityError):
            await dao.bulk_create(session, items)

    async def test_bulk_create_missing_required_field(self, dao, session):
        """Bulk insert with missing NOT NULL column must raise."""
        items = [
            {"username": "bk_miss", "password_hash": "h"},  # missing email
        ]
        with pytest.raises(IntegrityError):
            await dao.bulk_create(session, items)


# ── Pagination ───────────────────────────────────────────────────────────


class TestPaginate:
    async def _seed_users(self, dao, session, count: int) -> list[User]:
        """Create *count* users with staggered created_at."""
        users = []
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(count):
            user = await dao.create(
                session,
                username=f"user_{i:03d}",
                email=f"user_{i:03d}@example.com",
                password_hash="h",
            )
            # Manually set created_at to ensure deterministic ordering
            user.created_at = base_time + timedelta(minutes=i)
            await session.flush()
            users.append(user)
        return users

    async def test_first_page(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)
        page = await dao.paginate(session, query, page_size=3)

        assert len(page.data) == 3
        assert page.has_more is True
        assert page.next_cursor is not None
        assert page.total is None  # DAO doesn't compute total

    async def test_second_page_with_cursor(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)

        page1 = await dao.paginate(session, query, page_size=3)
        page2 = await dao.paginate(session, query, cursor=page1.next_cursor, page_size=3)

        assert len(page2.data) == 2
        assert page2.has_more is False
        assert page2.next_cursor is None

    async def test_no_overlap_between_pages(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)

        page1 = await dao.paginate(session, query, page_size=3)
        page2 = await dao.paginate(session, query, cursor=page1.next_cursor, page_size=3)

        ids1 = {u.id for u in page1.data}
        ids2 = {u.id for u in page2.data}
        assert ids1.isdisjoint(ids2)

    async def test_desc_ordering(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)

        page = await dao.paginate(session, query, page_size=10)
        timestamps = [u.created_at for u in page.data]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_empty_result(self, dao, session):
        query = select(User)
        page = await dao.paginate(session, query, page_size=10)

        assert len(page.data) == 0
        assert page.has_more is False
        assert page.next_cursor is None

    async def test_invalid_cursor_raises(self, dao, session):
        query = select(User)
        with pytest.raises(InvalidCursorError):
            await dao.paginate(session, query, cursor="bad_cursor")

    async def test_page_size_clamped_to_max(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)
        # page_size=9999 should be clamped to 100
        page = await dao.paginate(session, query, page_size=9999)
        assert len(page.data) == 5  # only 5 rows exist, all returned

    async def test_page_size_clamped_to_min(self, dao, session):
        await self._seed_users(dao, session, 5)
        query = select(User)
        page = await dao.paginate(session, query, page_size=0)
        assert len(page.data) == 1  # clamped to 1

    async def test_negative_page_size_clamped(self, dao, session):
        """Negative page_size should be clamped to minimum (1), not crash."""
        await self._seed_users(dao, session, 3)
        query = select(User)
        page = await dao.paginate(session, query, page_size=-5)
        assert len(page.data) == 1  # clamped to PAGE_SIZE_MIN

    async def test_paginate_with_where_filter(self, dao, session):
        """Pagination must work correctly with a pre-filtered query."""
        # Create 3 admins and 3 viewers
        for i in range(3):
            await dao.create(
                session,
                username=f"adm_{i}",
                email=f"adm_{i}@example.com",
                password_hash="h",
                role="admin",
            )
            await dao.create(
                session,
                username=f"vwr_{i}",
                email=f"vwr_{i}@example.com",
                password_hash="h",
            )
        query = select(User).where(User.role == "admin")
        page = await dao.paginate(session, query, page_size=10)
        assert len(page.data) == 3
        assert all(u.role == "admin" for u in page.data)

    async def test_paginate_with_filter_and_cursor(self, dao, session):
        """Cursor must respect the WHERE filter across pages."""
        base_time = datetime(2026, 6, 1, tzinfo=timezone.utc)
        for i in range(5):
            user = await dao.create(
                session,
                username=f"fadm_{i}",
                email=f"fadm_{i}@example.com",
                password_hash="h",
                role="admin",
            )
            user.created_at = base_time + timedelta(minutes=i)
            await session.flush()

        query = select(User).where(User.role == "admin")
        page1 = await dao.paginate(session, query, page_size=2)
        page2 = await dao.paginate(session, query, cursor=page1.next_cursor, page_size=2)

        all_data = page1.data + page2.data
        assert len(all_data) == 4
        assert all(u.role == "admin" for u in all_data)


# ── Count ────────────────────────────────────────────────────────────────


class TestCount:
    async def test_count_all(self, dao, session):
        for i in range(3):
            await dao.create(
                session,
                username=f"cnt_{i}",
                email=f"cnt_{i}@example.com",
                password_hash="h",
            )
        total = await dao.count(session)
        assert total == 3

    async def test_count_empty(self, dao, session):
        total = await dao.count(session)
        assert total == 0

    async def test_count_with_filter(self, dao, session):
        await dao.create(
            session,
            username="admin1",
            email="a1@example.com",
            password_hash="h",
            role="admin",
        )
        await dao.create(
            session,
            username="viewer1",
            email="v1@example.com",
            password_hash="h",
        )
        query = select(User).where(User.role == "admin")
        assert await dao.count(session, query) == 1


# ── Robustness / Malformed Input ─────────────────────────────────────────


class TestRobustness:
    """Adversarial and edge-case inputs that a real caller might send."""

    async def test_get_by_id_none_raises(self, dao, session):
        """pk=None must not silently return a random row."""
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.get_by_id(session, None)

    async def test_exists_none_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.exists(session, None)

    async def test_delete_none_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.delete(session, None)

    async def test_get_by_field_none_value(self, dao, session):
        """WHERE username = NULL is not the same as IS NULL — should return None."""
        await dao.create(session, username="real", email="real@example.com", password_hash="h")
        # SQL: WHERE username = NULL → always false, returns nothing
        result = await dao.get_by_field(session, username=None)
        assert result is None

    async def test_update_none_pk_raises(self, dao, session):
        with pytest.raises(ValueError, match="pk must not be None"):
            await dao.update(session, None, email="x@x.com")

    async def test_create_with_unicode(self, dao, session):
        """Unicode values must be stored and retrieved correctly."""
        await dao.create(session, username="用户名", email="日本語@example.com", password_hash="h")
        found = await dao.get_by_field(session, username="用户名")
        assert found is not None
        assert found.email == "日本語@example.com"

    async def test_create_with_special_chars(self, dao, session):
        """SQL metacharacters in values must not cause injection."""
        await dao.create(
            session,
            username="admin' OR 1=1--",
            email="injection@example.com",
            password_hash="h",
        )
        # Must be stored literally, not interpreted as SQL
        found = await dao.get_by_field(session, username="admin' OR 1=1--")
        assert found is not None
        assert found.username == "admin' OR 1=1--"

    async def test_get_by_field_sql_injection_in_value(self, dao, session):
        """SQL injection in filter value must not match unrelated rows."""
        await dao.create(session, username="safe", email="safe@example.com", password_hash="h")
        result = await dao.get_by_field(session, username="' OR '1'='1")
        assert result is None

    async def test_create_empty_string_fields(self, dao, session):
        """Empty strings are valid Text values — must not be treated as NULL."""
        user = await dao.create(
            session, username="empty_pw", email="ep@example.com", password_hash=""
        )
        assert user.password_hash == ""

    async def test_paginate_exact_page_boundary(self, dao, session):
        """When row count == page_size, has_more must be False."""
        for i in range(3):
            await dao.create(
                session,
                username=f"exact_{i}",
                email=f"exact_{i}@example.com",
                password_hash="h",
            )
        query = select(User)
        page = await dao.paginate(session, query, page_size=3)
        assert len(page.data) == 3
        assert page.has_more is False
        assert page.next_cursor is None
