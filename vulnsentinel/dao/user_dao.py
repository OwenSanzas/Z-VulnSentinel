"""UserDAO — users table operations."""

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnsentinel.dao.base import BaseDAO
from vulnsentinel.models.user import User


class UserDAO(BaseDAO[User]):
    model = User

    async def get_by_username(self, session: AsyncSession, username: str) -> User | None:
        """Look up a user by username (login flow)."""
        return await self.get_by_field(session, username=username)

    async def upsert(
        self,
        session: AsyncSession,
        *,
        username: str,
        email: str,
        password_hash: str,
        role: str = "admin",
    ) -> User | None:
        """Insert a user or do nothing if username already exists.

        Used at startup to ensure the initial admin account exists.
        Returns the user row, or None if the insert was skipped
        (i.e. the user already existed).
        """
        stmt = (
            insert(User)
            .values(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
            )
            .on_conflict_do_nothing(index_elements=["username"])
            .returning(User)
        )
        result = await session.execute(stmt)
        row = result.scalars().first()
        if row is None:
            # Conflict — user already existed, fetch it
            return await self.get_by_field(session, username=username)
        return row
