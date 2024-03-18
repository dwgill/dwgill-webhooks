import asyncio
import hashlib
import secrets
import datetime as dt
from typing import Annotated, Literal, Optional, TypeAlias, TypedDict, cast
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import (
    Computed,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
    insert,
    select,
)
from sqlalchemy.orm import Mapped, validates
from sqlalchemy.orm import mapped_column
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncSession
from app.emails import InvalidEmailError, validate_email
from sqlalchemy.orm import MappedAsDataclass
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncAttrs
from app.passwords import (
    PasswordVersion,
    hash_new_password,
    latest_password_version,
    test_password_plaintext_against_hash,
    UnknownPasswordVersion,
    validate_password_version,
)
import sqlalchemy.exc


class Base(AsyncAttrs, DeclarativeBase):
    pass


class UserDB(Base):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    username: Mapped[str] = mapped_column(String())
    updated_datetime: Mapped[dt.datetime] = mapped_column(
        DateTime(), server_default=func.now(), onupdate=func.now()
    )
    created_datetime: Mapped[dt.datetime] = mapped_column(
        DateTime(), server_default=func.now()
    )
    username_lc: Mapped[str] = mapped_column(
        String(),
        Computed("LOWER(username)"),
        unique=True,
    )
    email: Mapped[str] = mapped_column(String())
    email_lc: Mapped[str] = mapped_column(
        String(),
        Computed("LOWER(email)"),
        unique=True,
    )
    password_hash: Mapped[str] = mapped_column(String())
    password_salt: Mapped[str] = mapped_column(String())
    password_version: Mapped[int] = mapped_column(Integer())
    tokens: Mapped[list["TokenDB"]] = relationship(back_populates="user")

    @validates("email")
    def _validate_email(self, key: str, email: str):
        try:
            return validate_email(email)
        except InvalidEmailError as e:
            raise ValueError(f"Invalid email: {e.error_message.lower()}")

    @validates("username")
    def _validate_username(self, key: str, username: str):
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")

        return username

    @validates("updated_datetime", "created_datetime")
    def _validate_datetimes(self, key: str, value: dt.datetime):
        if value.tzinfo is not None:
            value.astimezone(dt.timezone.utc)

        return value

    @validates("password_version")
    def _validate_password_version(self, key: str, password_version: int):
        if not validate_password_version(password_version):
            raise UnknownPasswordVersion(password_version)

        return password_version

    def test_password(self, password_plaintext: str) -> bool:
        return test_password_plaintext_against_hash(
            password_plaintext=password_plaintext,
            password_hash=self.password_hash,
            password_salt=self.password_salt,
            password_version=self.password_version,
        )


class TokenDB(Base):
    __tablename__ = "token"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    value: Mapped[str] = mapped_column(String())
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"), nullable=True, index=True)
    user: Mapped[Optional["UserDB"]] = relationship(back_populates="tokens")


async def recreate_tables(engine: AsyncEngine):
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSession(engine) as session, session.begin():
        foobar = UserDB(
            username="FooBar",
            email="foo.bar@example.com",
            **hash_new_password(
                password_plaintext="Password123",
            ),
        )

        barfoo = UserDB(
            username="BarFOo",
            email="bar.foo@example.com",
            **hash_new_password(
                password_plaintext="!Password123",
            ),
        )

        foobar.tokens.append(TokenDB(
            value="foobar_token"
        ))

        barfoo.tokens.append(TokenDB(
            value="barfoo_token"
        ))

        session.add(foobar)
        session.add(barfoo)



async def main():
    engine = create_async_engine("sqlite+aiosqlite:///./database.db", echo=True)

    await recreate_tables(engine)

    async with AsyncSession(engine) as session, session.begin():
        result = await session.execute(
            select(UserDB).where(UserDB.username_lc == "foobar")
        )
        row = result.scalar_one()

        


if __name__ == "__main__":
    asyncio.run(main())
