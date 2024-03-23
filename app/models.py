import asyncio
import hashlib
import secrets
import datetime as dt
from typing import Annotated, Literal, Optional, TypeAlias, TypedDict, cast
from pydantic import field_validator
from app.emails import InvalidEmailError, validate_email
from app.passwords import (
    PasswordVersion,
    hash_new_password,
    latest_password_version,
    test_password_plaintext_against_hash,
    UnknownPasswordVersion,
    validate_password_version,
)
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import Field, SQLModel, Computed, func, select
from sqlmodel.ext.asyncio.session import AsyncSession


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_datetime: Optional[dt.datetime] = Field(
        default=None,
        allow_mutation=False,
        sa_column_kwargs={
            "server_default": func.now(),
        },
    )
    updated_datetime: Optional[dt.datetime] = Field(
        default=None,
        allow_mutation=False,
        sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()},
    )
    username: str = Field()
    username_lc: Optional[str] = Field(
        default=None,
        unique=True,
        allow_mutation=False,
        sa_column_args=(
            (
                Computed(
                    "LOWER(username)",
                ),
            )
        ),
    )
    email: str = Field()
    email_lc: Optional[str] = Field(
        default=None,
        unique=True,
        allow_mutation=False,
        sa_column_args=(
            (
                Computed(
                    "LOWER(email)",
                ),
            )
        ),
    )
    password_hash: str = Field()
    password_salt: str = Field()
    password_version: int = Field()

    def test_password(self, password_plaintext: str) -> bool:
        return test_password_plaintext_against_hash(
            password_plaintext=password_plaintext,
            password_hash=self.password_hash,
            password_salt=self.password_salt,
            password_version=self.password_version,
        )

    @field_validator("email")
    @classmethod
    def _validate_email(cls, email: str):
        try:
            return validate_email(email)
        except InvalidEmailError as e:
            raise ValueError(f"Invalid email: {e.error_message.lower()}")

    @field_validator("username")
    @classmethod
    def _validate_username(cls, username: str):
        username = username.strip()
        if not username:
            raise ValueError("Username cannot be empty")

        return username

    @field_validator("updated_datetime", "created_datetime")
    @classmethod
    def _validate_datetimes(cls, value: dt.datetime):
        if value.tzinfo is not None:
            value.astimezone(dt.timezone.utc)

        return value

    @field_validator("password_version")
    @classmethod
    def _validate_password_version(cls, password_version: int):
        if not validate_password_version(password_version):
            raise UnknownPasswordVersion(password_version)

        return password_version


class Token(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_datetime: Optional[dt.datetime] = Field(
        default=None,
        allow_mutation=False,
        sa_column_kwargs={
            "server_default": func.now(),
        },
    )
    updated_datetime: Optional[dt.datetime] = Field(
        default=None,
        allow_mutation=False,
        sa_column_kwargs={"server_default": func.now(), "onupdate": func.now()},
    )
    


# class TokenDB(Base):
#     __tablename__ = "token"

#     id: Mapped[int] = mapped_column(Integer(), primary_key=True)
#     value: Mapped[str] = mapped_column(String())
#     user_id: Mapped[Optional[int]] = mapped_column(
#         ForeignKey("user.id"), nullable=True, index=True
#     )
#     user: Mapped[Optional["UserDB"]] = relationship(back_populates="tokens")


# async def recreate_tables(engine: AsyncEngine):
#     async with engine.begin() as connection:
#         await connection.run_sync(Base.metadata.drop_all)
#         await connection.run_sync(Base.metadata.create_all)

#     async with AsyncSession(engine) as session, session.begin():
#         foobar = UserDB(
#             username="FooBar",
#             email="foo.bar@example.com",
#             **hash_new_password(
#                 password_plaintext="Password123",
#             ),
#         )

#         barfoo = UserDB(
#             username="BarFOo",
#             email="bar.foo@example.com",
#             **hash_new_password(
#                 password_plaintext="!Password123",
#             ),
#         )

#         foobar.tokens.append(TokenDB(value="foobar_token"))

#         barfoo.tokens.append(TokenDB(value="barfoo_token"))

#         session.add(foobar)
#         session.add(barfoo)


async def main():
    engine = create_async_engine("sqlite+aiosqlite:///./database.db", echo=True)
    
    async with engine.begin() as conn:
        await conn.run_sync(User.metadata.drop_all)
        await conn.run_sync(User.metadata.create_all)

    async with AsyncSession(engine) as session, session.begin():
        user_1 = User(
            username="FooBar",
            email="foo.bar@example.com",
            **hash_new_password(
                password_plaintext="Password123",
            ),
        )
        user_2 = User(
            username="BarFoo",
            email="bar.foo@example.com",
            **hash_new_password(
                password_plaintext="Password123",
            ),
        )
        session.add(user_1)
        session.add(user_2)

    async with AsyncSession(engine) as session:
        statement = select(User).where(User.username_lc == "foobar")
        for user in await session.exec(statement):
            print(f'User {user.username}, password test: {user.test_password("Password123")}')



if __name__ == "__main__":
    asyncio.run(main())
