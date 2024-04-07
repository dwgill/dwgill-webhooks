import asyncio
import datetime as dt
from enum import StrEnum
from typing import Mapping, Optional, TypeAlias, cast
from pydantic import field_validator
from app.hashing import (
    test_secret_plaintext_against_hash, hash_new_secret
)
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import Field, SQLModel, func, JSON
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
import sqlalchemy.orm.attributes
from uuid import uuid4, UUID
import env

PermissionMapping: TypeAlias = Mapping[str, str | Mapping[str, str]]

class ClientType(StrEnum):
    Webhook = 'webhook'

class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True, allow_mutation=False)
    active: bool = Field(default=True)
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
    public_id: UUID = Field(default_factory=uuid4, allow_mutation=False)
    display_name: str = Field()
    secret_hash: str = Field()
    secret_salt: str = Field()
    secret_version: int = Field()

    permissions: PermissionMapping = Field(
        default_factory=lambda: {},
        sa_type=PG_JSONB if env.database_connection_type() == "postgresql" else JSON
    )

    client_type: ClientType = Field()

    @classmethod
    def permissions_comp(cls):
        return cast(
            sqlalchemy.orm.attributes.InstrumentedAttribute[PermissionMapping],
            cls.permissions,
        ).comparator

    def test_secret(self, secret_plaintext: str) -> bool:
        return test_secret_plaintext_against_hash(
            secret_plaintext=secret_plaintext,
            secret_hash=self.secret_hash,
            secret_salt=self.secret_salt,
            secret_version=self.secret_version,
        )

    @field_validator("updated_datetime", "created_datetime")
    @classmethod
    def _validate_datetimes(cls, value: dt.datetime):
        if value.tzinfo is not None:
            return value.astimezone(dt.timezone.utc)
        else:
            return value.combine(value.date(), value.time(), dt.timezone.utc)


async def main():
    engine = create_async_engine(env.database_connection_string(), echo=True)

    async with engine.begin() as conn:
        await conn.run_sync(Client.metadata.drop_all)
        await conn.run_sync(Client.metadata.create_all)

    async with AsyncSession(engine) as session, session.begin():
        client = Client(
            display_name="Test Client",
            **hash_new_secret(
                secret_plaintext="Hello World"
            ),
            client_type=ClientType.Webhook,
        )

        session.add(client)


if __name__ == "__main__":
    asyncio.run(main())
