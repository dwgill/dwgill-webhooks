import os
import functools
from typing import Callable, Literal, overload
from sqlalchemy.engine.url import make_url
from .secrets import new_salt

_MISSING_VALUE = new_salt(secret_version=1)


@overload
def _get_env_var[
    T
](key: str, *, coerce: Callable[[str], T] = str,) -> T: ...


@overload
def _get_env_var[
    T
](key: str, default: str, *, coerce: Callable[[str], T] = str,) -> T: ...


def _get_env_var[
    T
](key: str, default: str | None = None, *, coerce: Callable[[str], T] = str,) -> T:
    str_value = os.environ.get(key, _MISSING_VALUE)

    if str_value == _MISSING_VALUE:
        if default is None:
            raise MissingEnvVarError(key)
        else:
            str_value = default

    try:
        return coerce(str_value)
    except (ValueError, TypeError) as e:
        raise InvalidEnvVarError(key, str_value) from e


@functools.lru_cache(1)
def database_connection_string() -> str:
    def coerce_connection_string(db_url: str):
        try:
            make_url(db_url)
        except Exception as e:
            raise InvalidEnvVarError("DATABASE_CONNECTION_STRING", db_url) from e
        return db_url

    return _get_env_var("DATABASE_CONNECTION_STRING", coerce=coerce_connection_string)

@functools.lru_cache(1)
def database_connection_type() -> Literal["sqlite", "postgresql"]:
    connection_string = database_connection_string()

    if connection_string.startswith("sqlite"):
        return "sqlite"
    elif connection_string.startswith("postgresql"):
        return "postgresql"
    else:
        raise ValueError(f"Unsupported database connection string type: {connection_string}")


def _surround_with_quotes(string: str) -> str:
    if '"' in string:
        return f"'{string}'"
    elif "'" in string:
        return f'"{string}"'
    else:
        return f'''"""{string}"""'''


class MissingEnvVarError(ValueError):
    def __init__(self, env_var_name: str) -> None:
        self.env_var_name = env_var_name
        self.message = (
            f"Missing environment variable: {_surround_with_quotes(env_var_name)}"
        )

        super().__init__(self.message)


class InvalidEnvVarError(ValueError):
    def __init__(self, env_var_name: str, env_var_value: str) -> None:
        self.env_var_name = env_var_name
        self.env_var_value = env_var_value
        self.message = f"Invalid environment variable: {_surround_with_quotes(env_var_name)} = {_surround_with_quotes(env_var_value)}"

        super().__init__(self.message)