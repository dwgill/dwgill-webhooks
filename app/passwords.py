import hashlib
import secrets
from typing import Literal, Optional, TypeAlias, TypeGuard, TypedDict
import base64

PasswordVersion: TypeAlias = Literal[1]

latest_password_version: PasswordVersion = 1


class UnknownPasswordVersion(ValueError):
    def __init__(self, invalid_version: int) -> None:
        self.invalid_version = invalid_version
        super().__init__(f"Unknown password version: {invalid_version}")


def validate_password_version(password_version: int) -> TypeGuard[PasswordVersion]:
    return password_version == latest_password_version


class HashDetails(TypedDict):
    password_hash: str
    password_salt: str
    password_version: PasswordVersion


def new_salt(*, password_version: int) -> str:
    if not validate_password_version(password_version):
        raise UnknownPasswordVersion(password_version)

    match password_version:
        case 1:
            return secrets.token_urlsafe(20)
        case _:
            raise UnknownPasswordVersion(password_version)


def hash_new_password(
    *,
    password_plaintext: str,
    password_version: int = latest_password_version,
) -> HashDetails:
    if not validate_password_version(password_version):
        raise UnknownPasswordVersion(password_version)

    password_salt = new_salt(password_version=password_version)
    password_hash = hash_password(
        password_plaintext=password_plaintext,
        password_salt=password_salt,
        password_version=password_version,
    )
    return {
        "password_hash": password_hash,
        "password_salt": password_salt,
        "password_version": password_version,
    }


def test_password_plaintext_against_hash(
    *,
    password_plaintext: str,
    password_hash: str,
    password_salt: str,
    password_version: int,
) -> bool:
    """
    Compare the password_plaintext against the password_hash
    according to the password_salt and password_version,
    returning True if they match.
    """

    return password_hash == hash_password(
        password_plaintext=password_plaintext,
        password_salt=password_salt,
        password_version=password_version,
    )


def hash_password(
    *,
    password_plaintext: str,
    password_salt: str,
    password_version: int,
) -> str:
    if not validate_password_version(password_version):
        raise UnknownPasswordVersion(password_version)

    match password_version:
        case 1:
            return _hash_password_v1(
                password_plaintext=password_plaintext,
                password_salt=password_salt,
            )
        case _:
            raise UnknownPasswordVersion(password_version)


def _hash_password_v1(
    *,
    password_plaintext: str,
    password_salt: str,
) -> str:
    # reference: https://stackoverflow.com/a/76446925
    raw_hash_bytes = hashlib.scrypt(
        password=password_plaintext.encode(),
        salt=password_salt.encode(),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    hash_b64_bytes = base64.b64encode(raw_hash_bytes)
    hash_b64_str = hash_b64_bytes.decode("utf-8")
    return hash_b64_str
