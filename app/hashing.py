from typing import Literal, TypeAlias, TypeGuard, TypedDict
import base64
import hashlib
import secrets

SecretVersion: TypeAlias = Literal[1]

latest_secret_version: SecretVersion = 1


class UnknownSecretVersion(ValueError):
    def __init__(self, invalid_version: int) -> None:
        self.invalid_version = invalid_version
        super().__init__(f"Unknown secret version: {invalid_version}")


def validate_secret_version(secret_version: int) -> TypeGuard[SecretVersion]:
    return secret_version == latest_secret_version


class SecretHashDetails(TypedDict):
    secret_hash: str
    secret_salt: str
    secret_version: SecretVersion


def new_salt(*, secret_version: int) -> str:
    if not validate_secret_version(secret_version):
        raise UnknownSecretVersion(secret_version)

    match secret_version:
        case 1:
            return secrets.token_urlsafe(20)
        case _:
            raise UnknownSecretVersion(secret_version)


def hash_new_secret(
    *,
    secret_plaintext: str,
    secret_version: int = latest_secret_version,
) -> SecretHashDetails:
    if not validate_secret_version(secret_version):
        raise UnknownSecretVersion(secret_version)

    secret_salt = new_salt(secret_version=secret_version)
    secret_hash = hash_secret(
        secret_plaintext=secret_plaintext,
        secret_salt=secret_salt,
        secret_version=secret_version,
    )
    return {
        "secret_hash": secret_hash,
        "secret_salt": secret_salt,
        "secret_version": secret_version,
    }


def test_secret_plaintext_against_hash(
    *,
    secret_plaintext: str,
    secret_hash: str,
    secret_salt: str,
    secret_version: int,
) -> bool:
    """
    Compare the secret_plaintext against the secret_hash
    according to the secret_salt and secret_version,
    returning True if they match.
    """

    return secret_hash == hash_secret(
        secret_plaintext=secret_plaintext,
        secret_salt=secret_salt,
        secret_version=secret_version,
    )


def hash_secret(
    *,
    secret_plaintext: str,
    secret_salt: str,
    secret_version: int,
) -> str:
    if not validate_secret_version(secret_version):
        raise UnknownSecretVersion(secret_version)

    match secret_version:
        case 1:
            return _hash_secret_v1(
                secret_plaintext=secret_plaintext,
                secret_salt=secret_salt,
            )
        case _:
            raise UnknownSecretVersion(secret_version)


def _hash_secret_v1(
    *,
    secret_plaintext: str,
    secret_salt: str,
) -> str:
    # reference: https://stackoverflow.com/a/76446925
    raw_hash_bytes = hashlib.scrypt(
        password=secret_plaintext.encode(),
        salt=secret_salt.encode(),
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    hash_b64_bytes = base64.b64encode(raw_hash_bytes)
    hash_b64_str = hash_b64_bytes.decode("utf-8")
    return hash_b64_str


def _cli_main():
    import argparse

    parser = argparse.ArgumentParser(description="CLI for secret hashing and testing")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # New command
    new_parser = subparsers.add_parser("new", help="Generate a new hashed secret")
    new_parser.add_argument("plaintext_secret", type=str, help="Plaintext secret")
    new_parser.add_argument("--version", type=int, default=1, help="Secret version")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test a hashed secret")
    test_parser.add_argument("plaintext_secret", type=str, help="Plaintext secret")
    test_parser.add_argument("hashed_secret", type=str, help="Hashed secret")
    test_parser.add_argument("salt", type=str, help="Salt")
    test_parser.add_argument("--version", type=int, default=1, help="Secret version")

    args = parser.parse_args()

    command: Literal["new", "test"] = args.command

    match command:
        case "new":
            plaintext_secret: str = args.plaintext_secret
            secret_version: int = args.version
            secret_details = hash_new_secret(
                secret_plaintext=plaintext_secret, secret_version=secret_version
            )
            print("Hashed secret:", secret_details["secret_hash"])
            print("Salt:", secret_details["secret_salt"])
            print("Version:", secret_details["secret_version"])
        case "test":
            plaintext_secret: str = args.plaintext_secret
            hashed_secret: str = args.hashed_secret
            salt: str = args.salt
            secret_version: int = args.version
            result = test_secret_plaintext_against_hash(
                secret_plaintext=plaintext_secret,
                secret_hash=hashed_secret,
                secret_salt=salt,
                secret_version=secret_version,
            )
            print("Result:", result)
            print("Version:", secret_version)
        case _:
            parser.print_help()

if __name__ == "__main__":
    _cli_main()
