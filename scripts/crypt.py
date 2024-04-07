from typing import Any, Literal
from cryptography.fernet import Fernet
from pathlib import Path


def new_key_file(*, key_file_path: Path):
    key_content = Fernet.generate_key()
    with open(key_file_path, "wb") as key_file:
        key_file.write(key_content)


def read_key_file(*, key_file_path: Path) -> bytes:
    with open(key_file_path, "rb") as key_file:
        return key_file.read()


def encrypt_file(
    *, plaintext_source_path: Path, encrypted_destination_path: Path, key_bytes: bytes
):
    f = Fernet(key_bytes)
    with plaintext_source_path.open("rb") as plaintext_source_file:
        plaintext_data = plaintext_source_file.read()

    encrypted_data = f.encrypt(plaintext_data)

    with encrypted_destination_path.open("wb") as encrypted_destination_file:
        encrypted_destination_file.write(encrypted_data)


def decrypt_file(
    *, encrypted_source_path: Path, plaintext_destination_path: Path, key_bytes: bytes
):
    f = Fernet(key_bytes)
    with encrypted_source_path.open("rb") as encrypted_source_file:
        encrypted_data = encrypted_source_file.read()

    plaintext_data = f.decrypt(encrypted_data)

    with plaintext_destination_path.open("wb") as plaintext_destination_file:
        plaintext_destination_file.write(plaintext_data)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file")
    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    def existing_path(path: Any) -> Path:
        path_value = Path(path)
        if not path_value.exists() and path_value.is_file():
            raise argparse.ArgumentTypeError(f"{path} is not an existing file")
        return path_value

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument(
        "plaintext_source",
        help="The source plaintext file to encrypt",
        type=existing_path,
    )
    encrypt_parser.add_argument(
        "encrypted_destination",
        help="The destination file to place the encrypted result",
        type=Path,
    )
    encrypt_parser.add_argument(
        "key_file",
        help="The file containing the encryption key",
        type=existing_path,
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument(
        "encrypted_source",
        help="The source encrypted file to decrypt",
        type=existing_path,
    )
    decrypt_parser.add_argument(
        "plaintext_destination",
        help="The destination file to place the decrypted result",
        type=Path,
    )
    decrypt_parser.add_argument(
        "key_file",
        help="The file containing the encryption key",
        type=existing_path,
    )

    new_key_parser = subparsers.add_parser(
        "new-key", help="Generate a new encryption key"
    )
    new_key_parser.add_argument(
        "key_file",
        help="The file to place the new encryption key",
        type=Path,
    )
    new_key_parser.add_argument(
        "--force",
        help="Force overwrite if the key file already exists",
        action="store_true",
    )

    args = parser.parse_args()

    subcommand: Literal["encrypt", "decrypt", "new-key"] = args.subcommand

    match subcommand:
        case "new-key":
            key_file_path: Path = args.key_file
            if key_file_path.exists() and not args.force:
                raise ValueError(
                    f"Key file already exists at {key_file_path.absolute()}"
                )
            new_key_file(key_file_path=key_file_path)
            print(f'Created new key file at "{key_file_path.absolute()}"')
        case "encrypt":
            plaintext_source_file: Path = args.plaintext_source
            encrypted_destination_file: Path = args.encrypted_destination
            key_file_path: Path = args.key_file
            encrypt_file(
                plaintext_source_path=plaintext_source_file,
                encrypted_destination_path=encrypted_destination_file,
                key_bytes=read_key_file(key_file_path=key_file_path),
            )
            print(
                f'Created encrypted file at "{encrypted_destination_file.absolute()}"'
            )
        case "decrypt":
            encrypted_source_file: Path = args.encrypted_source
            plaintext_destination_file: Path = args.plaintext_destination
            key_file_path: Path = args.key_file
            decrypt_file(
                encrypted_source_path=encrypted_source_file,
                plaintext_destination_path=plaintext_destination_file,
                key_bytes=read_key_file(key_file_path=key_file_path),
            )
            print(
                f'Created plaintext file at "{plaintext_destination_file.absolute()}"'
            )
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
