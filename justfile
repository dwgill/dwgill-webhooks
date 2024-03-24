set positional-arguments
export PYTHONPATH := justfile_directory()
export ENV_FILE_PATH := justfile_directory() / '.env'

SECRET_KEY_PATH := env_var_or_default('SECRET_KEY_PATH', justfile_directory() / '..' / 'secret.key')

_help:
    just --list

_ensure_env_file:
    touch "$PWD/.env"

models: _ensure_env_file
    poetry run python -m app.models

secrets *ARGS: _ensure_env_file
    poetry run python -m app.secrets "$@"

decrypt-env ENCRYPTED_ENV_FILE='./env.dev.enc' PLAINTEXT_ENV_FILE=ENV_FILE_PATH:
    just crypt 'decrypt' '{{ENCRYPTED_ENV_FILE}}' '{{PLAINTEXT_ENV_FILE}}' '{{SECRET_KEY_PATH}}'

encrypt-env ENCRYPTED_ENV_FILE='./env.dev.enc' PLAINTEXT_ENV_FILE=ENV_FILE_PATH:
    just crypt 'encrypt' '{{PLAINTEXT_ENV_FILE}}' '{{ENCRYPTED_ENV_FILE}}' '{{SECRET_KEY_PATH}}'

new-env-encryption-key KEY_PATH:
    just crypt 'new-key' '{{KEY_PATH}}'

crypt *ARGS:
    poetry run python -m scripts.crypt "$@"

