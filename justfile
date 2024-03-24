set positional-arguments

models:
    DATABASE_CONNECTION_STRING='sqlite+aiosqlite:///./database.db' PYTHONPATH="$(pwd)" poetry run python -m app.models

secrets *args='':
    PYTHONPATH="$$PWD" poetry run python -m app.secrets "$@"
