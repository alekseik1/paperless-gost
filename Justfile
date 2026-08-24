set dotenv-load := true

default:
    @just --list

help:
    @just --list

install:
    uv sync --locked --all-groups

lint:
    uv run ruff check src tests
    uv run ruff format --check src tests

typecheck:
    uv run ty check src

test *args:
    uv run pytest {{args}}

build:
    uv build

ci: lint typecheck test build
