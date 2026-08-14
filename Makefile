.PHONY: install format lint test typecheck check docker-build run

install:
	python -m pip install -e '.[dev]'

format:
	ruff format src tests

lint:
	ruff check src tests

test:
	pytest

typecheck:
	mypy src

check: lint test typecheck

docker-build:
	docker build -t mobsf-mcp:local .

run:
	mobsf-mcp
