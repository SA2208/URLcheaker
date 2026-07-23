.PHONY: install dev test lint security api web docker-up docker-down train validate-data

install:
	python -m pip install -e ".[dev]"
	cd web && npm install

dev:
	docker compose up --build

test:
	pytest --cov=src/urlchecker --cov-report=term-missing
	cd web && npm test -- --run

lint:
	ruff check .
	ruff format --check .
	mypy src
	cd web && npm run lint

security:
	bandit -c pyproject.toml -r src
	pip-audit
	cd web && npm audit --audit-level=high

api:
	uvicorn urlchecker.main:app --reload --host 127.0.0.1 --port 8000

web:
	cd web && npm run dev

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

train:
	python ml/pipelines/train_pycaret.py --dataset data/sample_urls.csv --output ml/models/urlchecker_pycaret

validate-data:
	python ml/pipelines/validate_dataset.py --dataset data/sample_urls.csv
