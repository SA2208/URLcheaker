# URLCHEAKER

URLCHEAKER is a defensive, SOC-oriented URL triage application. It combines exact threat-feed matching with deterministic lexical feature extraction and a pluggable classifier. It returns `malicious`, `benign`, or `uncertain` and never visits the submitted destination in the default analysis path.

> The bundled dataset and heuristic scorer are demonstration assets. They are not evidence of production detection quality. Train and approve a PyCaret model using licensed, versioned, time-aware data before operational use.

## Implemented components

- FastAPI REST API with strict URL validation and normalization.
- Exact-match local threat-feed layer.
- Deterministic lexical feature extraction.
- Explicit uncertainty thresholds.
- PyCaret model loader with optional HMAC artifact verification.
- Privacy-preserving analysis history and analyst verdicts.
- React/TypeScript analyst interface.
- PostgreSQL production profile and SQLite local profile.
- Docker Compose deployment.
- Unit, integration, frontend, adversarial, and CI scaffolding.
- Data validation and grouped PyCaret training pipelines.
- Security, data, model, testing, deployment, and SOC documentation.

## Architecture

```text
Browser -> Nginx -> FastAPI -> URL normalization
                            -> Threat-feed lookup
                            -> Feature extraction
                            -> Heuristic or PyCaret predictor
                            -> Decision policy
                            -> PostgreSQL
```

The API does not perform DNS resolution, HTTP requests, redirects, screenshots, or page rendering. Network enrichment must be implemented as a separately isolated worker.

## Environment

- API: Python 3.11+
- ML training: Python 3.11, PyCaret 3.3.2
- Web: Node.js 24 LTS, React, TypeScript, Vite
- Database: PostgreSQL 17 in Docker; SQLite for local development

## Local backend

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
cp .env.example .env
alembic upgrade head
uvicorn urlchecker.main:app --reload --host 127.0.0.1 --port 8000
```

API documentation is available at `http://127.0.0.1:8000/docs` outside production mode.

## Local frontend

```bash
cd web
npm install
npm run dev
```

The Vite server proxies `/api` and `/health` to `http://127.0.0.1:8000`.

## Docker Compose

```bash
cp .env.example .env
# Replace POSTGRES_PASSWORD in .env with a generated secret before deployment.
docker compose up --build
```

Open `http://localhost:8080`.

## Sample API request

```bash
curl --fail-with-body \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"url":"http://known-malware.test/dropper.exe"}' \
  http://127.0.0.1:8000/api/v1/analyses
```

Representative response:

```json
{
  "classification": "malicious",
  "threat_type": "malware",
  "decision_source": "threat_feed",
  "requires_analyst_review": false
}
```

## CLI

```bash
urlchecker 'https://www.example.com/docs?token=secret'
```

Query values are redacted from stored and returned history by default.

## Testing

```bash
pytest --cov=src/urlchecker --cov-report=term-missing
ruff check .
ruff format --check .
mypy src
bandit -c pyproject.toml -r src

cd web
npm test -- --run
npm run lint
npm run build
```

## PyCaret training

Use a dedicated Python 3.11 environment:

```bash
python3.11 -m venv .venv-ml
source .venv-ml/bin/activate
python -m pip install -e .
python -m pip install -r ml/requirements.txt
python ml/pipelines/validate_dataset.py --dataset data/sample_urls.csv
python ml/pipelines/train_pycaret.py \
  --dataset data/sample_urls.csv \
  --output ml/models/urlchecker_pycaret
```

The training pipeline:

1. Extracts the same features used by production inference.
2. Groups URLs by registrable domain.
3. Creates a domain-held-out test set.
4. Uses grouped cross-validation.
5. Compares, tunes, and calibrates PyCaret models.
6. Writes model metadata and evaluation metrics.

The synthetic sample is only a pipeline smoke test. Production promotion additionally requires temporal and source-holdout evaluation.

Optional DVC and MLflow tooling is separated from the core runtime:

```bash
python -m pip install -r ml/requirements-ops.txt
dvc repro validate_data
dvc repro train
```

## Enable PyCaret inference

```bash
export URLCHECKER_MODEL_BACKEND=pycaret
export URLCHECKER_MODEL_PATH=ml/models/urlchecker_pycaret
export URLCHECKER_MODEL_VERSION=urlchecker-approved-version
```

Serialized Python models are executable artifacts. Load only internally produced artifacts. For HMAC verification:

```bash
export URLCHECKER_MODEL_HMAC_KEY='replace-with-a-secret-at-least-32-characters'
python scripts/sign_model.py ml/models/urlchecker_pycaret.pkl
```

Use a secret manager in production. Do not commit the key or signature workflow secrets.

## Data ingestion policy

`configs/data_sources.yaml` documents candidate sources but disables downloads. Before enabling any collector:

- Review current provider terms and API authentication.
- Record attribution, redistribution, retention, and commercial-use constraints.
- Store immutable snapshots and SHA-256 checksums.
- Remove URL and registrable-domain overlap between training and testing.
- Exclude conflicting or uncertain labels.
- Never assume that popularity proves benignness.

## Security constraints

- Only HTTP and HTTPS input is accepted.
- Embedded credentials are rejected.
- Control characters and invalid IDNA are rejected.
- The default pipeline performs no outbound request.
- URLs are escaped and not rendered as clickable links.
- Query values are redacted from history.
- Production containers run without root privileges and with reduced capabilities.
- The in-memory rate limiter is development-grade; use a gateway or Redis-backed limiter for multiple replicas.

## Repository documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Data card](docs/data-card.md)
- [Model card](docs/model-card.md)
- [Test strategy](docs/testing.md)
- [Verification report](docs/verification.md)
- [Deployment and rollback](docs/deployment.md)
- [SOC playbook](docs/soc-playbook.md)
- [API examples](docs/api.md)

## Limitations

- Lexical signals cannot observe page content or post-redirect behavior.
- Threat feeds have coverage and freshness limitations.
- A low score does not prove safety.
- The heuristic backend is not a trained model.
- The sample threat feed and dataset use reserved demonstration domains.
- Authentication and distributed rate limiting remain release-hardening work for a public multi-user deployment.
