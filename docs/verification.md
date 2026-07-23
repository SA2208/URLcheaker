# Verification Report

Verification date: 2026-07-23

## Completed checks

- Python source compilation: passed.
- Backend tests: 21 passed.
- URL normalization and IDNA tests: passed.
- Unsupported-scheme and control-character tests: passed.
- Threat-feed precedence tests: passed.
- No-network analysis regression test: passed.
- Query-value redaction and model-HMAC tests: passed.
- API history, verdict, dashboard, and security-header tests: passed.
- Dataset validation: 120 rows, 60 benign, 60 malicious, 120 unique domains, no mixed-label domains.
- Alembic upgrade from base to revision `0001`: passed on SQLite.
- Alembic downgrade from revision `0001` to base: passed on SQLite.
- OpenAPI schema generation: passed.
- JSON and YAML syntax validation: passed.
- TypeScript/TSX syntax transpilation with TypeScript 5.8.3: passed.

## Environment limitations

The execution environment could not complete package downloads from the configured npm and Python package registries. Consequently:

- The full frontend dependency installation, Vitest suite, ESLint run, and Vite production build were not executed locally.
- The PyCaret training job was not executed because the environment did not provide Python 3.11 plus the PyCaret ML dependency set.
- Ruff, mypy, Bandit, and pip-audit were not executed locally after registry access failed.

GitHub Actions workflows are included to run those checks in a normal connected environment. The PyCaret pipeline was compiled, its dataset preparation and temporal/domain split logic were exercised independently, and the runtime API was tested using the heuristic backend.
