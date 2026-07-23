# Architecture

## Components

1. `web`: React analyst interface served by unprivileged Nginx.
2. `urlchecker.main`: FastAPI entry point and middleware.
3. `url_normalizer`: strict parsing, IDNA conversion, default-port normalization, fragment removal, and registrable-domain extraction.
4. `feed_store`: exact normalized-URL hash matching against local snapshots.
5. `features`: deterministic numerical lexical features.
6. `model_service`: heuristic development backend or trusted PyCaret artifact.
7. `decision_policy`: feed precedence and malicious/benign/uncertain thresholds.
8. `database`: analysis history and analyst verdict persistence.
9. `ml/pipelines`: dataset validation and grouped model training.

## Data flow

```text
POST URL
  -> request validation
  -> strict normalization
  -> exact feed lookup
  -> deterministic features
  -> model probability
  -> decision policy
  -> query-value redaction
  -> transactional database write
  -> JSON response
```

## Trust boundaries

- Browser input is untrusted.
- Threat-feed snapshots are untrusted until schema and checksum verification.
- Serialized model artifacts are executable and must be trusted and signed.
- Production secrets are external to the repository.
- PostgreSQL is not exposed to the frontend network.
- The API has no intended outbound network requirement during classification.

## Availability behavior

- Missing feed file: continue in model-only degraded capability.
- Model load failure: startup fails when PyCaret mode is explicitly requested.
- Database unavailable: readiness and analysis persistence fail; do not return unlogged security decisions as successful.
- Uncertain probability: return `uncertain`, not `benign`.
