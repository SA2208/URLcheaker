# API

## Analyze

```http
POST /api/v1/analyses
Content-Type: application/json

{"url":"https://example.test/account/verify"}
```

## History

```http
GET /api/v1/analyses?page=1&page_size=25&classification=malicious
```

## Analysis

```http
GET /api/v1/analyses/{analysis_id}
```

## Verdict

```http
POST /api/v1/analyses/{analysis_id}/verdicts
Content-Type: application/json

{"verdict":"needs_more_analysis"}
```

## Health

- `/health/live`: process liveness.
- `/health/ready`: initialized service readiness.
- `/api/v1/system/health`: model, dataset, and feed status.
