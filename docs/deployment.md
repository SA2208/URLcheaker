# Deployment and Rollback

## Production prerequisites

- External secret manager
- TLS termination
- Managed PostgreSQL backups
- Shared rate limiter or API gateway
- Centralized logs with URL-value redaction
- Signed container and model artifacts
- Vulnerability and SBOM scanning
- Authentication and RBAC for analyst verdicts

## Deployment

1. Build immutable API and web images.
2. Scan images and dependencies.
3. Verify model HMAC and metadata.
4. Apply database migrations.
5. Deploy to staging.
6. Run smoke, security, and model compatibility tests.
7. Deploy production with a pinned image digest.
8. Verify health, error rate, and classification distribution.

## Rollback

- Application: redeploy the prior signed image digest.
- Model: restore the prior model alias/path and restart API replicas.
- Database: prefer backward-compatible migrations; use tested downgrade only when data loss is understood.
- Feed: restore the most recent verified snapshot and record its age.

A failed model load must fail startup rather than silently selecting an unapproved fallback in production PyCaret mode.
