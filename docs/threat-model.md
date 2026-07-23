# Threat Model

## Assets

- Analyst workstation safety
- Submitted URL confidentiality
- Threat-feed integrity
- Model integrity
- Classification audit trail
- Analyst verdicts
- Deployment credentials

## Threat actors

- External attacker submitting crafted URLs
- Adversary attempting SSRF or browser exploitation
- Data-poisoning actor
- Supply-chain attacker
- Unauthorized internal user

## Primary threats and controls

| Threat | Control |
|---|---|
| SSRF | No DNS or HTTP access in synchronous analysis |
| XSS through URL display | React escaping, no HTML injection, CSP, URLs rendered as text |
| Credential leakage in URLs | Embedded credentials rejected; query values redacted |
| Model deserialization attack | Trusted artifacts only, optional HMAC verification, read-only mounts |
| Dataset poisoning | Source provenance, immutable snapshots, conflict handling, manual promotion |
| Train/test leakage | Registrable-domain grouped split and separate temporal evaluation |
| Brute-force resource abuse | Input limit, request limit, reverse-proxy body limit |
| SQL injection | SQLAlchemy parameter binding and typed filters |
| Unauthorized verdict changes | Authentication and RBAC required before public multi-user deployment |
| Dependency compromise | Lock files, CI scanning, Dependabot, SBOM plan |

## Residual risks

- Lexical-only detection can miss compromised legitimate domains.
- Shared hosting can mix benign and malicious paths under one domain.
- The development in-memory rate limiter is not distributed.
- Authentication is not included in the demonstration MVP.
