# Test Strategy

## Backend

- Unit: normalization, IDNA, feature values, decision policy, signature verification.
- Integration: API, database, feed lookup, history, verdict workflow, headers.
- Property testing: arbitrary strings must not crash URL validation.
- Regression: previously observed false positives and false negatives.

## Frontend

- Unit: form validation and component states.
- Integration: API error handling and result rendering.
- End-to-end: submit, inspect, store, and verdict workflow.
- Accessibility: keyboard navigation and automated WCAG checks.

## ML

- Required columns and valid labels.
- Canonical URL conflict detection.
- Domain overlap detection.
- Reproducible seed.
- Calibration and threshold tests.
- Serialization/loading compatibility.
- Temporal and source-held-out metrics.

## Security

- Unsupported schemes.
- User-info URLs.
- IPv4 and IPv6 representations.
- Unicode and punycode.
- Null and control characters.
- Nested encoded URLs.
- Excessive URL length.
- XSS payloads rendered as text.
- Confirmation that classification performs no DNS/HTTP access.
