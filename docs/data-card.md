# Dataset Card

## Bundled dataset

`data/sample_urls.csv` contains synthetic URLs under reserved documentation domains and TEST-NET IP space. Its purpose is to verify parsing, feature extraction, grouped splitting, and PyCaret pipeline execution.

It must not be used to claim operational accuracy.

## Required production fields

- `url`
- `label`
- `source`
- `source_record_id`
- `first_seen`
- `last_seen`
- `verified`
- `acquired_at`
- `snapshot_id`
- `license`
- `raw_sha256`

## Label policy

- `malicious`: authoritative verified record or multiple independent corroborating sources.
- `benign candidate`: independently observed legitimate URL absent from all collected malicious snapshots.
- `unknown`: conflicts, incomplete evidence, malformed record, or uncertain disposition.

Unknown records are excluded from binary training.

## Split policy

- No canonical URL overlap.
- No registrable-domain overlap in grouped benchmark splits.
- A separate later-time test set is mandatory.
- At least one source-holdout evaluation is mandatory.

## Known biases

- Feeds observe reported threats, not all threats.
- Popular-domain samples overrepresent high-traffic sites.
- Older datasets may encode obsolete campaign patterns.
- Provider-specific formatting can become an unintended shortcut.
