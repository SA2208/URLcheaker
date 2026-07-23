# Model Card

## Development backend

The default `heuristic` backend is a deterministic logistic score over lexical features. It exists for end-to-end development and must not be represented as a trained security model.

## Production candidate

The PyCaret training pipeline compares classification estimators, tunes the leading candidate, applies sigmoid calibration, and evaluates a registrable-domain-held-out test set.

## Inputs

Only deterministic lexical features derived from the normalized URL. No page content, DNS, WHOIS, TLS, or redirect behavior is included.

## Outputs

- Malicious probability in `[0, 1]`
- Version and backend identifier
- Policy classification: malicious, benign, or uncertain

## Prohibited claims

- A benign classification proves safety.
- Feature importance establishes causation.
- Results from the synthetic bundled dataset represent real-world accuracy.

## Promotion gates

- Complete provenance and license review
- Domain leakage check
- Temporal holdout
- External source holdout
- Malicious recall and false-positive targets
- Calibration evaluation
- Adversarial corpus evaluation
- Artifact signature and checksum
- Manual technical, QA, and SOC approval
