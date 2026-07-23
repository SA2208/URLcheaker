# Security Policy

## Supported versions

Only the latest tagged release receives security fixes during the pre-1.0 phase.

## Reporting

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting after the repository is published. Include affected versions, reproduction steps, impact, and a minimal proof of concept.

## Security boundaries

URLCHEAKER's synchronous classification path must not resolve or fetch a submitted URL. A pull request that introduces outbound access in this path requires a new threat model, network sandbox, redirect revalidation, private-address blocking, DNS-rebinding controls, response limits, and explicit security approval.

## Model artifacts

Python model artifacts can execute code during deserialization. Production systems must load only internally built, checksum-verified, signed artifacts from read-only storage. User-uploaded models are prohibited.
