# SOC URL Triage Playbook

## Inputs

- URLCHEAKER classification
- Threat-feed evidence
- Lexical indicators
- Source email, proxy, EDR, DNS, or SIEM event
- Approved external enrichment tools

## Procedure

1. Confirm the submitted URL exactly matches the originating event.
2. Review exact threat-feed matches first.
3. Treat model output as prioritization, not proof.
4. For malicious or uncertain results, investigate domain age, DNS, TLS, redirects, hosting, and page content only through approved isolated systems.
5. Identify affected users, endpoints, messages, and network sessions.
6. Search telemetry for related domains, URL paths, hashes, sender infrastructure, and process execution.
7. Escalate confirmed credential theft, malware delivery, or active compromise under the incident-response procedure.
8. Record an analyst verdict and concise evidence.

## Suggested severities

| Condition | Initial severity |
|---|---|
| Exact active malware/phishing feed match plus user interaction | High |
| High-confidence model result with corroborating telemetry | Medium/High |
| Uncertain model result with no corroboration | Informational/Review |
| Benign candidate with conflicting external evidence | Escalate external evidence |

## False-positive handling

- Do not globally allow-list a domain from one URL verdict.
- Record the exact normalized URL and observed context.
- Determine whether the feature, label, source, or threshold caused the error.
- Add the case to a versioned regression corpus.
