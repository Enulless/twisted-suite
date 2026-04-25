---
step_id: bb.stage1.censys_walkthrough
procedure: bb
stage: stage1
title: Censys Certificate Search (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

SSL/TLS certificates secure encrypted communications between clients and servers. Certificate analysis reveals cryptographic strength, validity periods, issuance details, and — critically — subject alternative names that expose additional infrastructure. Weak or expired certificates indicate neglected infrastructure.

## How

For each prioritised subdomain, run: openssl s_client -connect subdomain.example.com:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -noout -text

From the output, document: Subject (primary domain), Issuer (certificate authority), Public Key (bit strength), Not Before (issue date), Not After (expiry date), Subject Alternative Names (all covered domains).

For a quick validity date check: echo | openssl s_client -servername subdomain.example.com -connect subdomain.example.com:443 2>/dev/null | openssl x509 -noout -dates

To extract just the SAN field: openssl s_client -connect subdomain.example.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

Flag any certificate with: 1024-bit or weaker key, self-signed issuer, expiry date within 90 days, expiry date in the past, SAN entries not previously discovered.

openssl s_client -connect subdomain.example.com:443 -showcerts < /dev/null 2>/dev/null | openssl x509 -noout -text

echo | openssl s_client -servername subdomain.example.com -connect subdomain.example.com:443 2>/dev/null | openssl x509 -noout -dates

## What To Look For In Certificates

Key Strength: 1024-bit RSA is cryptographically broken and exploitable. 2048-bit RSA is the current minimum standard. 4096-bit or ECDSA P-256 are stronger alternatives. Any certificate with fewer than 2048-bit RSA is a finding.

Certificate Issuer: Let's Encrypt certificates are legitimate and free. Self-signed certificates indicate development or internal infrastructure that has been publicly exposed. Unknown or untrusted issuers may indicate compromised or shadow infrastructure.

Validity Dates: Certificates expiring within 30 days suggest neglected infrastructure. Expired certificates indicate completely abandoned services — a server running on an expired certificate has likely not been updated or monitored.

Subject Alternative Names: The SAN field lists every domain the certificate covers. A certificate for staging-api.example.com might also cover dev-api.example.com and internal-api.example.com, revealing infrastructure not found in other sources.
