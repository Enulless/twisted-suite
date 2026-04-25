---
step_id: bb.stage1.crtsh
procedure: bb
stage: stage1
title: Certificate Transparency Log Harvesting
estimated_minutes: 8
---

## What We Are Doing

Certificate Transparency (CT) logs are public, append-only records of every SSL/TLS certificate issued by a Certificate Authority. When a company secures a subdomain with an SSL certificate, that certificate is permanently logged in CT databases accessible to anyone.

## Why

Development teams frequently spin up staging environments, test APIs, or temporary projects using SSL certificates without coordinating with the security team. When the project ends, the DNS record may be removed but the certificate remains in CT logs permanently. Acquisitions also introduce entirely separate domain namespaces that may not have been fully audited. Each forgotten subdomain is a potential attack vector.

## How

Navigate to crt.sh in a web browser.

In the search field, enter the client's primary domain preceded by a percentage sign, for example: %.example.com

The percentage sign is a wildcard that matches any subdomain. The results return every certificate ever issued for that domain and all subdomains.

Examine the Common Name (CN) and Subject Alternative Name (SAN) fields in the results. These list every domain covered by each certificate.

Export results by appending ?output=json to the URL and saving the response, or manually copy the subdomain list.

Perform the same search on Censys.io: navigate to censys.io, select Certificates, and search for: parsed.names:example.com

Cross-reference results from both sources. Add every unique subdomain to the master spreadsheet with the source noted as "crt.sh" or "Censys CT".
