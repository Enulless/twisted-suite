---
step_id: bb.stage1.whois
procedure: bb
stage: stage1
title: WHOIS Registrar Intelligence
estimated_minutes: 8
---

## What We Are Doing

WHOIS databases contain registration information about domain names including registrant contact details, registrar information, creation and expiry dates, and associated nameservers. This data is publicly available and reveals infrastructure relationships and ownership details.

## How

Run a WHOIS query for the primary domain: whois example.com

Document the registrar name, creation date, expiry date, nameservers listed, and any registrant contact information that is publicly available.

Note the expiry date. Domains expiring within 60 days may indicate neglected infrastructure. Domains that recently changed registrar may indicate acquisitions or migrations.

Search for related domains. If the client's primary domain is example.com, query example.net, example.org, and example.io. Companies often register variants to protect their brand. These may have different security postures.

Document all findings in the master spreadsheet with source noted as "WHOIS".

whois example.com
