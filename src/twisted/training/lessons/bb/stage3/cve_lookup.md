---
step_id: bb.stage3.cve_lookup
procedure: bb
stage: stage3
title: NVD CVE Cross-Reference
estimated_minutes: 8
---

## What We Are Doing

For each detected technology and version in the master spreadsheet, navigate to nvd.nist.gov (National Vulnerability Database).

Search for the technology name and version, for example: "Apache 2.4.41"

Review all matching CVEs. Note the CVE ID, CVSS score, and a brief description of the vulnerability.

Alternatively, use cvedetails.com which organises CVEs by vendor and product with version filtering.

For automated CVE lookup, use the NVD API: curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache%202.4.41&keywordExactMatch"

Document applicable CVEs in the master spreadsheet under the "Known CVEs" column.

curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache%202.4.41"
