---
step_id: bb.stage4.zap_walkthrough
procedure: bb
stage: stage4
title: OWASP ZAP Active Scan (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Download OWASP ZAP from zaproxy.org (free, open-source).

Launch ZAP. On the quick-start screen, enter the target URL and click "Automated Scan".

ZAP will first spider (crawl) the application to discover all pages and forms, then run the active scanner against all discovered endpoints.

For a more controlled approach: Tools > Spider to crawl first, then Active Scan > right-click target > Attack > Active Scan.

Wait for the scan to complete. Review the Alerts tab for findings.

Findings are categorised by risk level: High, Medium, Low, Informational.

For each High and Medium finding, note: the alert name, URL affected, parameter affected, evidence, and ZAP's solution suggestion.

Export the full report: Report > Generate Report > select HTML or JSON format.
