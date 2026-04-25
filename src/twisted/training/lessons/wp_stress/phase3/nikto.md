---
step_id: wp_stress.phase3.nikto
procedure: wp_stress
stage: phase3
title: Nikto generic web-server scan
estimated_minutes: 8
---

## Why

Under stress, WordPress often becomes more verbose: error pages expose stack traces, PHP version strings leak in headers, database error messages appear inline, and debugging mode (WP_DEBUG) may have been inadvertently left on. Even at idle, automated scanners identify known vulnerable plugin/theme versions, default file exposures, and missing security headers. Understanding what an attacker sees lets you close those windows before they are exploited.

## How

Step 1 — Passive Header Analysis

Collect response headers from key endpoints before and after stress testing:

a. Run: curl -I https://yoursite.com/ and capture full headers.

b. Run: curl -I https://yoursite.com/wp-login.php

c. Run: curl -I https://yoursite.com/wp-admin/admin-ajax.php

d. Note any: Server header (Apache/Nginx version), X-Powered-By (PHP version), missing security headers (X-Frame-Options, CSP, X-Content-Type-Options, Strict-Transport-Security).

Step 2 — WPScan Enumeration

Run WPScan to enumerate the WordPress installation:

a. Plugin enumeration: wpscan --url https://yoursite.com --enumerate p --plugins-detection aggressive

b. Theme enumeration: wpscan --url https://yoursite.com --enumerate t

c. User enumeration: wpscan --url https://yoursite.com --enumerate u

d. WordPress core version: wpscan --url https://yoursite.com --enumerate vp,vt,tt,cb,dbe

e. Save full output: wpscan --url https://yoursite.com -o wpscan_output.txt --format cli-no-colour

Step 3 — Nikto Scan

Run Nikto against the root and sensitive paths:

a. Root scan: nikto -h https://yoursite.com -output nikto_root.txt

b. Admin scan: nikto -h https://yoursite.com/wp-admin/ -output nikto_admin.txt

c. Review for: outdated software, default files, misconfigured CGI, SSL/TLS weaknesses, dangerous HTTP methods (PUT, DELETE, TRACE).

Step 4 — OWASP ZAP Active Scan

Run OWASP ZAP in active scan mode:

a. Launch ZAP GUI. Set scope to yoursite.com.

b. Run the spider against the site to discover all endpoints.

c. Run Active Scan on discovered endpoints.

d. Export the full report as HTML: Report > Generate Report > HTML.

e. Review alerts by risk level: High > Medium > Low > Informational.

Step 5 — Manual Sensitive File Check

Check for commonly exposed files that attackers target:

a. curl -o /dev/null -s -w '%{http_code}' https://yoursite.com/wp-config.php.bak

b. curl -o /dev/null -s -w '%{http_code}' https://yoursite.com/.env

c. curl -o /dev/null -s -w '%{http_code}' https://yoursite.com/debug.log

d. curl -o /dev/null -s -w '%{http_code}' https://yoursite.com/wp-content/debug.log

e. curl -o /dev/null -s -w '%{http_code}' https://yoursite.com/xmlrpc.php

f. A 200 response on any of the above is a critical finding.

Each scanner finding maps to a specific remediation action. WPScan plugin CVEs map to plugin updates or removals. Missing headers map to server config changes. Exposed files map to access control rules. ZAP injection findings map to input validation hardening. All findings feed directly into the remediation matrix in Phase 4.

## What to Collect

curl header dumps for all tested endpoints (headers_[endpoint].txt)

wpscan_output.txt — full WPScan results

nikto_root.txt and nikto_admin.txt

ZAP HTML report (zap_report.html)

List of exposed sensitive files with HTTP response codes

Any error messages, stack traces, or debug output observed under stress (from Phase 2 error logs)
