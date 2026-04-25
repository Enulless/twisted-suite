---
step_id: bb.stage3.headers_audit
procedure: bb
stage: stage3
title: Security Headers Audit
estimated_minutes: 8
---

## What We Are Doing

HTTP headers are metadata returned by a web server in response to every request. They contain information about the server software, backend language, security configurations, and sometimes developer mistakes that inadvertently expose infrastructure details. We use curl to retrieve these headers passively without loading the full page.

## How

For each prioritised subdomain from Stage Two, run: curl -I https://subdomain.example.com

The -I flag sends an HTTP HEAD request, retrieving only headers without downloading page content.

Document every header returned. Note the exact value, not just whether it is present.

For each of the following headers, note "Present" with the value or "MISSING": Server, X-Powered-By, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Set-Cookie attributes.

Run the verbose flag for additional details: curl -v https://subdomain.example.com 2>&1 | head -50

Some servers reveal version information in the verbose output that is suppressed in standard headers.

Try connecting over plain HTTP as well: curl -I http://subdomain.example.com — if the server responds with HTTP instead of redirecting to HTTPS, that is a finding.

curl -I https://subdomain.example.com

curl -v https://subdomain.example.com 2>&1 | head -50

curl -I http://subdomain.example.com

## Key Security Headers To Evaluate

Server: Reveals the web server type and version. "Server: Apache/2.4.41" identifies the exact version for CVE lookup. Some servers are configured to suppress this header.

X-Powered-By: Reveals the backend technology. "X-Powered-By: PHP/7.2.26" exposes an outdated, end-of-life PHP version.

X-Frame-Options: Controls whether the page can be loaded in an iframe. Missing this header makes the site vulnerable to clickjacking attacks where an attacker frames the page inside a malicious site to steal clicks.

Content-Security-Policy (CSP): Defines which sources of content the browser should trust. A missing or weak CSP policy leaves the site vulnerable to Cross-Site Scripting (XSS) attacks.

Strict-Transport-Security (HSTS): Forces browsers to use HTTPS for future connections. Missing HSTS enables SSL stripping attacks that downgrade connections to unencrypted HTTP.

X-Content-Type-Options: When set to "nosniff", prevents browsers from guessing the MIME type of responses. Missing this allows MIME-sniffing attacks.

Set-Cookie: Cookie attributes reveal session management security. Missing Secure flag means session cookies can be transmitted over HTTP. Missing HttpOnly flag means JavaScript can read session cookies (XSS risk). Missing SameSite attribute enables Cross-Site Request Forgery (CSRF) attacks.

## Example Analysis

A curl request returns: Server: Apache/2.4.41, X-Powered-By: PHP/7.2.26, no X-Frame-Options header, no Content-Security-Policy header, no Strict-Transport-Security header. This single header check has identified: an Apache version with known CVEs, PHP 7.2 which reached end-of-life in November 2019 and has multiple remote code execution vulnerabilities, three missing security headers enabling clickjacking, XSS, and SSL stripping attacks respectively. That is a minimum of five findings from a one-second command.
