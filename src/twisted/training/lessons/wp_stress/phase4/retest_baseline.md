---
step_id: wp_stress.phase4.retest_baseline
procedure: wp_stress
stage: phase4
title: Re-test baseline after remediation
estimated_minutes: 8
---

## Why

Finding vulnerabilities without remediating them provides no security value. This phase closes the loop: every weakness identified is mapped to a concrete fix, the fix is implemented, and a targeted re-test confirms the issue is resolved.

## How

The before/after evidence set is your proof of remediation. It documents what was vulnerable, what was changed, and that the fix was effective. Retain this record for your own audit trail.

## What to Collect

Finding inventory spreadsheet with severity, status, and fix notes

Before/after curl header dumps proving header fixes

Before/after WPScan outputs showing plugin CVEs resolved

Re-test ab/wrk output showing improved error rate and latency

Securityheaders.com grade screenshot (before and after)

## 4 3 Remediation Steps

Build the finding inventory

a. Merge all findings from WPScan, Nikto, ZAP, and the stress test error logs into a single spreadsheet.

b. Assign severity, status (Open / In Progress / Closed), and owner for each finding.

Apply critical and high fixes first

a. Restrict sensitive file access via .htaccess or NGINX deny rules.

b. Update all plugins and themes. Remove unused ones entirely.

c. Disable XML-RPC if not in use: add deny from all rule for /xmlrpc.php.

d. Remove server version disclosure from Apache/NGINX and PHP headers.

Implement rate limiting and brute-force protection

a. Install Wordfence (free tier) or configure fail2ban with the wp-login jail.

b. Set: max login attempts = 5, lockout duration = 30 minutes.

c. Consider Cloudflare free tier for Layer 7 rate limiting and DDoS protection.

Add missing security headers

a. For Apache — add to .htaccess or VirtualHost:

b. Header always set X-Frame-Options SAMEORIGIN

c. Header always set X-Content-Type-Options nosniff

d. Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'

e. Header always set X-XSS-Protection '1; mode=block'

Performance hardening to raise the DoS threshold

a. Enable object caching: install Redis or Memcached + a WordPress cache plugin.

b. Enable page caching: WP Super Cache or W3 Total Cache.

c. Tune PHP-FPM pool: set pm.max_children based on available RAM.

d. Optimize MySQL: add indexes on wp_postmeta, increase innodb_buffer_pool_size.

e. Configure NGINX or Apache to limit request rates at the server level.

Re-test to verify fixes

a. Repeat the specific ab/wrk round that first produced errors. Confirm error rate is now below 1%.

b. Re-run WPScan and Nikto. Confirm previous HIGH/CRITICAL findings no longer appear.

c. Re-run curl header checks. Confirm version strings are removed and security headers are present.

d. Check securityheaders.com against your domain for an independent header grade.
