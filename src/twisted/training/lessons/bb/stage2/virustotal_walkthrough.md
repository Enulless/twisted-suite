---
step_id: bb.stage2.virustotal_walkthrough
procedure: bb
stage: stage2
title: VirusTotal historical IPs (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

VirusTotal maintains historical DNS resolution records showing every IP address a domain has ever resolved to, along with when those resolutions occurred. This reveals infrastructure migration history and may uncover old servers that are still live but no longer actively maintained.

## Why

When a company migrates its web application from one server to another, the old server is often forgotten. If the old server is still running, it may have the same application deployed but on an older, unpatched version. It may not have the same firewall rules as the new server. It may still have old credentials, test accounts, or debugging features enabled. Historical DNS data reveals these forgotten servers.

## How

Navigate to virustotal.com and create a free account.

In the search bar, enter the primary domain: example.com

Click the "Relations" tab on the domain analysis page.

Under "Resolutions", review the history of IP addresses this domain has pointed to, along with the dates.

For each historical IP that differs from the current A record, note it in the master spreadsheet with the resolution dates.

Navigate to each historical IP directly in VirusTotal by searching the IP address. Review what other domains have resolved to that IP, what security flags if any exist, and what ports or services have been observed.

Repeat for each subdomain in your inventory.

Flag any historical IPs with security warnings or that resolved from high-priority subdomains (staging, dev, admin) as targets for Stage Three investigation.
