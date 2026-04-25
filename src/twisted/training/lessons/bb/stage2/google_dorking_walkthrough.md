---
step_id: bb.stage2.google_dorking_walkthrough
procedure: bb
stage: stage2
title: Google Advanced Search Operators (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Google indexes far more than just web pages. It caches configuration files, backup files, exposed directory listings, and administrative panels that were accidentally made publicly accessible. Advanced search operators — commonly called "Google Dorking" — allow precise queries to surface this sensitive content.

## Why

A developer who uploads a database backup to a web-accessible directory and does not set proper access controls will have that file indexed by Google within days. Configuration files containing database credentials, API keys, or environment variables that end up in web roots are a common source of critical vulnerabilities. Google Dorking surfaces these without ever touching the target infrastructure.

## How

Open a web browser and navigate to google.com.

Execute the following searches systematically, one at a time. Replace example.com with the client's domain.

Find all indexed subdomains: site:*.example.com

Find administrative interfaces: site:example.com inurl:admin OR inurl:administrator OR inurl:login

Find backup files: site:example.com filetype:sql OR filetype:bak OR filetype:backup

Find configuration files: site:example.com filetype:env OR filetype:config OR filetype:cfg

Find exposed directory listings: site:example.com intitle:"index of"

Find PDF documents: site:example.com filetype:pdf

Find exposed source code: site:example.com filetype:php OR filetype:js OR filetype:py

Document every result URL, the search operator that found it, what the page contains, and why it's significant.

site:*.example.com

site:example.com inurl:admin filetype:php

site:example.com intitle:"index of"

site:example.com filetype:sql

## Core Dorking Operators And Their Purpose

site: restricts results to a specific domain. site:*.example.com searches all subdomains.

inurl: requires the specified string to appear in the URL. inurl:admin finds pages with "admin" in the path.

filetype: restricts results to specific file extensions. filetype:sql finds SQL files.

intitle: requires the string to appear in the page title. intitle:"index of" finds directory listings.
