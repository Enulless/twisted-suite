---
step_id: bb.stage3.wappalyzer_walkthrough
procedure: bb
stage: stage3
title: Wappalyzer Technology Fingerprint (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Wappalyzer analyses HTML source code, JavaScript files, HTTP response headers, and cookie names to identify specific technologies running on a web application. It detects not just the web server but the full stack — CMS, plugins, JavaScript libraries, analytics tools, payment processors, and more — all with version numbers where available.

## How

Install the Wappalyzer browser extension from wappalyzer.com for Firefox or Chrome.

For each prioritised subdomain, open the URL in the browser with Wappalyzer enabled.

Click the Wappalyzer icon in the browser toolbar to see the detected technology list.

Record every detected technology, its version, and its category (CMS, JavaScript library, web server, analytics, etc.).

For command-line batch processing of multiple subdomains, install the CLI tool: npm install -g wappalyzer

Run against each target: wappalyzer https://subdomain.example.com --pretty

Add all detected technologies to the master spreadsheet with source "Wappalyzer".

npm install -g wappalyzer

wappalyzer https://subdomain.example.com --pretty

## Example Findings

Wappalyzer detects on api.example.com: WordPress 5.8.1, Elementor 3.4.0, Yoast SEO 18.1.0, WooCommerce 5.9.0, jQuery 3.5.1, Stripe payment integration. Cross-referencing against CVE databases reveals: Elementor 3.4.0 has an authenticated arbitrary file upload vulnerability (CVE-2021-38312). Yoast SEO 18.1.0 has a reflected XSS in admin panel. jQuery 3.5.1 has XSS via HTML parsing (CVE-2020-11022). WooCommerce 5.9.0 has SQL injection in product filtering. This single Wappalyzer scan has identified four exploitable vulnerabilities before any active testing has begun.
