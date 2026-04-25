---
step_id: bb.stage2.fofa_walkthrough
procedure: bb
stage: stage2
title: Fofa technology indexing (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Fofa is an internet asset search engine with different geographic scanning coverage than Censys. It excels at technology fingerprinting — identifying not just that a service is running, but what specific software and version is deployed. Running both Censys and Fofa compensates for coverage gaps either platform may have.

## Why

When Fofa identifies a database port open on a public-facing subdomain, this is a significant finding regardless of whether authentication is required. Databases should never be directly internet-accessible. Even with strong passwords, databases expose a direct data access surface that bypasses all web application security controls.

## How

Navigate to fofa.info and create a free account.

Search for the primary domain: domain="example.com"

Review all results for open ports, service names, and technology identifications.

Refine searches to find specific service types: domain="example.com" && port="3306" finds MySQL databases.

Search for administrative interfaces: domain="example.com" && title="admin" finds pages with "admin" in the HTML title.

Search for specific technologies: domain="example.com" && app="WordPress" finds WordPress installations.

Document all discoveries: subdomain, IP, port, service, version, and any notable observations. Add to master spreadsheet with source "Fofa".

domain="example.com"

domain="example.com" && port="3306"

domain="example.com" && title="admin"
