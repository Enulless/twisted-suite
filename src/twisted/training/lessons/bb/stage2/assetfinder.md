---
step_id: bb.stage2.assetfinder
procedure: bb
stage: stage2
title: assetfinder (alternative aggregator)
estimated_minutes: 8
---

## What We Are Doing

Tools like Sublist3r and assetfinder query multiple public data sources simultaneously — certificate transparency logs, search engine indexes, DNS brute-force wordlists, and threat intelligence databases — and aggregate the results into a single subdomain list. Using multiple tools ensures coverage gaps in one tool's data sources are compensated by another.

## Why

Each tool weights different data sources differently. Sublist3r may have cached data from search engines that assetfinder does not query. assetfinder may have access to certificate data from providers Sublist3r misses. Subdomains confirmed by multiple tools are considered high-confidence entries. Single-source discoveries require verification before testing.

## Step By Step Execution With Sublist3r

Ensure Sublist3r is installed on your Ubuntu VM: pip3 install sublist3r --break-system-packages

Run Sublist3r against the primary domain: python3 sublist3r.py -d example.com -o stage2_sublist3r.txt

The -d flag specifies the target domain. The -o flag saves output to a text file.

Sublist3r queries: crt.sh, Censys, Google, Bing, Yahoo, Baidu, Netcraft, VirusTotal, and DNSdumpster simultaneously.

Wait for completion. Review the output file for discovered subdomains.

Add each new subdomain to the master spreadsheet with source noted as "Sublist3r".

pip3 install sublist3r --break-system-packages

python3 sublist3r.py -d example.com -o stage2_sublist3r.txt

## Step By Step Execution With Assetfinder

Install assetfinder: go install github.com/tomnomnom/assetfinder@latest

Run against the primary domain: assetfinder --subs-only example.com | tee stage2_assetfinder.txt

assetfinder queries: crt.sh, Certspotter, Hackertarget, Threatcrowd, Riddler, and Facebook's Certificate Transparency.

Compare output against Sublist3r results. Highlight subdomains that appear in only one source — these are less certain and need verification.

Add all new unique subdomains to the master spreadsheet with source noted as "assetfinder".

assetfinder --subs-only example.com | tee stage2_assetfinder.txt
