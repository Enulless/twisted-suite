---
step_id: bb.stage4.nmap_top
procedure: bb
stage: stage4
title: Nmap targeted port scan (common vuln ports)
estimated_minutes: 8
---

## What We Are Doing

For each critical-risk target from Stage Three, run a targeted scan of commonly vulnerable ports.

Command: nmap -sV -p 21,22,23,25,53,80,443,3306,5432,27017,3389,8080,8443,8888,9000,9200 subdomain.example.com -oA stage4_target_common

The -sV flag enables service version detection. Nmap connects to each open port and analyses the response to determine the software and version.

-oA saves output in all three formats simultaneously: .nmap (text), .xml, and .gnmap (greppable).

Review the output for any unexpected open ports.

nmap -sV -p 21,22,23,25,53,80,443,3306,5432,27017,3389,8080,8443,8888,9000,9200 subdomain.example.com -oA stage4_target_common
