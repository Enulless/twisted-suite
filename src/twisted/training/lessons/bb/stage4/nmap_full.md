---
step_id: bb.stage4.nmap_full
procedure: bb
stage: stage4
title: Nmap full-range scan (high-priority targets)
estimated_minutes: 8
---

## What We Are Doing

For targets scoring Critical on the risk matrix, run a full port scan to find services on non-standard ports.

Command: nmap -sV -p- subdomain.example.com -oA stage4_target_full

The -p- flag scans all 65,535 TCP ports. This takes significantly longer but discovers services on unusual ports.

Document every open port with its service name, version, and any banner information returned.

nmap -sV -p- subdomain.example.com -oA stage4_target_full
