---
step_id: wifi.phase3.host_discovery
procedure: wifi
stage: phase3
title: Host discovery (nmap ping sweep)
estimated_minutes: 8
---

## What We Are Doing

nmap -sn [SUBNET_CIDR] -oA phase3_hosts

The -sn flag performs a ping sweep without port scanning. Documents all live hosts for the evidence record.
