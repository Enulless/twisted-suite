---
step_id: bb.stage1.dns_enum
procedure: bb
stage: stage1
title: DNS Record Enumeration
estimated_minutes: 8
---

## What We Are Doing

DNS records map domain names to infrastructure components. Each record type reveals something different about the client's environment. We query the DNS system to extract all available record types for the primary domain and any known subdomains.

## How

Open a terminal on your Ubuntu VM.

Query all DNS records for the primary domain: dig @8.8.8.8 example.com ANY

The @8.8.8.8 directs the query to Google's public DNS resolver, avoiding cached results. ANY requests all available record types.

Document each record type returned: A records with IP addresses, MX records with mail server hostnames, NS records with nameserver hostnames, TXT records with full text content, CNAME records with target destinations.

For each discovered subdomain from Procedure A, repeat the dig query: dig @8.8.8.8 subdomain.example.com A

Record which subdomains resolve (return an IP address) and which do not. Non-resolving subdomains may still be accessible via direct IP or may indicate dangling DNS entries.

Attempt a DNS zone transfer on each nameserver discovered: dig @ns1.example.com example.com axfr

If the zone transfer succeeds, the nameserver is misconfigured and leaks all DNS records. This is a critical finding. Document the full zone transfer output.

dig @8.8.8.8 example.com ANY

dig @8.8.8.8 example.com MX

dig @ns1.example.com example.com axfr

## Dns Record Types And Their Significance

A Record: Maps a domain name to an IPv4 address. Tells you exactly where a service is hosted. Unexpected IP addresses may indicate shadow IT or forgotten servers.

AAAA Record: Same as A record but for IPv6. Organizations that have adopted IPv6 may have infrastructure that is only discoverable via IPv6 scanning.

MX Record: Mail Exchange record. Points to the mail server responsible for receiving email for the domain. Mail servers are often separate infrastructure with different security postures than web servers. Exposed mail servers are common entry points.

NS Record: Nameserver record. Identifies which DNS servers are authoritative for the domain. If nameservers are misconfigured or use outdated software, DNS hijacking or zone transfer attacks may be possible.

TXT Record: Holds arbitrary text data. Commonly used for SPF, DKIM, and DMARC email security policies. May also contain information about third-party services the client uses, such as Google Workspace or Salesforce verification tokens.

CNAME Record: Canonical Name. Points one domain to another. May reveal internal naming conventions, third-party hosting platforms, or legacy infrastructure.
