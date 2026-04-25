---
step_id: bb.stage4.sqlmap_walkthrough
procedure: bb
stage: stage4
title: sqlmap SQL injection probing (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

For web forms and API parameters that interact with databases, test for SQL injection using sqlmap.

Basic test against a URL parameter: sqlmap -u "https://subdomain.example.com/search?q=test" --dbs

The --dbs flag attempts to enumerate database names if injection is confirmed.

For POST requests: sqlmap -u "https://subdomain.example.com/login" --data="username=test&password=test" --dbs

sqlmap will test multiple injection techniques automatically: boolean-based blind, time-based blind, error-based, UNION-based, and stacked queries.

If injection is confirmed, sqlmap extracts the database list. Do not extract full tables or user data beyond what is necessary to prove the vulnerability.

Document: the vulnerable parameter, the injection technique that worked, database names discovered, and the sqlmap command used as proof-of-concept.

sqlmap -u "https://subdomain.example.com/search?q=test" --dbs

sqlmap -u "https://subdomain.example.com/login" --data="username=test&password=test" --dbs
