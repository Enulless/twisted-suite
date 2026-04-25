---
step_id: wp_stress.phase2.endpoint_stress
procedure: wp_stress
stage: phase2
title: Targeted endpoint stress (login / admin-ajax / xmlrpc)
estimated_minutes: 8
---

## Why

WordPress sites have multiple attack vectors under load: exhausted PHP-FPM workers, MySQL connection pool limits, memory ceiling breaches, and misconfigured caching that collapses under concurrency. Each failure mode produces observable signals (error messages, timeouts, HTTP status codes) that an attacker uses to fingerprint and exploit the system. We intentionally trigger those conditions in a controlled environment to find and fix them first.

## How

Step 1 — Warm-Up Load (Calibration)

Run a low-volume baseline confirmation test:

a. Command: ab -n 500 -c 10 https://yoursite.com/

b. Expected result: matches baseline. If not, investigate before proceeding.

Step 2 — Escalating Concurrency Test

Gradually increase concurrency to find the saturation point:

a. Round 1: wrk -t4 -c50 -d30s https://yoursite.com/  (50 concurrent users, 30 sec)

b. Round 2: wrk -t4 -c100 -d30s https://yoursite.com/  (100 concurrent)

c. Round 3: wrk -t4 -c250 -d30s https://yoursite.com/  (250 concurrent)

d. Round 4: wrk -t8 -c500 -d30s https://yoursite.com/  (500 concurrent)

e. After each round, record: req/sec, error %, latency p99, server CPU/RAM from htop.

f. Stop escalating when: error rate exceeds 50%, server CPU is pinned at 100% for 10+ seconds, or site becomes unresponsive.

Step 3 — Targeted Endpoint Stress

Stress high-cost WordPress endpoints individually:

a. Login page: ab -n 1000 -c 50 https://yoursite.com/wp-login.php

b. Admin AJAX: ab -n 1000 -c 50 https://yoursite.com/wp-admin/admin-ajax.php

c. Search: ab -n 500 -c 25 'https://yoursite.com/?s=test'

d. XML-RPC: ab -n 500 -c 25 https://yoursite.com/xmlrpc.php

e. For each: capture full HTTP response headers and body at failure point using curl -v.

Step 4 — Scenario-Based Load with Locust

Simulate realistic multi-step user sessions:

a. Create locustfile.py that simulates: visit homepage, visit a post, submit a comment, run a search.

b. Run: locust -f locustfile.py --headless -u 200 -r 10 --host=https://yoursite.com --run-time 2m

c. Capture the Locust HTML report at completion.

The saturation point tells you your current capacity ceiling. Error messages tell you what an attacker sees. Slow queries tell you what to optimize. Each failure type maps directly to a remediation action in Phase 4.

## What to Collect

wrk/ab output for each round (saved to stress_round_N.txt)

Error responses (full HTTP response headers + body) for any non-200 status codes

Error log excerpts showing PHP fatal errors, OOM kills, DB connection failures

Slow query log entries triggered during testing

Server resource graphs (screenshots from htop at peak load)

Exact concurrency level at which errors first appeared (saturation point)
