---
step_id: bb.stage4.postman_walkthrough
procedure: bb
stage: stage4
title: Postman API endpoint testing (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Download Postman from postman.com (free tier). Launch Postman.

For each API endpoint discovered during reconnaissance, create a new request in Postman.

Test without authentication first: send a GET request to /api/users without any authentication header. If data is returned, the endpoint is unauthenticated — critical finding.

Test parameter manipulation: if the authenticated endpoint is /api/users/profile?id=1, change the id to 2. If a different user's profile loads, Insecure Direct Object Reference (IDOR) vulnerability exists.

Test for mass assignment: send a POST or PUT request with additional parameters the API should not accept, such as role=admin or is_admin=true. If the server accepts these parameters, mass assignment vulnerability exists.

Test API rate limiting: send the same request rapidly 100+ times. If no rate limiting is enforced, the API is vulnerable to brute-force attacks.

Test for verbose error messages: send malformed requests to trigger error responses. If stack traces, file paths, or database error messages are returned, information disclosure exists.
