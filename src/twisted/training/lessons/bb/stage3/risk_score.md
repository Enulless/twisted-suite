---
step_id: bb.stage3.risk_score
procedure: bb
stage: stage3
title: "Risk Scoring & Tier Classification"
estimated_minutes: 8
---

## What We Are Doing

Apply the following scoring criteria to each target in the master spreadsheet. Sum the scores to produce a total risk score for each subdomain.

Software Age Factor: Software less than 1 year old = 0 points. 1 to 2 years old = 1 point. 2 to 3 years old = 2 points. Over 3 years old or end-of-life = 3 points.

Known CVEs Factor: No CVEs = 0 points. 1-2 CVEs, no public exploits = 1 point. 3-5 CVEs with some public exploits = 3 points. 5+ CVEs or critical CVEs with active exploits = 5 points.

Missing Security Headers: Missing X-Frame-Options = 1 point. Missing Content-Security-Policy = 2 points. Missing HSTS = 1 point. Missing X-Content-Type-Options = 1 point.

Certificate Issues: Valid, strong cert = 0 points. Expiring within 3 months = 1 point. Self-signed = 2 points. 1024-bit RSA or weaker = 3 points. Expired = 4 points.

Email Security: All three records present and strict = 0 points. Partial configuration = 1-2 points. All missing = 3 points.

Infrastructure Exposure: Standard web ports only = 0 points. Database port exposed (3306, 5432, 27017) = 3 points. RDP or SSH exposed unexpectedly = 3 points. Admin interface exposed = 2 points.

Environment Type: Production = 0 points. Staging/Development = 3 points. Unknown/abandoned = 2 points.

Technology Stack Complexity: Single technology = 0 points. 2-3 technologies = 1 point. 4-6 technologies = 2 points. 7+ technologies = 3 points.
