---
step_id: bb.stage4.manual_xss
procedure: bb
stage: stage4
title: Manual XSS verification (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Automated scanners produce findings that range from confirmed critical vulnerabilities to false positives. Manual verification tests every automated finding to confirm it is real and exploitable. Manual testing also covers vulnerability classes that automation cannot detect — business logic flaws, workflow bypasses, privilege escalation chains, and application-specific issues.

## Part D1 Vulnerability Triage And Classification

Before testing anything manually, categorise all automated findings:

Confirmed Vulnerability: Automated tool found it, initial review suggests it is real. Manual verification will confirm exploitation.

Needs Verification: Automated tool flagged it but confidence is not high. Manual investigation required before classifying.

False Positive: Automated tool flagged it, but context suggests it is mitigated or not applicable. Manual testing confirms dismissal.

Requires Context: Finding is technically real but impact depends on business logic. Deeper analysis needed.

Create a triage table with these four columns. Every automated finding goes into this table before any manual testing begins.

## Part D2 Manual Sql Injection Verification

Navigate to the suspected injection point in a web browser.

Enter a single quote character in the input field: '

Submit the form. If a database error message is returned (e.g., "You have an error in your SQL syntax"), error-based injection is confirmed.

Test boolean-based injection: enter ' OR '1'='1 in the field.

If all records are returned instead of filtered results, injection is confirmed.

Test in the URL: https://subdomain.example.com/search?q=test' OR '1'='1

Test UNION-based extraction: ' UNION SELECT NULL, username, password FROM users --

Document the exact payload, the URL or form field, and the response that confirms the vulnerability.

Screenshot the vulnerable input with the payload entered and the response showing the injection effect.

' OR '1'='1

' UNION SELECT NULL, username, password FROM users --

## Part D3 Manual Authentication Testing

Admin Panel Access Without Login:

Navigate directly to discovered admin URLs: /admin, /administrator, /admin.php, /wp-admin, /dashboard, /console

If the page loads without requesting credentials, authentication bypass is confirmed. Document the URL and take a screenshot showing the accessible content.

Default Credentials:

For identified services and CMS platforms, test default credentials.

WordPress: admin/admin, admin/password, admin/[domain name]

Tomcat: tomcat/tomcat, admin/admin, manager/manager

Jenkins: admin/admin (or no authentication)

Grafana: admin/admin

Document each credential pair tested and the result.

Session Management:

After logging in, copy the session token from cookies.

Log out. Attempt to use the copied session token to access authenticated pages.

If the old session token still works after logout, session tokens are not properly invalidated. Document as a finding.

## Part D4 Cross Site Scripting Xss Manual Verification

For each input field that reflects user input in the response, test: <script>alert(1)</script>

If an alert box appears, reflected XSS is confirmed.

For input that is sanitising angle brackets, try: <img src=x onerror=alert(1)>

For DOM-based XSS, check if input appears in JavaScript contexts in the page source.

Document: the input field or URL parameter, the payload that triggered XSS, a screenshot showing the alert box, and the URL of the vulnerable page.

<script>alert(1)</script>

<img src=x onerror=alert(1)>

## Part D5 Business Logic And Workflow Testing

Business logic vulnerabilities are specific to the application and cannot be found by generic scanners. The following tests apply broadly across web applications:

Price and Quantity Manipulation:

Add an item to a shopping cart. Intercept the request using OWASP ZAP or browser developer tools.

Modify the price parameter to 0 or a negative value. Complete the purchase.

If the item is purchased at the modified price, price manipulation is possible. Critical finding.

Modify the quantity to a negative number. Check if the application creates a refund.

Step Skipping:

For multi-step workflows (checkout, approval, registration), attempt to access later steps directly by URL without completing earlier steps.

Example: navigate directly to /checkout/confirm without going through /checkout/payment

If the confirmation page loads without requiring payment details, step skipping is possible.

Insecure Direct Object Reference (IDOR):

Find any URL or parameter containing a user-specific identifier: /profile?id=1, /document?file_id=100, /order?order_id=5678

Change the identifier to different values: id=2, file_id=101, order_id=5679

If other users' data loads, IDOR vulnerability is confirmed. Document the URL, original ID, modified ID, and the unauthorised data returned.

Race Conditions:

For any action that should only happen once (coupon redemption, limited item purchase, concurrent fund transfer), attempt to send the same request multiple times simultaneously.

Use Burp Suite Intruder or a custom script to send parallel requests.

If the action is performed multiple times, a race condition exists.

## Part D6 Evidence Collection And Pii Redaction

Every confirmed vulnerability must have associated evidence. Evidence standards:

Screenshots: capture the vulnerable state, the payload entered, and the exploited result. Use Flameshot (sudo apt install flameshot) for annotated screenshots with boxes and arrows highlighting the relevant areas.

HTTP Request and Response: capture the exact HTTP request sent and the response received. Copy from browser developer tools Network tab or OWASP ZAP's request/response pane.

Command-line output: copy terminal output showing the tool execution and results to a text file.

Video: for complex multi-step exploits, record a short screen recording using OBS Studio (free). Keep recordings under 5 minutes.

PII Redaction Process:

Before including any evidence in the report, review for personally identifiable information.

Real usernames, email addresses, names, and addresses must be replaced with placeholders: user1@example.com, User One.

Real password hashes must be replaced with: [REDACTED].

Real API keys, tokens, and credentials must be completely removed.

Use GIMP (free) to blur or black-out PII in screenshots before saving the final evidence version.

Keep the original evidence file in the raw evidence folder. Put the redacted version in the report evidence folder.

## Part D7 False Positive Analysis And Dismissal

For each finding classified as "Needs Verification" or suspected false positive, perform the following analysis:

Identify what compensating control might be present. Does the application use a WAF? Is the page behind a VPN despite being indexed? Does the application use CAPTCHA to prevent automated testing?

Test whether the vulnerability is actually exploitable given the compensating controls. Run manual payloads rather than relying on scanner output.

If manual testing confirms the vulnerability cannot be exploited, classify as False Positive.

Document the dismissal reasoning: what the scanner found, what manual testing showed, and why the finding is not exploitable.

Example dismissal: Scanner flagged missing X-Frame-Options header. Manual investigation shows the application is a read-only public information page with no forms, no authentication, and no sensitive functionality. An attacker framing this page in an iframe gains nothing. Classified as Low risk, not reported as a vulnerability. Header addition recommended as best practice improvement.
