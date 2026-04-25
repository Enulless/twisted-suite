---
step_id: bb.stage4.business_logic
procedure: bb
stage: stage4
title: "Business logic & workflow testing (walkthrough)"
estimated_minutes: 8
---

## What We Are Doing

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
