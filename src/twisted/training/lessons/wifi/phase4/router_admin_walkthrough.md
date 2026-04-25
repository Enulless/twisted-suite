---
step_id: wifi.phase4.router_admin_walkthrough
procedure: wifi
stage: phase4
title: Router/gateway admin access (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Attempt to access the router's admin interface using default credentials or the recovered Wi-Fi passphrase:

curl -s http://[GATEWAY_IP]/

Navigate to the admin panel and attempt login with: admin/admin, admin/password, admin/[WIFI_PASSWORD]. Access to the router is a critical finding as it provides complete network control.
