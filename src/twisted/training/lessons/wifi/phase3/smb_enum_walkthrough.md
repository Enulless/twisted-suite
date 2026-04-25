---
step_id: wifi.phase3.smb_enum_walkthrough
procedure: wifi
stage: phase3
title: SMB share enumeration (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

enum4linux-ng -A [TARGET_HOST_IP]

smbclient -L [TARGET_HOST_IP] -N

Document any readable or writable shares, user accounts, or policy information returned without credentials.
