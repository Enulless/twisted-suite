---
step_id: wifi.phase4.credential_reuse
procedure: wifi
stage: phase4
title: Credential reuse testing (CrackMapExec)
estimated_minutes: 8
---

## What We Are Doing

Test the recovered Wi-Fi passphrase and any other credentials found during Phase 3 against all discovered hosts:

crackmapexec smb [SUBNET_CIDR] -u administrator -p '[PASSWORD]'

crackmapexec ssh [SUBNET_CIDR] -u admin -p '[PASSWORD]'

Why: Credential reuse is endemic. The Wi-Fi password is frequently reused for router admin interfaces, shared drives, and local accounts.
