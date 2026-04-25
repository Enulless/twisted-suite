---
step_id: wifi.phase1.airodump_scan
procedure: wifi
stage: phase1
title: airodump-ng passive enumeration
estimated_minutes: 8
---

## What We Are Doing

Run airodump-ng to enumerate all visible wireless networks. Write output to file for later analysis.

airodump-ng wlan0mon -w recon_output --output-format csv,pcap

Let this run for 3-5 minutes minimum, or until all target networks are identified. Observe:

BSSID: Access point MAC address — used in all subsequent commands

ESSID: Network name (SSID)

CH: Channel the AP is operating on

ENC: Encryption type (WPA2, WPA3, WEP, OPN)

AUTH: Authentication method (PSK, MGT/RADIUS)

PWR: Signal strength — higher (less negative) is stronger

Clients: Devices currently associated with each AP

Why: This data set is the foundation for every subsequent decision. Encryption type determines which Phase 2 attack vector is viable. Channel is required for targeted capture. BSSID identifies the exact AP.
